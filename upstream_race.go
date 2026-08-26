/*
File:    upstream_race.go
Version: 2.52.0
Last Updated: 07-Aug-2026 21:30 CEST

Description:
  Advanced routing and parallel execution strategies for sdproxy upstream groups.
  Abstracts away `stagger`, `round-robin`, `random`, `fastest`, and `secure` strategies.

Changes:
  2.52.0 - [FIX] bootstrapResolve stopped after the first upstream that answered
           AT ALL, rather than after the first that produced a usable address.
           The loop harvested whatever A/AAAA records the response carried and
           then broke unconditionally, so a bootstrap server returning an empty
           NOERROR, an NXDOMAIN, or a CNAME-only answer consumed the entire
           attempt for that qtype and the configured fallbacks were never tried.
           Bootstrap resolution is what turns a DoH/DoT hostname into an address
           before any encrypted transport exists, so this failure mode takes the
           whole upstream group offline at boot — and it does so on a HEALTHY
           response, which is why no failover logic ever engaged. The break now
           requires at least one address to have been harvested.
         - [SECURITY/PERF] exchangeSecure selected its fan-out subset with
           `servers[:maxSecure]` — the first N in configured order, health
           disregarded. With a ten-server group capped at five, servers 6-10 were
           unreachable for consensus no matter what happened to the first five,
           so an attacker who could degrade those five (blackhole, slow-loris,
           or simply outrace them) drove the group below the strict quorum floor
           2.51.0 installed, while five healthy peers sat unused. The subset is
           now filled healthy-first, preserving configured order WITHIN each
           health class so the participant set stays deterministic for a given
           health state. Deliberately not sorted by RTT: consensus wants
           independent views, and ranking by latency would systematically
           re-select the same fastest peers and correlate the sample.
         - [PERF/FIX] exchangeFastest ranked never-probed upstreams FIRST.
           emaRTT is zero-valued until an exchange completes, and the comparator
           sorted ascending, so any upstream that had never been dialled sorted
           ahead of every measured one — permanently, if it kept failing before
           updateRTT ran. At boot that made "fastest" a synonym for "configured
           order", and after any group edit the new server was preferred
           indefinitely regardless of merit. Unprobed upstreams now rank at a
           neutral baseline (fastestUnprobedRTT) instead of at zero, and health
           is the primary sort key so a failing peer cannot hold the front of
           the queue at all.
         - [FIX] exchangeFastest reported "epsilon-greedy random" in the strategy
           log even when the random draw selected index 0, which changes nothing.
           Exploration now draws from indices 1..n-1 so a draw always explores,
           and the label always describes what actually happened.
  2.51.0 - [SECURITY/FIX] Restored a quorum floor to `mode: strict` (audit item
           S-A). 2.50.0 correctly stopped treating an abstaining peer as a
           disagreement, but in doing so it left `len(evalResults) == 0` as the
           ONLY remaining gate — so a strict-mode group whose peers had all
           failed except one would serve that one peer's answer, uncorroborated,
           while still reporting itself as strict. With a five-server pool an
           attacker who can degrade four peers (blackhole, slow-loris, or simply
           outrace them to the deadline) silently downgrades cross-validation to
           a plain forward.
           exchangeSecure now requires minStrictConsensus (2) upstreams to have
           produced MATCHING payloads whenever the fan-out held more than one
           server, and fails closed below that. Loose mode, poison detection and
           the 2.50.0 abstention semantics are all untouched: a disagreeing peer
           still short-circuits to a block inside evaluateResult() before this
           guard is ever reached, so the new check only ever fires on
           "insufficient evidence", never on "conflicting evidence".
           No new configuration knob — see the comment on minStrictConsensus for
           why `mode: loose` is the correct escape hatch rather than a tunable
           floor.
  2.50.0 - [SECURITY/FIX] Completed the strict-consensus repair that 2.49.0 only
           narrowed. 2.49.0 forgave context.Canceled and context.DeadlineExceeded,
           but every OTHER transport failure still counted as a validation
           failure and synthesised a block for the entire query. That left a
           long list of entirely ordinary conditions able to suppress a valid,
           unanimous answer from the healthy peers:
             ECONNREFUSED            (upstream daemon restarting)
             io.EOF / unexpected EOF (connection torn down mid-TLS)
             EHOSTUNREACH / ENETUNREACH (transient routing)
             TLS handshake failures, DoH non-200 responses, QUIC resets
           The predicate is now the correct one: did this peer produce a DNS
           payload at all? A peer that returned no message contributed no
           evidence about poisoning and is skipped, whatever the error kind.
           Poison detection is untouched — a malicious upstream must reply with
           r.msg != nil to say anything, and mismatched RCODE or answer
           fingerprints still fail closed. Total failure also still fails
           closed via the unchanged `len(evalResults) == 0` guard, so "nobody
           answered" remains a block rather than a passthrough. This finally
           closes the KNOWN-OPEN item for real.
         - [PERF] Repaired the `equalRRs` default branch, which 2.48.0 made
           twice as expensive while claiming to eliminate allocations. The A /
           AAAA / CNAME fast paths were genuinely improved; the fallback went
           from one `a.String() == b.String()` pair (2 allocations) to two
           `dns.Copy` deep clones PLUS two String() calls (4 allocations, plus
           full RR duplication). Since equalRRs runs O(n^2) over the answer set
           under `preference: consolidate`, that doubled GC pressure on exactly
           the RR types that reach the fallback — MX, SRV, TXT, HTTPS, SVCB.
           Restored a 2-allocation fast path for the common case (records
           identical including TTL) and confined the TTL-insensitive comparison
           to a slow path that only executes when the strings actually differ.
           Semantics are preserved: two upstreams returning identical rdata with
           different remaining TTLs still deduplicate correctly.
  2.49.0 - [SECURITY/FIX] Resolved the long-standing KNOWN-OPEN strict-consensus
           regression recorded in version.go. `exchangeSecure` in strict mode
           classified a plain upstream timeout (context.DeadlineExceeded) as a
           consensus *validation failure* and synthesized a block — so one dead or
           slow peer could suppress otherwise-valid, matching answers from the
           healthy peers, and strict-mode latency tracked the slowest peer all the
           way to the 2500ms safety-net ceiling. DeadlineExceeded is now forgiven
           and skipped exactly like the already-handled context.Canceled case (a
           transport non-answer is not poisoning). Poison detection is unchanged:
           mismatched RCODE/answer payloads still fail closed, and the existing
           `len(evalResults) == 0` guard still blocks when NO peer produced a valid
           answer. Header date field advanced.
  2.48.0 - [PERF] Eradicated redundant heap allocations from the consensus
           deduplication path. `equalRRs` compared owner names and CNAME targets
           via `strings.ToLower(x) == strings.ToLower(y)`, allocating two throwaway
           lowercase strings per comparison. Since equalRRs runs O(n²) over the
           answer set under the "consolidate" preference, this thrashed the GC on
           large merged RRsets. Both comparisons now use allocation-free
           `strings.EqualFold`, which short-circuits on the first differing byte.
           Semantically identical for DNS names (ASCII case rules, RFC 4343).
           Header date field normalized from `Updated:` to `Last Updated:`.
  2.47.0 - [FEAT] `exchangeSecure` now caps the number of upstreams queried 
           simultaneously using `g.MaxSecureUpstreams` (configurable via 
           `server.max_secure_upstreams`, default 5) instead of unconditionally 
           querying every server in the group.
  2.46.0 - [FIX] Removed duplicate `bootstrapResolveECH` function declaration 
           after its migration to the dedicated `upstream_ddr.go` discovery engine 
           natively, resolving compilation conflicts.
  2.45.0 - [SECURITY/FIX] Eradicated a critical Consensus Pipeline stall vulnerability 
           natively. The `exchangeSecure` safety-net bounds check previously overwrote 
           the 2500ms execution ceiling with unbounded parent deadlines (up to 30s), 
           causing catastrophic goroutine pile-ups during upstream server outages. 
           The evaluation now strictly enforces the minimum limit organically.
  2.44.0 - [CODE SMELL/FIX] Transitioned `synthesizeConsensusBlock` to emit the 
           strongly-typed `ErrSilentDrop` sentinel natively. Prevents string 
           evaluation drifts during SingleFlight consensus shedding operations.
  2.43.0 - [SECURITY/FIX] Added strict `nil` checks inside `bootstrapResolve` and 
           `bootstrapResolveECH` loops. Definitively guards against resolving DDR 
           records against uninitialized nodes during the concurrent Boot Engine phases.
  2.42.0 - [FIX] Resolved compiler errors in exchangeFastest logging statements by restoring proper 
           rttMs variable usage and eliminating the undefined status reference.
  2.41.0 - [FEAT] Introduced 'consolidate' preference option to the secure strategy, merging and 
           deduplicating A, AAAA, and CNAME records across all matching validated answers dynamically.
  2.40.0 - [SECURITY/FIX] Resolved a compilation error where `penalizeRTT` was mistakenly
           called as a method of `*Upstream` inside the `exchangeSecure` drain-loop. Corrected
           to invoke `g.penalizeRTT(extra.up)`.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Upstream Group Dispatcher
// ---------------------------------------------------------------------------

// Exchange processes the DNS request using the configured routing strategy of the Upstream Group.
func (g *UpstreamGroup) Exchange(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	if len(g.Servers) == 0 {
		return nil, "", errors.New("no upstreams configured")
	}

	if len(g.Servers) == 1 {
		up := g.Servers[0]
		start := time.Now()
		resp, addr, err := up.Exchange(ctx, req, clientID, clientName, clientAddr)
		rtt := time.Since(start).Nanoseconds()
		
		if err == nil && resp != nil {
			up.recordSuccess()
			g.updateRTT(up, rtt)
			return resp, addr, nil
		}
		
		// Avoid recording structural timeouts or manual query cancellations as connection drops
		if err != nil && !errors.Is(err, context.Canceled) {
			up.recordFailure()
			g.penalizeRTT(up)
		}
		
		if err != nil {
			return nil, addr, fmt.Errorf("upstream exchange failed: %w", err)
		}
		return nil, addr, errors.New("upstream exchange failed")
	}

	switch g.Strategy {
	case "round-robin":
		return g.exchangeRoundRobin(ctx, req, clientID, clientName, clientAddr)
	case "random":
		return g.exchangeRandom(ctx, req, clientID, clientName, clientAddr)
	case "fastest":
		return g.exchangeFastest(ctx, req, clientID, clientName, clientAddr)
	case "secure":
		return g.exchangeSecure(ctx, req, clientID, clientName, clientAddr)
	case "stagger":
		fallthrough
	default:
		return g.exchangeStagger(ctx, req, clientID, clientName, clientAddr)
	}
}

// ---------------------------------------------------------------------------
// Unified Staggered Racing Engine
// ---------------------------------------------------------------------------

// executeRace provides a unified, high-performance parallel racing engine.
// It eliminates duplicate loop logic across strategies and ensures that if
// 'upstreamStagger' is configured, ALL algorithms benefit from rapid failover
// and zero-pause parallel fallback mechanics natively.
func (g *UpstreamGroup) executeRace(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr, ordered []*Upstream) (*dns.Msg, string, error) {
	// [SECURITY/FIX] Embed an isolated cancellation envelope natively.
	// Binds all executing network dials to this specific racing cluster. The moment the 
	// primary successful routine completes, the envelope collapses, instantly tearing down 
	// any lingering, parallel network connections to prevent resource starvation.
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Sequential execution fallback (Strict sequential, no parallel overlaps)
	if upstreamStagger <= 0 {
		var lastErr error
		var lastAddr string
		for _, up := range ordered {
			start := time.Now()
			resp, addr, err := up.Exchange(raceCtx, req, clientID, clientName, clientAddr)
			rtt := time.Since(start).Nanoseconds()
			if err == nil && resp != nil {
				up.recordSuccess()
				g.updateRTT(up, rtt)
				return resp, addr, nil
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				up.recordFailure()
				g.penalizeRTT(up)
			}
			lastErr = err
			lastAddr = addr
		}
		if lastErr != nil {
			return nil, lastAddr, fmt.Errorf("exchange failed: %w", lastErr)
		}
		return nil, lastAddr, errors.New("exchange failed")
	}

	// ── Parallel Staggered Racing ──
	n := len(ordered)
	type raceResult struct {
		msg  *dns.Msg
		addr string
		up   *Upstream
		err  error
		rtt  int64
	}

	ch := make(chan raceResult, n)
	launched := 0

	for i, up := range ordered {
		if i > 0 {
			// [PERF/FIX] Only stagger the launch if the preceding server in the 
			// sequence is healthy. If the previous server is already known to be 
			// offline/penalized, bypass the stagger delay to fire immediately, 
			// eliminating artificial lag during failovers.
			if ordered[i-1].isHealthy() {
				t := time.NewTimer(upstreamStagger)
				select {
				case r := <-ch:
					t.Stop()
					launched--
					if r.err == nil && r.msg != nil {
						r.up.recordSuccess()
						g.updateRTT(r.up, r.rtt)
						return r.msg, r.addr, nil
					}
					if r.err != nil && !errors.Is(r.err, context.Canceled) {
						r.up.recordFailure()
						g.penalizeRTT(r.up)
					}
				case <-t.C:
				}
			}
		}
		launched++
		go func(u *Upstream) {
			start := time.Now()
			msg, addr, err := u.Exchange(raceCtx, req, clientID, clientName, clientAddr)
			ch <- raceResult{msg, addr, u, err, time.Since(start).Nanoseconds()}
		}(up)
	}

	var lastErr error
	var lastAddr string
	
	// Await the remaining launched routines. The first valid success intercepts 
	// the loop natively and returns to the client.
	for i := 0; i < launched; i++ {
		r := <-ch
		if r.err == nil && r.msg != nil {
			r.up.recordSuccess()
			g.updateRTT(r.up, r.rtt)
			return r.msg, r.addr, nil
		}
		if r.err != nil && !errors.Is(r.err, context.Canceled) {
			r.up.recordFailure()
			g.penalizeRTT(r.up)
		}
		lastErr = r.err
		lastAddr = r.addr
	}
	
	if lastErr != nil {
		return nil, lastAddr, fmt.Errorf("staggered exchange failed: %w", lastErr)
	}
	return nil, lastAddr, errors.New("staggered exchange failed")
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

// exchangeStagger implements the default parallel racing mechanic using the unified engine.
func (g *UpstreamGroup) exchangeStagger(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, g.Servers)
}

// exchangeRoundRobin loops through the upstream group array sequentially.
// Automatically benefits from parallel-staggered fallback via the unified engine.
func (g *UpstreamGroup) exchangeRoundRobin(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	idx := int(g.rrCount.Add(1) % uint64(len(g.Servers)))
	ordered := make([]*Upstream, len(g.Servers))
	for i := 0; i < len(g.Servers); i++ {
		ordered[i] = g.Servers[(idx+i)%len(g.Servers)]
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

// exchangeRandom blindly selects a random upstream index.
// Automatically benefits from parallel-staggered fallback via the unified engine.
func (g *UpstreamGroup) exchangeRandom(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	idx := rand.IntN(len(g.Servers))
	ordered := make([]*Upstream, len(g.Servers))
	for i := 0; i < len(g.Servers); i++ {
		ordered[i] = g.Servers[(idx+i)%len(g.Servers)]
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

// fastestUnprobedRTT is the ranking value assigned to an upstream that has never
// completed an exchange.
//
// [PERF/FIX 2.52.0] emaRTT is an atomic.Int64 and therefore zero until
// updateRTT runs for the first time. exchangeFastest sorted ascending on the
// raw value, so zero — "no measurement" — outranked every real measurement,
// including a 1ms one. Three consequences, all of them making "fastest" mean
// something other than fastest:
//
//   - At boot, every upstream reads zero, the sort is a no-op, and the strategy
//     silently degrades to configured order until measurements accumulate.
//   - An upstream added to a running group is preferred over the entire
//     established pool on its first query, regardless of merit.
//   - An upstream that fails BEFORE updateRTT can run keeps its zero and
//     therefore keeps first place. penalizeRTT does substitute 500ms in that
//     case, so this is bounded in practice — but it depends on the failure
//     being observed and recorded, which a context cancellation explicitly is
//     not.
//
// 50ms places an unprobed peer mid-field: ahead of anything genuinely slow, so
// it still gets tried early enough to earn a real measurement, and behind
// anything genuinely fast, so it cannot displace a proven performer on the
// strength of having no record at all.
const fastestUnprobedRTT = int64(50 * time.Millisecond)

// exchangeFastest uses an Epsilon-Greedy approach integrated with staggered racing.
// Dynamically ranks all active connections natively by Exponential Moving Average.
func (g *UpstreamGroup) exchangeFastest(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	n := len(g.Servers)
	type ranked struct {
		up      *Upstream
		rtt     int64 // effective ranking latency (unprobed peers get a baseline)
		rawRTT  int64 // measured EMA, 0 when never probed — logged as-is
		unfit   int   // health tier: 0 healthy, 1 failing. Primary sort key.
		idx     int
	}
	
	ranks := make([]ranked, n)
	for i, up := range g.Servers {
		raw := up.emaRTT.Load()

		// [FIX 2.52.0] Neutral baseline instead of zero for unprobed peers.
		eff := raw
		if eff <= 0 {
			eff = fastestUnprobedRTT
		}

		// [FIX 2.52.0] Health is the PRIMARY key. A peer past healthThreshold
		// consecutive failures should not lead the queue on the strength of a
		// stale-but-low EMA; penalizeRTT doubles the EMA on each observed
		// failure, but failures that never reach it (cancellations, races lost
		// to a faster peer) leave the old value intact.
		unfit := 0
		if !up.isHealthy() {
			unfit = 1
		}

		ranks[i] = ranked{up: up, rtt: eff, rawRTT: raw, unfit: unfit, idx: i}
	}

	// Sort by health tier, then EMA latency natively, avoiding interface
	// allocations (GC thrashing).
	slices.SortFunc(ranks, func(a, b ranked) int {
		if a.unfit != b.unfit {
			if a.unfit < b.unfit {
				return -1
			}
			return 1
		}
		if a.rtt < b.rtt {
			return -1
		} else if a.rtt > b.rtt {
			return 1
		}
		return 0
	})

	// 5% Epsilon-Greedy Exploration: pluck a random server and shove it to the front
	// of the queue to organically test for recovered network pathways.
	//
	// [FIX 2.52.0] The draw now excludes index 0. Previously rand.IntN(n) could
	// select the element that was ALREADY at the front, in which case the guard
	// `if rIdx > 0` correctly skipped the rotation — but isRandom was set true
	// regardless, so the strategy log claimed an exploration that had not
	// happened. Drawing from 1..n-1 makes every exploration draw a real one and
	// the label always truthful.
	isRandom := false
	if n > 1 && rand.Float32() < 0.05 {
		rIdx := 1 + rand.IntN(n-1)
		chosen := ranks[rIdx]
		// Shift others down natively
		for i := rIdx; i > 0; i-- {
			ranks[i] = ranks[i-1]
		}
		ranks[0] = chosen
		isRandom = true
	}

	if logStrategy {
		qName := req.Question[0].Name
		qType := dns.TypeToString[req.Question[0].Qtype]
		reason := "ema-based"
		if isRandom {
			reason = "epsilon-greedy random"
		}
		for i, r := range ranks {
			mark := " "
			if i == 0 {
				mark = "*"
			}
			// Report the RAW measurement so an operator can distinguish "fast"
			// from "never measured"; the baseline is a ranking device, not an
			// observation, and printing it as one would be a fabricated metric.
			rttMs := r.rawRTT / 1000000
			state := ""
			if r.rawRTT <= 0 {
				state = " unprobed"
			}
			if r.unfit != 0 {
				state += " UNHEALTHY"
			}
			log.Printf("[STRATEGY] [%s] %s %s | fastest (%s) | POOL MEMBER: %s %s (EMA: %dms%s)", clientID, qName, qType, reason, mark, getUpstreamURL(r.up, clientName), rttMs, state)
		}
	}

	ordered := make([]*Upstream, n)
	for i, r := range ranks {
		ordered[i] = r.up
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

// minStrictConsensus is the number of upstreams that must independently return
// a MATCHING DNS payload before `mode: strict` will serve an answer.
//
// [SECURITY 2.51.0] Two is the smallest number for which the word "consensus"
// means anything at all: it is the point at which a second, independent view of
// the zone has confirmed the first. One peer answering is not agreement, it is
// simply a forwarded answer wearing a consensus label.
//
// Raising this beyond 2 would make strict mode fragile on the small pools it is
// most often deployed against (two or three curated resolvers), where a single
// upstream going down for maintenance would take the whole group offline. Two
// preserves availability across one failure while still guaranteeing that every
// served answer was corroborated.
const minStrictConsensus = 2

// synthesizeConsensusBlock crafts a secure payload natively mirroring the active global block definitions.
// If the global action is Drop, it returns a specialized error to cleanly terminate the connection in ProcessDNS.
func synthesizeConsensusBlock(req *dns.Msg, consensusAddr string) (*dns.Msg, string, error) {
	if globalBlockAction == BlockActionDrop {
		return nil, consensusAddr, ErrSilentDrop
	}
	
	// [PERF] Retrieve from pool to generate the template, but strictly clone 
	// and return it so the pool lifecycle is preserved. Upstream responses 
	// are not placed back into the pool by ProcessDNS.
	pooled := generateBlockMsg(req, syntheticTTL)
	msg := pooled.Copy()
	msgPool.Put(pooled)
	
	return msg, consensusAddr, nil
}

// selectSecureFanout picks which members of the group participate in this
// consensus round, capped at maxSecure.
//
// [SECURITY/FIX 2.52.0] Replaces `servers[:maxSecure]`.
//
// Taking the first N in configured order made the participant set completely
// static: with a ten-server group capped at five, members 6-10 could never
// contribute to a consensus decision under any circumstances. That interacts
// badly with the strict-mode quorum floor added in 2.51.0 — an attacker who can
// degrade the first five members (blackhole them, slow-loris them, or simply
// beat them to the deadline) drives evalResults below minStrictConsensus and
// the group fails closed on every query, while five perfectly healthy peers sit
// idle. The operator's remedy would have been to reorder their config, which is
// not a thing anyone discovers under attack.
//
// Selection is healthy-first, and CONFIGURED ORDER is preserved within each
// health class. That ordering choice is deliberate:
//
//   - Not RTT-sorted. Consensus derives its value from independent views. Always
//     selecting the fastest peers would systematically re-sample the same subset
//     — typically the topologically closest ones, which are also the ones most
//     likely to share an on-path adversary — and correlate exactly the evidence
//     the mode exists to keep independent.
//   - Not randomised. A participant set that changes per query makes a
//     consensus failure irreproducible, and "it blocks sometimes" is the hardest
//     class of bug to diagnose in a resolver.
//
// Unhealthy members backfill the remaining slots rather than being excluded
// outright: a group whose members are ALL currently marked unhealthy must still
// attempt the query, and isHealthy() is a heuristic over recent consecutive
// failures, not a verdict.
func selectSecureFanout(servers []*Upstream, maxSecure int) []*Upstream {
	if len(servers) <= maxSecure {
		return servers
	}

	out := make([]*Upstream, 0, maxSecure)

	// Pass 1: healthy members, in configured order.
	for _, up := range servers {
		if len(out) == maxSecure {
			return out
		}
		if up.isHealthy() {
			out = append(out, up)
		}
	}

	// Pass 2: backfill with the rest, still in configured order.
	for _, up := range servers {
		if len(out) == maxSecure {
			break
		}
		if !up.isHealthy() {
			out = append(out, up)
		}
	}

	return out
}

// exchangeSecure queries a bounded subset of upstreams in the group simultaneously to 
// enforce strict/loose consensus. Provides on-the-fly verification to instantly 
// short-circuit discrepancies securely.
//
// [FEAT] The number of servers queried simultaneously is capped by
// g.MaxSecureUpstreams (configurable via server.max_secure_upstreams, default 5,
// see config.go/init_upstreams.go). Previously this fan-out was unconditionally
// every server in the group; large "secure" pools could fire dozens of parallel
// consensus dials per query.
//
// [SECURITY 2.52.0] WHICH servers participate is decided by selectSecureFanout()
// — healthy members first, configured order preserved within each health class —
// rather than by a flat prefix slice. See that function for why.
func (g *UpstreamGroup) exchangeSecure(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	// [FEAT] Resolve the effective fan-out cap. Falls back to the historical 
	// hardcoded default of 5 if the group was somehow constructed without one 
	// (e.g. unit tests instantiating UpstreamGroup directly).
	maxSecure := g.MaxSecureUpstreams
	if maxSecure <= 0 {
		maxSecure = 5
	}

	servers := selectSecureFanout(g.Servers, maxSecure)
	n := len(servers)
	
	// [PERF/FIX] Secure mode queries the bounded server subset simultaneously.
	// We intelligently bound the consensus gathering phase using the overarching 
	// execution context natively. If no global timeout is defined, we enforce 
	// a 2500ms safety net to prevent a single dead server from stalling the pipeline.
	timeout := 2500 * time.Millisecond
	if dl, ok := ctx.Deadline(); ok {
		if t := time.Until(dl); t > 0 && t < timeout {
			timeout = t // Honor the parent deadline if it's strictly shorter than our safety net natively
		}
	}
	raceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel() // Native cancel cleans up all remaining in-flight dials instantly upon short-circuit

	// [PERF/FIX] Establish baseline expectations for healthy servers natively.
	// This prevents the consensus gathering phase from stalling blindly on known-dead targets.
	expectedHealthy := 0
	for _, up := range servers {
		if up.isHealthy() {
			expectedHealthy++
		}
	}
	if expectedHealthy == 0 {
		expectedHealthy = 1 // Enforce evaluating at least one regardless of health
	}

	type raceResult struct {
		msg  *dns.Msg
		addr string
		up   *Upstream
		err  error
		rtt  int64
	}
	
	ch := make(chan raceResult, n)
	for _, up := range servers {
		go func(u *Upstream) {
			start := time.Now()
			msg, addr, err := u.Exchange(raceCtx, req, clientID, clientName, clientAddr)
			ch <- raceResult{msg, addr, u, err, time.Since(start).Nanoseconds()}
		}(up)
	}
	
	var results []raceResult
	var evalResults []raceResult
	var baseRcode int
	var baseHasAnswers bool
	var baseFingerprint string
	baseSet := false

	consensusAddr := "consensus(" + g.Name + ")"

	// Evaluate validation immediately as responses hit the wire
	evaluateResult := func(r raceResult) bool {
		if g.Mode == "strict" {
			if r.err != nil || r.msg == nil {
				// [SECURITY/FIX 2.50.0] A peer that produced no DNS payload is
				// forgiven and skipped, regardless of why.
				//
				// The question consensus exists to answer is "do the upstreams
				// AGREE about this name". A peer that never spoke has not
				// disagreed — it has abstained. Treating an abstention as a
				// disagreement lets any transport hiccup on any single peer
				// suppress a valid, unanimous answer from all the others.
				//
				// 2.49.0 forgave only context.Canceled and
				// context.DeadlineExceeded. That left every other ordinary
				// failure still able to synthesise a block for the whole query:
				// ECONNREFUSED while an upstream restarts, io.EOF from a
				// connection torn down mid-TLS, EHOSTUNREACH on a transient
				// route flap, a TLS handshake failure, a DoH 5xx, a QUIC reset.
				// None of those carry any information about cache poisoning, yet
				// each one produced a hard consensus failure.
				//
				// Two properties are deliberately preserved:
				//
				//   Poison detection is untouched. A malicious upstream has to
				//   actually reply to assert anything, so it arrives with
				//   r.msg != nil and is still subjected to the NULL-IP, RCODE
				//   and answer-fingerprint checks below, all of which fail closed.
				//
				//   Total failure still fails closed. If NO peer produces a valid
				//   payload, evalResults stays empty and the
				//   `len(evalResults) == 0` guard after this loop blocks the
				//   query. "Nobody answered" is not silently upgraded to "answer
				//   allowed".
				//
				// Logged only under logStrategy: on a flapping upstream this
				// fires per query per peer, and it is now an expected, benign
				// condition rather than a security event.
				if logStrategy {
					log.Printf("[STRATEGY] [%s] Consensus: peer %s abstained for %s (no payload: %v)",
						clientID, r.addr, req.Question[0].Name, r.err)
				}
				return true
			}
			if responseContainsNullIP(r.msg) {
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: NULL-IP detected from %s", clientID, req.Question[0].Name, r.addr)
				return false
			}
			if !baseSet {
				baseRcode = r.msg.Rcode
				baseHasAnswers = len(r.msg.Answer) > 0
				if baseRcode == dns.RcodeSuccess {
					baseFingerprint = extractAnswerFingerprint(r.msg)
				}
				baseSet = true
			} else {
				if r.msg.Rcode != baseRcode {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: RCODE mismatch (base: %d, peer: %d) from %s", clientID, req.Question[0].Name, baseRcode, r.msg.Rcode, r.addr)
					return false
				}
				if baseRcode == dns.RcodeSuccess {
					if (len(r.msg.Answer) > 0) != baseHasAnswers {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: mixed empty/non-empty NOERROR responses from %s", clientID, req.Question[0].Name, r.addr)
						return false
					}
					fp := extractAnswerFingerprint(r.msg)
					if fp != baseFingerprint {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode answer mismatch from %s", clientID, req.Question[0].Name, r.addr)
						return false
					}
				}
			}
			evalResults = append(evalResults, r)
			return true
		} else {
			// Loose mode filters out any return codes other than NOERROR and NXDOMAIN,
			// and completely disregards connection timeouts and execution failures natively.
			if r.err == nil && r.msg != nil && (r.msg.Rcode == dns.RcodeSuccess || r.msg.Rcode == dns.RcodeNameError) {
				if responseContainsNullIP(r.msg) {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: NULL-IP detected from %s", clientID, req.Question[0].Name, r.addr)
					return false
				}
				if !baseSet {
					baseRcode = r.msg.Rcode
					baseHasAnswers = len(r.msg.Answer) > 0
					baseSet = true
				} else {
					if r.msg.Rcode != baseRcode {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: RCODE mismatch (base: %d, peer: %d) from %s", clientID, req.Question[0].Name, baseRcode, r.msg.Rcode, r.addr)
						return false
					}
					if baseRcode == dns.RcodeSuccess {
						if (len(r.msg.Answer) > 0) != baseHasAnswers {
							log.Printf("[SECURITY] [%s] Consensus validation failed for %s: mixed empty/non-empty NOERROR responses from %s", clientID, req.Question[0].Name, r.addr)
							return false
						}
					}
				}
				evalResults = append(evalResults, r)
			}
			return true
		}
	}

	healthyReceived := 0
	for i := 0; i < n; i++ {
		r := <-ch
		results = append(results, r)
		
		if r.up.isHealthy() {
			healthyReceived++
		}

		if r.err == nil && r.msg != nil {
			r.up.recordSuccess()
			g.updateRTT(r.up, r.rtt)
		} else if r.err != nil && !errors.Is(r.err, context.Canceled) {
			r.up.recordFailure()
			g.penalizeRTT(r.up)
		}

		// Short-circuit execution instantly on mismatch.
		// The active defer cancel() will brutally sever the trailing dials safely.
		if !evaluateResult(r) {
			return synthesizeConsensusBlock(req, consensusAddr)
		}

		// [OPTIMIZATION] Majority Quorum Consensus Optimization for Loose Mode:
		// If we are in loose mode, and the number of successful matching responses 
		// constitutes a strict majority of the expected healthy servers, we can 
		// short-circuit immediately without waiting for slow/unresponsive servers.
		if g.Mode == "loose" && len(evalResults) > 0 {
			majority := expectedHealthy/2 + 1
			if len(evalResults) >= majority {
				break // Short-circuit and return the consensus result immediately
			}
		}
		
		// If in loose mode, bypass waiting for offline servers once we have
		// gathered responses from all available healthy peers natively.
		if g.Mode == "loose" && healthyReceived >= expectedHealthy {
			// Short 2ms grace period to absorb simultaneous immediate stragglers seamlessly via select timeout
			grace := time.NewTimer(2 * time.Millisecond)
		drainLoop:
			for i < n-1 {
				select {
				case extra := <-ch:
					results = append(results, extra)
					if extra.up.isHealthy() {
						healthyReceived++
					}
					if extra.err == nil && extra.msg != nil {
						extra.up.recordSuccess()
						g.updateRTT(extra.up, extra.rtt)
					} else if extra.err != nil && !errors.Is(extra.err, context.Canceled) {
						extra.up.recordFailure()
						g.penalizeRTT(extra.up)
					}
					if !evaluateResult(extra) {
						grace.Stop()
						return synthesizeConsensusBlock(req, consensusAddr)
					}
					i++ // Advance outer tracker natively
				case <-grace.C:
					break drainLoop
				}
			}
			grace.Stop()
			break // Execute consensus aggressively without stalling
		}
	}

	if len(evalResults) == 0 {
		log.Printf("[SECURITY] [%s] Consensus validation failed for %s: no valid responses eligible for consensus (mode: %s)", clientID, req.Question[0].Name, g.Mode)
		return synthesizeConsensusBlock(req, consensusAddr)
	}

	// ── [SECURITY/FIX 2.51.0] Strict-mode quorum floor (S-A) ─────────────────
	//
	// The 2.50.0 abstention fix is correct in principle — a peer that produced
	// no DNS payload has not disagreed, and treating a transport hiccup as
	// poisoning let one flaky upstream suppress a unanimous answer. But it
	// removed the last thing that guaranteed a strict-mode answer had actually
	// been CROSS-CHECKED against anything, because the only remaining gate was
	// `len(evalResults) == 0`.
	//
	// The consequence: with a five-server secure group, if four peers abstain
	// (blackholed, slow, restarting, route-flapped, or simply beaten to the
	// deadline) the single peer that did reply satisfies the guard above and
	// its answer is served as "strict consensus". Nothing was compared. That is
	// reachable by an attacker who can degrade the other four — and it fails
	// silently, because from the operator's side the mode still reads "strict".
	//
	// A consensus of one is not a consensus. Strict mode therefore now requires
	// at least minStrictConsensus peers to have produced MATCHING payloads
	// whenever the fan-out actually contained more than one server, and fails
	// closed otherwise.
	//
	// Scope is deliberately narrow:
	//
	//   • Loose mode is untouched. Its documented contract already is "take the
	//     first acceptable answer and short-circuit on a majority", and it has
	//     its own expectedHealthy quorum optimisation above. Applying a floor
	//     there would change the meaning of an existing, working setting.
	//
	//   • n > 1 guard. A group with a single server never reaches exchangeSecure
	//     at all (Exchange short-circuits on len(g.Servers) == 1), but
	//     max_secure_upstreams can legitimately clamp the fan-out to 1. In that
	//     configuration the operator has explicitly asked for one dial, so
	//     demanding two agreeing answers would make the group permanently
	//     unresolvable rather than secure.
	//
	//   • No new configuration knob. "strict" already IS the opt-in: an operator
	//     who wants an answer served on the strength of one reachable upstream
	//     is asking for `mode: loose`, or for a non-secure strategy. Adding a
	//     tunable floor would mostly create a way to configure strict mode into
	//     behaving exactly like the hole this closes.
	//
	// Poison detection is unchanged — a disagreeing peer still short-circuits to
	// a block inside evaluateResult() long before this point, so this guard only
	// ever fires on "not enough evidence", never on "conflicting evidence".
	//
	// [2.52.0] selectSecureFanout now fills this fan-out healthy-first, which
	// materially reduces how often this guard fires for benign reasons: the
	// abstentions that used to starve the quorum were frequently peers the
	// health tracker already knew were down, sitting at the front of the
	// configured list.
	if g.Mode == "strict" && n > 1 && len(evalResults) < minStrictConsensus {
		log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode requires %d agreeing upstreams, only %d of %d produced a payload (the rest abstained)",
			clientID, req.Question[0].Name, minStrictConsensus, len(evalResults), n)
		return synthesizeConsensusBlock(req, consensusAddr)
	}

	var finalMsg *dns.Msg
	var finalAddr string
	var winningUpstream *Upstream

	if g.Preference == "consolidate" && len(evalResults) > 1 {
		// [CONSOLIDATION] Merge all Answer records (A, AAAA, CNAME, etc.) from all valid upstreams.
		// Base the transaction on the first valid message to preserve transaction ID, questions, authority, and EDNS0 OPT headers.
		baseMsg := evalResults[0].msg.Copy()
		var uniqueAnswers []dns.RR
		
		for _, r := range evalResults {
			for _, rr := range r.msg.Answer {
				duplicate := false
				for _, existing := range uniqueAnswers {
					if equalRRs(rr, existing) {
						duplicate = true
						break
					}
				}
				if !duplicate {
					// Deep copy the record to avoid sharing pointers or mutability conflicts down the pipeline.
					uniqueAnswers = append(uniqueAnswers, dns.Copy(rr))
				}
			}
		}
		baseMsg.Answer = uniqueAnswers
		finalMsg = baseMsg
		finalAddr = "consolidate(" + g.Name + ")"
		winningUpstream = evalResults[0].up
	} else {
		var winningResult *raceResult
		if g.Preference == "ordered" {
			targetUpstream := g.Servers[0]
			for i := range evalResults {
				if evalResults[i].up == targetUpstream {
					winningResult = &evalResults[i]
					break
				}
			}
		}
		if winningResult == nil {
			winningResult = &evalResults[0]
		}
		finalMsg = winningResult.msg
		finalAddr = winningResult.addr
		winningUpstream = winningResult.up
	}

	if logStrategy && finalMsg != nil {
		qName := req.Question[0].Name
		qType := dns.TypeToString[req.Question[0].Qtype]
		for _, r := range results {
			mark := " "
			// During consolidation, we highlight all participating valid upstreams that contributed to the final result.
			if r.up == winningUpstream && (g.Preference == "consolidate" || r.addr == finalAddr) {
				mark = "*"
			}
			status := "error/timeout"
			if r.err == nil && r.msg != nil {
				status = RcodeStr(r.msg.Rcode)
			}
			log.Printf("[STRATEGY] [%s] %s %s | secure | POOL MEMBER: %s %s (%dms, %s)", clientID, qName, qType, mark, getUpstreamURL(r.up, clientName), r.rtt/1000000, status)
		}
	}

	return finalMsg, finalAddr, nil
}

// extractAnswerFingerprint generates a stable representation of the end-answers natively.
func extractAnswerFingerprint(msg *dns.Msg) string {
	if msg == nil || len(msg.Answer) == 0 { return "" }
	var items []string
	hasIPs := false
	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			items = append(items, "A:"+r.A.String())
			hasIPs = true
		case *dns.AAAA:
			items = append(items, "AAAA:"+r.AAAA.String())
			hasIPs = true
		}
	}
	if !hasIPs {
		for _, rr := range msg.Answer {
			switch r := rr.(type) {
			case *dns.CNAME: items = append(items, "CNAME:"+r.Target)
			case *dns.TXT: items = append(items, "TXT:"+strings.Join(r.Txt, ""))
			case *dns.PTR: items = append(items, "PTR:"+r.Ptr)
			case *dns.MX: items = append(items, fmt.Sprintf("MX:%d:%s", r.Preference, r.Mx))
			case *dns.SRV: items = append(items, fmt.Sprintf("SRV:%d:%d:%d:%s", r.Priority, r.Weight, r.Port, r.Target))
			case *dns.SOA: items = append(items, fmt.Sprintf("SOA:%s:%s:%d", r.Ns, r.Mbox, r.Serial))
			case *dns.HTTPS: items = append(items, fmt.Sprintf("HTTPS:%d:%s", r.Priority, r.Target))
			case *dns.SVCB: items = append(items, fmt.Sprintf("SVCB:%d:%s", r.Priority, r.Target))
			default: items = append(items, fmt.Sprintf("TYPE%d", rr.Header().Rrtype))
			}
		}
	}
	sort.Strings(items)
	return strings.Join(items, "|")
}

// updateRTT applies an Alpha-Smooth Exponential Moving Average (EMA).
func (g *UpstreamGroup) updateRTT(up *Upstream, rtt int64) {
	cur := up.emaRTT.Load()
	if cur == 0 {
		up.emaRTT.Store(rtt)
	} else {
		up.emaRTT.Store((cur*7 + rtt*3) / 10)
	}
}

// penalizeRTT aggressively punishes the upstream latency on failure.
func (g *UpstreamGroup) penalizeRTT(up *Upstream) {
	cur := up.emaRTT.Load()
	if cur == 0 {
		cur = 500 * 1000000 // 500ms
	}
	next := cur * 2
	// Prevent int64 overflow from wrapping into negative (which permanently breaks fastest evaluation)
	if next < 0 || next > 60*1000000000 {
		next = 60 * 1000000000 // Cap at 60 seconds
	}
	up.emaRTT.Store(next)
}

// bootstrapResolve resolves host natively against the provided encrypted or plaintext bootstrap servers.
//
// [FIX 2.52.0] The per-qtype loop now falls through to the next bootstrap server
// unless the current one actually yielded an address.
//
// It used to `break` on any response that was not a transport error, so a
// bootstrap server answering with an empty NOERROR, an NXDOMAIN, or a CNAME-only
// chain consumed the whole attempt and the configured fallbacks were never
// contacted. Because that response is a perfectly healthy one at the transport
// layer, nothing anywhere logged a failure and no failover heuristic engaged —
// the hostname simply did not resolve and the upstream group stayed down.
//
// That is a boot-time, single-point-of-failure defect on the one code path that
// has no encrypted transport to fall back on: bootstrap resolution is what turns
// a DoH/DoT hostname into an address in the first place.
func bootstrapResolve(host string, servers []*Upstream) []string {
	fqdn   := dns.Fqdn(host)
	seen   := make(map[string]struct{})
	var ips []string
	
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		// [FEAT] IP Version filtering for Bootstrap Resolution
		if ipVersionSupport == "ipv4" && qtype == dns.TypeAAAA { continue }
		if ipVersionSupport == "ipv6" && qtype == dns.TypeA { continue }
		
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)
		m.RecursionDesired = true
		
		opt := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		m.Extra = append(m.Extra, opt)
		
		for _, u := range servers {
			// [SECURITY/FIX] Guard against uninitialized pointers natively during parallel discovery loops.
			if u == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			// Explicitly bypass ECS constraints dynamically via null netip.Addr injections for bootstrap probing
			resp, _, err := u.Exchange(ctx, m, "bootstrap", "bootstrap", netip.Addr{})
			cancel()
			
			if err != nil || resp == nil { continue }

			// [FIX 2.52.0] Track whether THIS server contributed anything usable.
			// The unconditional break this replaces treated "answered" as
			// "answered usefully".
			harvested := false

			for _, rr := range resp.Answer {
				var s string
				switch rec := rr.(type) {
				case *dns.A: s = rec.A.String()
				case *dns.AAAA: s = rec.AAAA.String()
				}
				if s != "" {
					if addr, err := netip.ParseAddr(s); err == nil {
						if ipVersionSupport == "ipv4" && !addr.Is4() { continue }
						if ipVersionSupport == "ipv6" && !addr.Is6() { continue }
						harvested = true
						if _, dup := seen[s]; !dup {
							seen[s] = struct{}{}
							ips = append(ips, s)
						}
					}
				}
			}

			if harvested {
				break
			}
			// Nothing usable in this answer — an empty NOERROR, an NXDOMAIN, a
			// CNAME-only chain, or a family filtered out by ip_version_support.
			// Try the next bootstrap server rather than abandoning this qtype.
		}
	}
	return ips
}

// equalRRs compares two dns.RR records for semantic equality of type, class, name, and underlying data.
// Specially handles A, AAAA, and CNAME records, falling back to string matching for other types.
func equalRRs(a, b dns.RR) bool {
	// [PERF 2.48.0] Owner-name comparison uses strings.EqualFold rather than the
	// previous `strings.ToLower(x) != strings.ToLower(y)` construction. The old
	// form allocated two fresh lowercase strings on the heap for *every* pairwise
	// comparison, and equalRRs is invoked O(n²) across the answer set during
	// "consolidate" deduplication. EqualFold walks both strings in place, allocates
	// nothing, and short-circuits on the first differing byte. DNS owner names are
	// ASCII-cased per RFC 4343, so the folding semantics are equivalent here.
	if a.Header().Rrtype != b.Header().Rrtype ||
		a.Header().Class != b.Header().Class ||
		!strings.EqualFold(a.Header().Name, b.Header().Name) {
		return false
	}
	switch va := a.(type) {
	case *dns.A:
		vb, ok := b.(*dns.A)
		return ok && va.A.Equal(vb.A)
	case *dns.AAAA:
		vb, ok := b.(*dns.AAAA)
		return ok && va.AAAA.Equal(vb.AAAA)
	case *dns.CNAME:
		vb, ok := b.(*dns.CNAME)
		// [PERF 2.48.0] Zero-allocation case-insensitive target comparison,
		// same rationale as the owner-name check above.
		return ok && strings.EqualFold(va.Target, vb.Target)
	default:
		// [PERF 2.50.0] Two-tier comparison for the residual RR types (MX, SRV,
		// TXT, HTTPS, SVCB, ...).
		//
		// The requirement is a TTL-INSENSITIVE comparison: two upstreams
		// returning byte-identical rdata with slightly different remaining TTLs
		// are the same record, and treating them as distinct defeats dedup under
		// `preference: consolidate`.
		//
		// 2.48.0 implemented that with two dns.Copy deep clones plus two
		// String() calls — four allocations and a full RR duplication on EVERY
		// pairwise comparison, in a function that runs O(n^2) across the answer
		// set. That is strictly worse than the single String() pair it replaced,
		// despite the changelog claiming an allocation win.
		//
		// Tier 1: compare the full string forms directly. Records that are
		// genuinely identical — including TTL — match here in two allocations,
		// which is the overwhelmingly common case since merged upstream answers
		// are usually fetched within milliseconds of each other.
		as, bs := a.String(), b.String()
		if as == bs {
			return true
		}

		// Tier 2: the strings differ, which MAY be a TTL-only difference. Strip
		// the header prefix from each and compare the rdata alone.
		//
		// dns.RR.String() is defined as Header().String() + rdata, and
		// RR_Header.String() renders "name\tttl\tclass\ttype\t" — so slicing
		// each string at the length of its own header yields exactly the rdata,
		// with the TTL (and any name-case difference) removed. This costs two
		// further allocations, but only on the mismatch path, and never
		// duplicates the record itself.
		ah, bh := a.Header().String(), b.Header().String()
		if len(as) < len(ah) || len(bs) < len(bh) {
			// Defensive: a malformed RR whose String() is shorter than its own
			// header cannot be meaningfully compared. Fall back to inequality
			// rather than slicing out of bounds.
			return false
		}
		return as[len(ah):] == bs[len(bh):]
	}
}
