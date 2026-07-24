/*
File:    upstream_race.go
Version: 2.49.0
Last Updated: 24-Jul-2026 18:20 CEST

Description:
  Advanced routing and parallel execution strategies for sdproxy upstream groups.
  Abstracts away `stagger`, `round-robin`, `random`, `fastest`, and `secure` strategies.

Changes:
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

// exchangeFastest uses an Epsilon-Greedy approach integrated with staggered racing.
// Dynamically ranks all active connections natively by Exponential Moving Average.
func (g *UpstreamGroup) exchangeFastest(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	n := len(g.Servers)
	type ranked struct {
		up  *Upstream
		rtt int64
		idx int
	}
	
	ranks := make([]ranked, n)
	for i, up := range g.Servers {
		ranks[i] = ranked{up: up, rtt: up.emaRTT.Load(), idx: i}
	}

	// Sort by EMA latency natively, avoiding interface allocations (GC thrashing)
	slices.SortFunc(ranks, func(a, b ranked) int {
		if a.rtt < b.rtt {
			return -1
		} else if a.rtt > b.rtt {
			return 1
		}
		return 0
	})

	// 5% Epsilon-Greedy Exploration: pluck a random server and shove it to the front
	// of the queue to organically test for recovered network pathways.
	isRandom := false
	if rand.Float32() < 0.05 {
		rIdx := rand.IntN(n)
		if rIdx > 0 {
			chosen := ranks[rIdx]
			// Shift others down natively
			for i := rIdx; i > 0; i-- {
				ranks[i] = ranks[i-1]
			}
			ranks[0] = chosen
		}
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
			rttMs := r.rtt / 1000000
			log.Printf("[STRATEGY] [%s] %s %s | fastest (%s) | POOL MEMBER: %s %s (EMA: %dms)", clientID, qName, qType, reason, mark, getUpstreamURL(r.up, clientName), rttMs)
		}
	}

	ordered := make([]*Upstream, n)
	for i, r := range ranks {
		ordered[i] = r.up
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

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

// exchangeSecure queries a bounded subset of upstreams in the group simultaneously to 
// enforce strict/loose consensus. Provides on-the-fly verification to instantly 
// short-circuit discrepancies securely.
//
// [FEAT] The number of servers queried simultaneously is capped by
// g.MaxSecureUpstreams (configurable via server.max_secure_upstreams, default 5,
// see config.go/init_upstreams.go). Previously this fan-out was unconditionally
// every server in the group; large "secure" pools could fire dozens of parallel
// consensus dials per query. Servers beyond the cap are simply not queried for
// that request — group ordering (as configured) determines which ones participate.
func (g *UpstreamGroup) exchangeSecure(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	// [FEAT] Resolve the effective fan-out cap. Falls back to the historical 
	// hardcoded default of 5 if the group was somehow constructed without one 
	// (e.g. unit tests instantiating UpstreamGroup directly).
	maxSecure := g.MaxSecureUpstreams
	if maxSecure <= 0 {
		maxSecure = 5
	}

	servers := g.Servers
	if len(servers) > maxSecure {
		servers = servers[:maxSecure]
	}
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
				// [SECURITY/FIX 2.49.0] A transport-level *non-answer* is not evidence
				// of cache poisoning, and must not be allowed to nuke an otherwise-valid
				// consensus. Two flavours are forgiven and skipped (return true) rather
				// than treated as a hard validation failure (return false):
				//
				//   context.Canceled         — our own defer cancel() tearing down the
				//                              trailing dials after a short-circuit.
				//   context.DeadlineExceeded — a peer that simply timed out (dead/slow
				//                              server), OR the 2500ms consensus safety-net
				//                              firing on that peer's socket.
				//
				// Previously only Canceled was forgiven, so a SINGLE dead/slow upstream
				// returning DeadlineExceeded flipped evaluateResult to false and
				// synthesised a block for the whole query — suppressing perfectly valid,
				// matching answers from the healthy peers, and forcing strict-mode
				// latency to track the slowest peer all the way to the 2500ms ceiling.
				// This was the long-standing KNOWN-OPEN item recorded in version.go.
				//
				// Poison detection is unaffected: a genuinely malicious upstream replies
				// with r.msg != nil carrying mismatched RCODE / answer data, which is
				// still caught by the fingerprint/RCODE checks below. And if EVERY peer
				// fails to answer, the `len(evalResults) == 0` guard downstream still
				// blocks the query — so "nobody agreed" continues to fail closed.
				if r.err != nil && (errors.Is(r.err, context.Canceled) || errors.Is(r.err, context.DeadlineExceeded)) {
					return true
				}
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: upstream %s returned error: %v", clientID, req.Question[0].Name, r.addr, r.err)
				return false
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
						if _, dup := seen[s]; !dup {
							seen[s] = struct{}{}
							ips = append(ips, s)
						}
					}
				}
			}
			break
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
		// Compare RR string representation excluding the TTL field,
		// since dns.RR.String() embeds TTL and two upstreams legitimately
		// returning identical data with a slightly different remaining TTL
		// would otherwise be treated as distinct records, defeating dedup
		// in the "consolidate" preference.
		// Original: return a.String() == b.String()
		ah, bh := *a.Header(), *b.Header()
		ah.Ttl, bh.Ttl = 0, 0
		aCopy, bCopy := dns.Copy(a), dns.Copy(b)
		*aCopy.Header() = ah
		*bCopy.Header() = bh
		return aCopy.String() == bCopy.String()
	}
}


