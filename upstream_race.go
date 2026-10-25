/*
File:    upstream_race.go
Version: 2.57.0
Last Updated: 25-Oct-2026 15:10 CET

Description:
  Advanced routing and parallel execution strategies for sdproxy upstream groups.
  Abstracts away `stagger`, `round-robin`, `random`, `fastest`, and `secure` strategies.

Changes:
  2.57.0 - [SECURITY/FIX] Enforced 100% upstream participation in `strict` consensus
           mode (`exchangeSecure`). Any timeout, error, nil message, or RCODE other
           than NOERROR/NXDOMAIN from any selected upstream immediately fails strict
           consensus.
         - [SECURITY/FIX] Overhauled `extractAnswerFingerprint` to canonicalize complete
           RRsets (owner, type, class, canonical RDATA for all DNS record types including
           CNAME chains, SVCB/HTTPS params, DNSKEY, DS, CAA, TLSA, etc., excluding TTL
           and volatile RRSIGs while preserving AD/signed state and negative SOA state).
  2.56.0 - [SECURITY/FIX] Cleared `baseMsg.AuthenticatedData = false` and `baseMsg.Ns = nil`
           and skipped `RRSIG` records when merging answers in `consolidate` preference
           mode (`exchangeSecure`).
  2.55.0 - [SECURITY/FIX] Hardened `extractAnswerFingerprint` and `consolidate` in
           `exchangeSecure` to validate records against the query's CNAME bailiwick
           chain, and restricted `consolidate` merging to A/AAAA queries.
  2.54.0 - [SECURITY/FIX] Upgraded `bootstrapResolve` to follow CNAME chains when
           upstream bootstrap responses return only CNAME records without in-message
           A/AAAA records (up to 4 hops).
  2.53.2 - [SECURITY/FIX] Explicitly enforced `msgPool.Put()` returns on synthetic
           block generation constructed during consensus abort short-circuits.
  2.53.1 - [FIX] Addressed an undeclared `responseContainsNullIP` evaluation fallback
           natively within `evaluateResult`.
*/

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"strconv"
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

func (g *UpstreamGroup) executeRace(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr, ordered []*Upstream) (*dns.Msg, string, error) {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

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

func (g *UpstreamGroup) exchangeStagger(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, g.Servers)
}

func (g *UpstreamGroup) exchangeRoundRobin(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	idx := int(g.rrCount.Add(1) % uint64(len(g.Servers)))
	ordered := make([]*Upstream, len(g.Servers))
	for i := 0; i < len(g.Servers); i++ {
		ordered[i] = g.Servers[(idx+i)%len(g.Servers)]
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

func (g *UpstreamGroup) exchangeRandom(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	idx := rand.IntN(len(g.Servers))
	ordered := make([]*Upstream, len(g.Servers))
	for i := 0; i < len(g.Servers); i++ {
		ordered[i] = g.Servers[(idx+i)%len(g.Servers)]
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

const fastestUnprobedRTT = int64(50 * time.Millisecond)

func (g *UpstreamGroup) exchangeFastest(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	n := len(g.Servers)
	type ranked struct {
		up     *Upstream
		rtt    int64
		rawRTT int64
		unfit  int
		idx    int
	}

	ranks := make([]ranked, n)
	for i, up := range g.Servers {
		raw := up.emaRTT.Load()

		eff := raw
		if eff <= 0 {
			eff = fastestUnprobedRTT
		}

		unfit := 0
		if !up.isHealthy() {
			unfit = 1
		}

		ranks[i] = ranked{up: up, rtt: eff, rawRTT: raw, unfit: unfit, idx: i}
	}

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

	isRandom := false
	if n > 1 && rand.Float32() < 0.05 {
		rIdx := 1 + rand.IntN(n-1)
		chosen := ranks[rIdx]
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

func synthesizeConsensusBlock(req *dns.Msg, consensusAddr string) (*dns.Msg, string, error) {
	if globalBlockAction == BlockActionDrop {
		return nil, consensusAddr, ErrSilentDrop
	}

	pooled := generateBlockMsg(req, syntheticTTL)
	msg := pooled.Copy()
	msgPool.Put(pooled)

	return msg, consensusAddr, nil
}

func selectSecureFanout(servers []*Upstream, maxSecure int) []*Upstream {
	if len(servers) <= maxSecure {
		return servers
	}

	out := make([]*Upstream, 0, maxSecure)

	for _, up := range servers {
		if len(out) == maxSecure {
			return out
		}
		if up.isHealthy() {
			out = append(out, up)
		}
	}

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

func buildMsgBailiwickChain(msg *dns.Msg, buf *[64]string) []string {
	if msg == nil || len(msg.Question) == 0 {
		return nil
	}
	validNames := buf[:0]
	validNames = append(validNames, strings.ToLower(msg.Question[0].Name))

	for depth := 0; depth < 16; depth++ {
		added := false
		for _, rr := range msg.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				owner := strings.ToLower(c.Hdr.Name)
				if isValidBailiwickName(validNames, owner) {
					target := strings.ToLower(c.Target)
					if !isValidBailiwickName(validNames, target) {
						if len(validNames) >= 64 {
							return nil
						}
						validNames = append(validNames, target)
						added = true
					}
				}
			}
		}
		if !added {
			break
		}
	}

	for _, rr := range msg.Answer {
		if !isValidBailiwickName(validNames, strings.ToLower(rr.Header().Name)) {
			return nil
		}
	}
	return validNames
}

// exchangeSecure queries a bounded subset of upstreams in the group simultaneously to 
// enforce strict/loose consensus.
// In strict mode, 100% participation is required: every selected upstream must return
// a valid response and agree on RCODE, bailiwick, and canonical RRset fingerprint.
func (g *UpstreamGroup) exchangeSecure(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	maxSecure := g.MaxSecureUpstreams
	if maxSecure <= 0 {
		maxSecure = 5
	}

	servers := selectSecureFanout(g.Servers, maxSecure)
	n := len(servers)

	timeout := 2500 * time.Millisecond
	if dl, ok := ctx.Deadline(); ok {
		if t := time.Until(dl); t > 0 && t < timeout {
			timeout = t
		}
	}
	raceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	expectedHealthy := 0
	for _, up := range servers {
		if up.isHealthy() {
			expectedHealthy++
		}
	}
	if expectedHealthy == 0 {
		expectedHealthy = 1
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

	evaluateResult := func(r raceResult) bool {
		hasNullIP := false
		if r.msg != nil {
			var chainBuf [64]string
			if len(r.msg.Answer) > 0 && buildMsgBailiwickChain(r.msg, &chainBuf) == nil {
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: out-of-bailiwick record from %s", clientID, req.Question[0].Name, r.addr)
				return false
			}
			for _, rr := range r.msg.Answer {
				switch rec := rr.(type) {
				case *dns.A:
					if rec.A.IsUnspecified() {
						hasNullIP = true
					}
				case *dns.AAAA:
					if rec.AAAA.IsUnspecified() {
						hasNullIP = true
					}
				}
				if hasNullIP {
					break
				}
			}
		}

		if g.Mode == "strict" {
			// [SECURITY/FIX 2.57.0] Strict mode requires 100% participation across all dialed upstreams.
			if r.err != nil || r.msg == nil {
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode requires 100%% participation, upstream %s failed (%v)",
					clientID, req.Question[0].Name, r.addr, r.err)
				return false
			}
			if r.msg.Truncated {
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode rejected truncated (TC=1) response from %s",
					clientID, req.Question[0].Name, r.addr)
				return false
			}
			if r.msg.Rcode != dns.RcodeSuccess && r.msg.Rcode != dns.RcodeNameError {
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode rejected RCODE %s from %s",
					clientID, req.Question[0].Name, RcodeStr(r.msg.Rcode), r.addr)
				return false
			}
			if hasNullIP {
				log.Printf("[SECURITY] [%s] Consensus validation failed for %s: NULL-IP detected from %s", clientID, req.Question[0].Name, r.addr)
				return false
			}
			fp := extractAnswerFingerprint(r.msg)
			if !baseSet {
				baseRcode = r.msg.Rcode
				baseHasAnswers = len(r.msg.Answer) > 0
				baseFingerprint = fp
				baseSet = true
			} else {
				if r.msg.Rcode != baseRcode {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: RCODE mismatch (base: %d, peer: %d) from %s", clientID, req.Question[0].Name, baseRcode, r.msg.Rcode, r.addr)
					return false
				}
				if (len(r.msg.Answer) > 0) != baseHasAnswers {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: mixed empty/non-empty responses from %s", clientID, req.Question[0].Name, r.addr)
					return false
				}
				if fp != baseFingerprint {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode answer mismatch from %s", clientID, req.Question[0].Name, r.addr)
					return false
				}
			}
			evalResults = append(evalResults, r)
			return true
		} else {
			if r.err == nil && r.msg != nil && (r.msg.Rcode == dns.RcodeSuccess || r.msg.Rcode == dns.RcodeNameError) {
				if hasNullIP {
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

		if !evaluateResult(r) {
			return synthesizeConsensusBlock(req, consensusAddr)
		}

		if g.Mode == "loose" && len(evalResults) > 0 {
			majority := expectedHealthy/2 + 1
			if len(evalResults) >= majority {
				break
			}
		}

		if g.Mode == "loose" && healthyReceived >= expectedHealthy {
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
					i++
				case <-grace.C:
					break drainLoop
				}
			}
			grace.Stop()
			break
		}
	}

	if len(evalResults) == 0 {
		log.Printf("[SECURITY] [%s] Consensus validation failed for %s: no valid responses eligible for consensus (mode: %s)", clientID, req.Question[0].Name, g.Mode)
		return synthesizeConsensusBlock(req, consensusAddr)
	}

	if g.Mode == "strict" && len(evalResults) != n {
		log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode requires all %d upstreams to agree, only %d succeeded",
			clientID, req.Question[0].Name, n, len(evalResults))
		return synthesizeConsensusBlock(req, consensusAddr)
	}

	var finalMsg *dns.Msg
	var finalAddr string
	var winningUpstream *Upstream

	qtype := req.Question[0].Qtype
	if g.Preference == "consolidate" && len(evalResults) > 1 && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		baseMsg := evalResults[0].msg.Copy()
		var uniqueAnswers []dns.RR
		hasOwnerCNAME := make(map[string]bool)

		for _, r := range evalResults {
			for _, rr := range r.msg.Answer {
				rt := rr.Header().Rrtype
				if rt == dns.TypeRRSIG {
					continue
				}
				if rt == dns.TypeCNAME {
					ownerLower := strings.ToLower(rr.Header().Name)
					if hasOwnerCNAME[ownerLower] {
						continue
					}
					hasOwnerCNAME[ownerLower] = true
				}
				duplicate := false
				for _, existing := range uniqueAnswers {
					if equalRRs(rr, existing) {
						duplicate = true
						break
					}
				}
				if !duplicate {
					uniqueAnswers = append(uniqueAnswers, dns.Copy(rr))
				}
			}
		}
		baseMsg.AuthenticatedData = false
		baseMsg.Answer = uniqueAnswers
		if len(uniqueAnswers) > 0 {
			baseMsg.Ns = nil
		}
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

// canonicalizeRR formats a complete DNS resource record into a canonical,
// TTL-independent, case-normalized string for strict consensus comparison.
func canonicalizeRR(rr dns.RR) string {
	if rr == nil {
		return ""
	}
	hdr := rr.Header()
	owner := strings.ToLower(dns.Fqdn(hdr.Name))
	prefix := owner + ":" + strconv.Itoa(int(hdr.Class)) + ":" + strconv.Itoa(int(hdr.Rrtype)) + ":"

	switch r := rr.(type) {
	case *dns.A:
		if addr, ok := netip.AddrFromSlice(r.A); ok {
			return prefix + addr.Unmap().String()
		}
		return prefix + r.A.String()
	case *dns.AAAA:
		if addr, ok := netip.AddrFromSlice(r.AAAA); ok {
			return prefix + addr.String()
		}
		return prefix + r.AAAA.String()
	case *dns.CNAME:
		return prefix + strings.ToLower(dns.Fqdn(r.Target))
	case *dns.NS:
		return prefix + strings.ToLower(dns.Fqdn(r.Ns))
	case *dns.PTR:
		return prefix + strings.ToLower(dns.Fqdn(r.Ptr))
	case *dns.DNAME:
		return prefix + strings.ToLower(dns.Fqdn(r.Target))
	case *dns.MX:
		return fmt.Sprintf("%s%d:%s", prefix, r.Preference, strings.ToLower(dns.Fqdn(r.Mx)))
	case *dns.SRV:
		return fmt.Sprintf("%s%d:%d:%d:%s", prefix, r.Priority, r.Weight, r.Port, strings.ToLower(dns.Fqdn(r.Target)))
	case *dns.SOA:
		return fmt.Sprintf("%s%s:%s", prefix, strings.ToLower(dns.Fqdn(r.Ns)), strings.ToLower(dns.Fqdn(r.Mbox)))
	case *dns.TXT:
		return prefix + strings.Join(r.Txt, "\x00")
	case *dns.CAA:
		return fmt.Sprintf("%s%d:%s:%s", prefix, r.Flag, strings.ToLower(r.Tag), r.Value)
	case *dns.DNSKEY:
		return fmt.Sprintf("%s%d:%d:%d:%s", prefix, r.Flags, r.Protocol, r.Algorithm, r.PublicKey)
	case *dns.DS:
		return fmt.Sprintf("%s%d:%d:%d:%s", prefix, r.KeyTag, r.Algorithm, r.DigestType, strings.ToLower(r.Digest))
	case *dns.TLSA:
		return fmt.Sprintf("%s%d:%d:%d:%s", prefix, r.Usage, r.Selector, r.MatchingType, strings.ToLower(r.Certificate))
	case *dns.SSHFP:
		return fmt.Sprintf("%s%d:%d:%s", prefix, r.Algorithm, r.Type, strings.ToLower(r.FingerPrint))
	case *dns.NAPTR:
		return fmt.Sprintf("%s%d:%d:%s:%s:%s:%s", prefix, r.Order, r.Preference, strings.ToLower(r.Flags), strings.ToLower(r.Service), r.Regexp, strings.ToLower(dns.Fqdn(r.Replacement)))
	case *dns.SVCB:
		params := make([]string, 0, len(r.Value))
		for _, kv := range r.Value {
			params = append(params, kv.Key().String()+"="+kv.String())
		}
		sort.Strings(params)
		return fmt.Sprintf("%s%d:%s:%s", prefix, r.Priority, strings.ToLower(dns.Fqdn(r.Target)), strings.Join(params, ";"))
	case *dns.HTTPS:
		params := make([]string, 0, len(r.Value))
		for _, kv := range r.Value {
			params = append(params, kv.Key().String()+"="+kv.String())
		}
		sort.Strings(params)
		return fmt.Sprintf("%s%d:%s:%s", prefix, r.Priority, strings.ToLower(dns.Fqdn(r.Target)), strings.Join(params, ";"))
	default:
		cp := dns.Copy(rr)
		cp.Header().Name = owner
		cp.Header().Ttl = 0
		var buf [4096]byte
		if off, err := dns.PackRR(cp, buf[:], 0, nil, false); err == nil && off > 0 {
			return prefix + hex.EncodeToString(buf[:off])
		}
		full := cp.String()
		hdrStr := cp.Header().String()
		if len(full) >= len(hdrStr) {
			return prefix + strings.TrimSpace(full[len(hdrStr):])
		}
		return prefix + full
	}
}

// extractAnswerFingerprint generates a canonical, order-independent representation
// of a DNS response for strict consensus verification.
// Compares all records in Answer (including CNAME chains and full SVCB/HTTPS/DNSSEC parameters),
// preserves the distinction between DNSSEC-signed and unsigned answers, and normalizes
// negative responses.
func extractAnswerFingerprint(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}

	var items []string
	hasRRSIG := false

	for _, rr := range msg.Answer {
		rt := rr.Header().Rrtype
		if rt == dns.TypeOPT {
			continue
		}
		if rt == dns.TypeRRSIG {
			hasRRSIG = true
			if sig, ok := rr.(*dns.RRSIG); ok {
				items = append(items, fmt.Sprintf("SIG:%s:%d:%d",
					strings.ToLower(dns.Fqdn(sig.Hdr.Name)), sig.TypeCovered, sig.Algorithm))
			}
			continue
		}
		items = append(items, canonicalizeRR(rr))
	}

	if len(msg.Answer) == 0 {
		for _, rr := range msg.Ns {
			switch r := rr.(type) {
			case *dns.SOA:
				items = append(items, "NS_SOA:"+strings.ToLower(dns.Fqdn(r.Hdr.Name))+":"+strings.ToLower(dns.Fqdn(r.Ns)))
			case *dns.RRSIG:
				hasRRSIG = true
			}
		}
	}

	sort.Strings(items)
	items = slices.Compact(items)

	secPrefix := "U|"
	if msg.AuthenticatedData && hasRRSIG {
		secPrefix = "AD+SIG|"
	} else if msg.AuthenticatedData {
		secPrefix = "AD|"
	} else if hasRRSIG {
		secPrefix = "SIG|"
	}

	return secPrefix + strconv.Itoa(msg.Rcode) + "|" + strings.Join(items, "|")
}

func (g *UpstreamGroup) updateRTT(up *Upstream, rtt int64) {
	cur := up.emaRTT.Load()
	if cur == 0 {
		up.emaRTT.Store(rtt)
	} else {
		up.emaRTT.Store((cur*7 + rtt*3) / 10)
	}
}

func (g *UpstreamGroup) penalizeRTT(up *Upstream) {
	cur := up.emaRTT.Load()
	if cur == 0 {
		cur = 500 * 1000000
	}
	next := cur * 2
	if next < 0 || next > 60*1000000000 {
		next = 60 * 1000000000
	}
	up.emaRTT.Store(next)
}

func bootstrapResolve(host string, servers []*Upstream) []string {
	seen := make(map[string]struct{})
	var ips []string

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if ipVersionSupport == "ipv4" && qtype == dns.TypeAAAA {
			continue
		}
		if ipVersionSupport == "ipv6" && qtype == dns.TypeA {
			continue
		}

		for _, u := range servers {
			if u == nil {
				continue
			}

			curFqdn := dns.Fqdn(host)
			harvested := false

			for hop := 0; hop < 4; hop++ {
				m := new(dns.Msg)
				m.SetQuestion(curFqdn, qtype)
				m.RecursionDesired = true

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
				}
				opt.SetUDPSize(4096)
				m.Extra = append(m.Extra, opt)

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				resp, _, err := u.Exchange(ctx, m, "bootstrap", "bootstrap", netip.Addr{})
				cancel()

				if err != nil || resp == nil {
					break
				}

				var nextCNAME string
				for _, rr := range resp.Answer {
					var s string
					switch rec := rr.(type) {
					case *dns.A:
						s = rec.A.String()
					case *dns.AAAA:
						s = rec.AAAA.String()
					case *dns.CNAME:
						if strings.EqualFold(rec.Hdr.Name, curFqdn) && rec.Target != "" {
							nextCNAME = dns.Fqdn(rec.Target)
						}
					}
					if s != "" {
						if addr, err := netip.ParseAddr(s); err == nil {
							if ipVersionSupport == "ipv4" && !addr.Is4() {
								continue
							}
							if ipVersionSupport == "ipv6" && !addr.Is6() {
								continue
							}
							harvested = true
							if _, dup := seen[s]; !dup {
								seen[s] = struct{}{}
								ips = append(ips, s)
							}
						}
					}
				}

				if harvested || nextCNAME == "" || strings.EqualFold(nextCNAME, curFqdn) {
					break
				}
				curFqdn = nextCNAME
			}

			if harvested {
				break
			}
		}
	}
	return ips
}

func equalRRs(a, b dns.RR) bool {
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
		return ok && strings.EqualFold(va.Target, vb.Target)
	default:
		return canonicalizeRR(a) == canonicalizeRR(b)
	}
}
