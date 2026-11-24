/*
File:    upstream_race.go
Version: 2.70.0
Last Updated: 24-Nov-2026 14:30 CET

Description:
  Advanced routing and parallel execution strategies for sdproxy upstream groups.
  Implements `stagger`, `round-robin`, `random`, `fastest`, and `secure` strategies.

Changes:
  2.70.0 - [CRITICAL/CONCURRENCY] Removed the premature `majority` early-exit in
           `exchangeSecure` (`Mode == "loose"`) so all healthy upstreams (`expectedHealthy`)
           participate in consensus verification, `ordered` selection, and
           `consolidate` merging, and added a throttled (10s) detached recovery
           probe (`maybeProbeUnhealthy`) so unhealthy upstreams never starve
           permanently behind `raceCtx` cancellation.
         - [SECURITY/FIX] Preserved signed `RRSIG`/`AD` responses in `exchangeSecure`
           by bypassing `consolidate` RR-rewriting when `DO=1` or `RequireDNSSECAD`
           is active.
  2.69.0 - [SECURITY/FIX] Collapsed terminal `A`/`AAAA` records onto
           `req.Question[0].Name` with `minAliasTTL` clamping in `consolidate` mode.
  2.68.0 - [SECURITY/FIX] Filtered non-matching record types in `consolidate`.
  2.67.0 - [REFACTOR/CLEANUP] Switched `buildMsgBailiwickChain` to `walkBailiwickChain`.
  2.66.0 - [PERF] Zero-reflection `canonicalizeRR` and `extractAnswerFingerprint`.
  2.65.0 - [SECURITY/FIX] Rejected NULL-IP responses in `pickFallback`.
  2.64.0 - [SECURITY/FIX] Honored `globalBlockAction == BlockActionLog` in
           `synthesizeConsensusBlock` and `exchangeSecure`.
  2.63.0 - [PERF/FIX] Cancelled `raceCtx` immediately upon consensus failure.
  2.62.0 - [FIX] Normalized `*dns.AAAA` addresses with `.Unmap()`.
  2.61.1 - [CLEANUP] Removed dead `extraOrErr` helper.
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

const recoveryProbeCooldownNano = int64(10 * time.Second)

func (g *UpstreamGroup) maybeProbeUnhealthy(req *dns.Msg, clientName string, clientAddr netip.Addr) {
	if req == nil || len(req.Question) == 0 {
		return
	}
	nowNano := time.Now().UnixNano()
	for _, up := range g.Servers {
		if up == nil || up.isHealthy() {
			continue
		}
		if !up.claimRecoveryProbe(nowNano, recoveryProbeCooldownNano) {
			continue
		}
		probeReq := req.Copy()
		go func(u *Upstream) {
			pCtx, pCancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), 3*time.Second)
			defer pCancel()
			start := time.Now()
			resp, _, err := u.Exchange(pCtx, probeReq, "health-probe", clientName, clientAddr)
			if err == nil && resp != nil {
				u.recordSuccess()
				g.updateRTT(u, time.Since(start).Nanoseconds())
			} else if err != nil && !errors.Is(err, context.Canceled) {
				u.recordFailure()
				g.penalizeRTT(u)
			}
		}(up)
	}
}

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
		perTryTimeout := 3500 * time.Millisecond
		if upstreamTimeout > 0 && upstreamTimeout < perTryTimeout {
			perTryTimeout = upstreamTimeout
		}

		for i, up := range ordered {
			if raceCtx.Err() != nil {
				break
			}
			tryCtx := raceCtx
			var tryCancel context.CancelFunc
			if i < len(ordered)-1 {
				tryCtx, tryCancel = context.WithTimeout(raceCtx, perTryTimeout)
			}
			start := time.Now()
			resp, addr, err := up.Exchange(tryCtx, req, clientID, clientName, clientAddr)
			if tryCancel != nil {
				tryCancel()
			}
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
	consumed := 0

	for i, up := range ordered {
		if i > 0 {
			if ordered[i-1].isHealthy() {
				t := time.NewTimer(upstreamStagger)
				select {
				case r := <-ch:
					t.Stop()
					consumed++
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
				case <-raceCtx.Done():
					t.Stop()
				}
			}
		}
		if raceCtx.Err() != nil {
			break
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

	for consumed < launched {
		r := <-ch
		consumed++
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
	n := len(g.Servers)
	idx := int(g.rrCount.Add(1) % uint64(n))
	var ordBuf [8]*Upstream
	var ordered []*Upstream
	if n <= len(ordBuf) {
		ordered = ordBuf[:n]
	} else {
		ordered = make([]*Upstream, n)
	}
	for i := 0; i < n; i++ {
		ordered[i] = g.Servers[(idx+i)%n]
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

func (g *UpstreamGroup) exchangeRandom(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	n := len(g.Servers)
	idx := rand.IntN(n)
	var ordBuf [8]*Upstream
	var ordered []*Upstream
	if n <= len(ordBuf) {
		ordered = ordBuf[:n]
	} else {
		ordered = make([]*Upstream, n)
	}
	for i := 0; i < n; i++ {
		ordered[i] = g.Servers[(idx+i)%n]
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

	var ranksBuf [8]ranked
	var ranks []ranked
	if n <= len(ranksBuf) {
		ranks = ranksBuf[:n]
	} else {
		ranks = make([]ranked, n)
	}
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
		qType := qtypeName(req.Question[0].Qtype)
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

	var ordBuf [8]*Upstream
	var ordered []*Upstream
	if n <= len(ordBuf) {
		ordered = ordBuf[:n]
	} else {
		ordered = make([]*Upstream, n)
	}
	for i, r := range ranks {
		ordered[i] = r.up
	}
	return g.executeRace(ctx, req, clientID, clientName, clientAddr, ordered)
}

func synthesizeConsensusBlock(req *dns.Msg, consensusAddr string, fallbackMsg *dns.Msg, fallbackAddr string) (*dns.Msg, string, error) {
	if globalBlockAction == BlockActionDrop {
		return nil, consensusAddr, ErrSilentDrop
	}
	if globalBlockAction == BlockActionLog {
		if fallbackMsg != nil {
			return fallbackMsg, "consensus-log(" + fallbackAddr + ")", nil
		}
		return nil, consensusAddr, errors.New("consensus validation failed (no valid upstream responses)")
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
	validNames, _, exceeded := walkBailiwickChain(msg.Answer, msg.Question[0].Name, 16, buf)
	if exceeded {
		return nil
	}

	for _, rr := range msg.Answer {
		if !isValidBailiwickName(validNames, strings.ToLower(rr.Header().Name)) {
			return nil
		}
	}
	return validNames
}

func (g *UpstreamGroup) exchangeSecure(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	maxSecure := g.MaxSecureUpstreams
	if maxSecure <= 0 {
		maxSecure = 5
	}

	if g.Mode == "loose" {
		g.maybeProbeUnhealthy(req, clientName, clientAddr)
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
	var healthyFlag [8]bool
	var healthyMap map[*Upstream]bool
	if n <= len(healthyFlag) {
		for idx, up := range servers {
			if up.isHealthy() {
				healthyFlag[idx] = true
				expectedHealthy++
			}
		}
	} else {
		healthyMap = make(map[*Upstream]bool, n)
		for _, up := range servers {
			if up.isHealthy() {
				healthyMap[up] = true
				expectedHealthy++
			}
		}
	}
	if expectedHealthy == 0 {
		expectedHealthy = 1
	}

	type raceResult struct {
		msg        *dns.Msg
		addr       string
		up         *Upstream
		err        error
		rtt        int64
		wasHealthy bool
	}

	ch := make(chan raceResult, n)
	for idx, up := range servers {
		wasH := false
		if healthyMap != nil {
			wasH = healthyMap[up]
		} else {
			wasH = healthyFlag[idx]
		}
		go func(u *Upstream, h bool) {
			start := time.Now()
			msg, addr, err := u.Exchange(raceCtx, req, clientID, clientName, clientAddr)
			ch <- raceResult{msg, addr, u, err, time.Since(start).Nanoseconds(), h}
		}(up, wasH)
	}

	var resultsBuf [8]raceResult
	var evalBuf [8]raceResult
	results := resultsBuf[:0]
	evalResults := evalBuf[:0]
	var baseRcode int
	var baseHasAnswers bool
	var baseFingerprint string
	baseSet := false

	consensusAddr := "consensus(" + g.Name + ")"

	msgHasNullIP := func(m *dns.Msg) bool {
		if m == nil {
			return false
		}
		for _, rr := range m.Answer {
			switch rec := rr.(type) {
			case *dns.A:
				if rec.A.IsUnspecified() {
					return true
				}
			case *dns.AAAA:
				if rec.AAAA.IsUnspecified() {
					return true
				}
			}
		}
		return false
	}

	pickFallback := func() (*dns.Msg, string) {
		if len(evalResults) > 0 {
			return evalResults[0].msg, evalResults[0].addr
		}
		for _, r := range results {
			if r.err == nil && r.msg != nil && !r.msg.Truncated && (r.msg.Rcode == dns.RcodeSuccess || r.msg.Rcode == dns.RcodeNameError) {
				if msgHasNullIP(r.msg) {
					continue
				}
				var chainBuf [64]string
				if len(r.msg.Answer) > 0 && buildMsgBailiwickChain(r.msg, &chainBuf) == nil {
					continue
				}
				return r.msg, r.addr
			}
		}
		return nil, ""
	}

	evaluateResult := func(r raceResult) bool {
		hasNullIP := false
		if r.msg != nil {
			var chainBuf [64]string
			if len(r.msg.Answer) > 0 && buildMsgBailiwickChain(r.msg, &chainBuf) == nil {
				if logSystem {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: out-of-bailiwick record from %s", clientID, req.Question[0].Name, r.addr)
				}
				return false
			}
			hasNullIP = msgHasNullIP(r.msg)
		}

		if g.Mode == "strict" {
			if r.err != nil || r.msg == nil {
				if logSystem {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode requires 100%% participation, upstream %s failed (%v)",
						clientID, req.Question[0].Name, r.addr, r.err)
				}
				return false
			}
			if r.msg.Truncated {
				if logSystem {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode rejected truncated (TC=1) response from %s",
						clientID, req.Question[0].Name, r.addr)
				}
				return false
			}
			if r.msg.Rcode != dns.RcodeSuccess && r.msg.Rcode != dns.RcodeNameError {
				if logSystem {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode rejected RCODE %s from %s",
						clientID, req.Question[0].Name, RcodeStr(r.msg.Rcode), r.addr)
				}
				return false
			}
			if hasNullIP {
				if logSystem {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: NULL-IP detected from %s", clientID, req.Question[0].Name, r.addr)
				}
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
					if logSystem {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: RCODE mismatch (base: %d, peer: %d) from %s", clientID, req.Question[0].Name, baseRcode, r.msg.Rcode, r.addr)
					}
					return false
				}
				if (len(r.msg.Answer) > 0) != baseHasAnswers {
					if logSystem {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: mixed empty/non-empty responses from %s", clientID, req.Question[0].Name, r.addr)
					}
					return false
				}
				if fp != baseFingerprint {
					if logSystem {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode answer mismatch from %s", clientID, req.Question[0].Name, r.addr)
					}
					return false
				}
			}
			evalResults = append(evalResults, r)
			return true
		}

		if r.err == nil && r.msg != nil && !r.msg.Truncated && (r.msg.Rcode == dns.RcodeSuccess || r.msg.Rcode == dns.RcodeNameError) {
			if hasNullIP {
				if logSystem {
					log.Printf("[SECURITY] [%s] Consensus validation failed for %s: NULL-IP detected from %s", clientID, req.Question[0].Name, r.addr)
				}
				return false
			}
			if !baseSet {
				baseRcode = r.msg.Rcode
				baseHasAnswers = len(r.msg.Answer) > 0
				baseSet = true
			} else {
				if r.msg.Rcode != baseRcode {
					if logSystem {
						log.Printf("[SECURITY] [%s] Consensus validation failed for %s: RCODE mismatch (base: %d, peer: %d) from %s", clientID, req.Question[0].Name, baseRcode, r.msg.Rcode, r.addr)
					}
					return false
				}
				if baseRcode == dns.RcodeSuccess {
					if (len(r.msg.Answer) > 0) != baseHasAnswers {
						if logSystem {
							log.Printf("[SECURITY] [%s] Consensus validation failed for %s: mixed empty/non-empty NOERROR responses from %s", clientID, req.Question[0].Name, r.addr)
						}
						return false
					}
				}
			}
			evalResults = append(evalResults, r)
		}
		return true
	}

	healthyReceived := 0
	for i := 0; i < n; i++ {
		r := <-ch
		results = append(results, r)

		if r.wasHealthy {
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
			cancel()
			fbMsg, fbAddr := pickFallback()
			return synthesizeConsensusBlock(req, consensusAddr, fbMsg, fbAddr)
		}

		if g.Mode == "loose" && healthyReceived >= expectedHealthy && len(evalResults) > 0 {
			if i < n-1 {
				grace := time.NewTimer(2 * time.Millisecond)
			drainLoop:
				for i < n-1 {
					select {
					case extra := <-ch:
						results = append(results, extra)
						if extra.wasHealthy {
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
							cancel()
							fbMsg, fbAddr := pickFallback()
							return synthesizeConsensusBlock(req, consensusAddr, fbMsg, fbAddr)
						}
						i++
					case <-grace.C:
						break drainLoop
					}
				}
				grace.Stop()
			}
			cancel()
			break
		}
	}

	if len(evalResults) == 0 {
		if logSystem {
			log.Printf("[SECURITY] [%s] Consensus validation failed for %s: no valid responses eligible for consensus (mode: %s)", clientID, req.Question[0].Name, g.Mode)
		}
		fbMsg, fbAddr := pickFallback()
		return synthesizeConsensusBlock(req, consensusAddr, fbMsg, fbAddr)
	}

	if g.Mode == "strict" && len(evalResults) != n {
		if logSystem {
			log.Printf("[SECURITY] [%s] Consensus validation failed for %s: strict mode requires all %d upstreams to agree, only %d succeeded",
				clientID, req.Question[0].Name, n, len(evalResults))
		}
		fbMsg, fbAddr := pickFallback()
		return synthesizeConsensusBlock(req, consensusAddr, fbMsg, fbAddr)
	}

	var finalMsg *dns.Msg
	var finalAddr string
	var winningUpstream *Upstream

	reqDO := g.RequireDNSSECAD
	if !reqDO {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			reqDO = true
		}
	}

	qtype := req.Question[0].Qtype
	if g.Preference == "consolidate" && !reqDO && len(evalResults) > 1 && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		baseMsg := evalResults[0].msg.Copy()
		qName := req.Question[0].Name
		if len(baseMsg.Question) > 0 {
			qName = baseMsg.Question[0].Name
		}

		var uniqueTerminals []dns.RR
		for _, r := range evalResults {
			var chainStack [64]string
			chainNames, minAliasTTL, exceeded := walkBailiwickChain(r.msg.Answer, qName, 16, &chainStack)
			if exceeded {
				continue
			}
			for _, rr := range r.msg.Answer {
				if rr.Header().Rrtype != qtype {
					continue
				}
				if !isValidBailiwickName(chainNames, strings.ToLower(rr.Header().Name)) {
					continue
				}
				cp := dns.Copy(rr)
				cp.Header().Name = qName
				if minAliasTTL != ^uint32(0) && minAliasTTL > 0 && cp.Header().Ttl > minAliasTTL {
					cp.Header().Ttl = minAliasTTL
				}
				duplicate := false
				for _, existing := range uniqueTerminals {
					if equalRRs(cp, existing) {
						if cp.Header().Ttl < existing.Header().Ttl {
							existing.Header().Ttl = cp.Header().Ttl
						}
						duplicate = true
						break
					}
				}
				if !duplicate {
					uniqueTerminals = append(uniqueTerminals, cp)
				}
			}
		}

		if len(uniqueTerminals) > 0 {
			baseMsg.AuthenticatedData = false
			baseMsg.Answer = uniqueTerminals
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
		qType := qtypeName(req.Question[0].Qtype)
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

func appendU16(sb *strings.Builder, v uint16) {
	var numBuf [8]byte
	sb.Write(strconv.AppendUint(numBuf[:0], uint64(v), 10))
}

func canonicalizeRR(rr dns.RR) string {
	if rr == nil {
		return ""
	}
	hdr := rr.Header()
	owner := strings.ToLower(dns.Fqdn(hdr.Name))

	sb := clientIDPool.Get().(*strings.Builder)
	sb.Reset()
	defer clientIDPool.Put(sb)

	sb.WriteString(owner)
	sb.WriteByte(':')
	appendU16(sb, hdr.Class)
	sb.WriteByte(':')
	appendU16(sb, hdr.Rrtype)
	sb.WriteByte(':')

	switch r := rr.(type) {
	case *dns.A:
		if addr, ok := netip.AddrFromSlice(r.A); ok {
			sb.WriteString(addr.Unmap().String())
		} else {
			sb.WriteString(r.A.String())
		}
	case *dns.AAAA:
		if addr, ok := netip.AddrFromSlice(r.AAAA); ok {
			sb.WriteString(addr.Unmap().String())
		} else {
			sb.WriteString(r.AAAA.String())
		}
	case *dns.CNAME:
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Target)))
	case *dns.NS:
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Ns)))
	case *dns.PTR:
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Ptr)))
	case *dns.DNAME:
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Target)))
	case *dns.MX:
		appendU16(sb, r.Preference)
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Mx)))
	case *dns.SRV:
		appendU16(sb, r.Priority)
		sb.WriteByte(':')
		appendU16(sb, r.Weight)
		sb.WriteByte(':')
		appendU16(sb, r.Port)
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Target)))
	case *dns.SOA:
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Ns)))
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Mbox)))
	case *dns.TXT:
		for i, s := range r.Txt {
			if i > 0 {
				sb.WriteByte(0)
			}
			sb.WriteString(s)
		}
	case *dns.CAA:
		appendU16(sb, uint16(r.Flag))
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(r.Tag))
		sb.WriteByte(':')
		sb.WriteString(r.Value)
	case *dns.DNSKEY:
		appendU16(sb, r.Flags)
		sb.WriteByte(':')
		appendU16(sb, uint16(r.Protocol))
		sb.WriteByte(':')
		appendU16(sb, uint16(r.Algorithm))
		sb.WriteByte(':')
		sb.WriteString(r.PublicKey)
	case *dns.DS:
		appendU16(sb, r.KeyTag)
		sb.WriteByte(':')
		appendU16(sb, uint16(r.Algorithm))
		sb.WriteByte(':')
		appendU16(sb, uint16(r.DigestType))
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(r.Digest))
	case *dns.TLSA:
		appendU16(sb, uint16(r.Usage))
		sb.WriteByte(':')
		appendU16(sb, uint16(r.Selector))
		sb.WriteByte(':')
		appendU16(sb, uint16(r.MatchingType))
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(r.Certificate))
	case *dns.SSHFP:
		appendU16(sb, uint16(r.Algorithm))
		sb.WriteByte(':')
		appendU16(sb, uint16(r.Type))
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(r.FingerPrint))
	case *dns.NAPTR:
		appendU16(sb, r.Order)
		sb.WriteByte(':')
		appendU16(sb, r.Preference)
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(r.Flags))
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(r.Service))
		sb.WriteByte(':')
		sb.WriteString(r.Regexp)
		sb.WriteByte(':')
		sb.WriteString(strings.ToLower(dns.Fqdn(r.Replacement)))
	case *dns.SVCB:
		appendSVCBBody(sb, r.Priority, r.Target, r.Value)
	case *dns.HTTPS:
		appendSVCBBody(sb, r.Priority, r.Target, r.Value)
	default:
		cp := dns.Copy(rr)
		cp.Header().Name = owner
		cp.Header().Ttl = 0
		var buf [4096]byte
		if off, err := dns.PackRR(cp, buf[:], 0, nil, false); err == nil && off > 0 {
			sb.WriteString(hex.EncodeToString(buf[:off]))
			return sb.String()
		}
		full := cp.String()
		hdrStr := cp.Header().String()
		if len(full) >= len(hdrStr) {
			sb.WriteString(strings.TrimSpace(full[len(hdrStr):]))
		} else {
			sb.WriteString(full)
		}
	}
	return sb.String()
}

func appendSVCBBody(sb *strings.Builder, prio uint16, target string, values []dns.SVCBKeyValue) {
	var pBuf [16]string
	params := pBuf[:0]
	for _, kv := range values {
		params = append(params, kv.Key().String()+"="+kv.String())
	}
	sort.Strings(params)
	appendU16(sb, prio)
	sb.WriteByte(':')
	sb.WriteString(strings.ToLower(dns.Fqdn(target)))
	sb.WriteByte(':')
	for i, p := range params {
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString(p)
	}
}

func extractAnswerFingerprint(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}

	var itemsBuf [16]string
	items := itemsBuf[:0]
	hasRRSIG := false

	for _, rr := range msg.Answer {
		rt := rr.Header().Rrtype
		if rt == dns.TypeOPT {
			continue
		}
		if rt == dns.TypeRRSIG {
			hasRRSIG = true
			if sig, ok := rr.(*dns.RRSIG); ok {
				var numBuf [8]byte
				s := "SIG:" + strings.ToLower(dns.Fqdn(sig.Hdr.Name)) + ":" +
					string(strconv.AppendUint(numBuf[:0], uint64(sig.TypeCovered), 10)) + ":" +
					string(strconv.AppendUint(numBuf[:0], uint64(sig.Algorithm), 10))
				items = append(items, s)
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

	sb := clientIDPool.Get().(*strings.Builder)
	sb.Reset()
	defer clientIDPool.Put(sb)

	sb.WriteString(secPrefix)
	appendU16(sb, uint16(msg.Rcode))
	sb.WriteByte('|')
	for i, it := range items {
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString(it)
	}
	return sb.String()
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

				ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), 3*time.Second)
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
							addr = addr.Unmap()
							if ipVersionSupport == "ipv4" && !addr.Is4() {
								continue
							}
							if ipVersionSupport == "ipv6" && !addr.Is6() {
								continue
							}
							canon := addr.String()
							harvested = true
							if _, dup := seen[canon]; !dup {
								seen[canon] = struct{}{}
								ips = append(ips, canon)
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
