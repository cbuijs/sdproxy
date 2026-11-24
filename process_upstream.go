/*
File:    process_upstream.go
Version: 1.32.0
Last Updated: 18-Nov-2026 18:05 CET

Description:
  Upstream exchange stage for the sdproxy resolution pipeline — the cache-miss
  path. Owns upstream group resolution, QNAME label-bounds enforcement,
  SingleFlight coalescing, the outbound dial, the post-response policy checks
  and the final client write.

Changes:
  1.32.0 - [SECURITY/FIX] Skipped `applyRcodeOnlyWireTTL(finalResp)` when serving
           an emergency stale fallback (`upstreamUsed == "stale-fallback"`) so
           `CacheGetExpired` responses strictly retain their bounded 30-second
           (or `maxSigTTL`) RFC 8767 stale TTL instead of being raised to
           `min_ttl` or `rcode_min_ttl`.
  1.31.0 - [FEAT] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.36.0) on
           upstream RCODE-only responses (`len(Answer) == 0`) and broadened the
           `CacheSet` condition so non-`NXDOMAIN` RCODE-only answers are also
           submitted to `CacheSet` when `rcode_ttl` or `rcode_min_ttl` is set.
  1.30.0 - [SECURITY/FIX] Aligned `RRSIG` stripping in `serveFromUpstream` with
           `CacheSet` (`cache_rw.go`) and `serveFromCache` (`process_cachehit.go`
           1.36.0) so authority `RRSIG` records (`finalResp.Ns`) are stripped
           whenever `!qc.doBit`, while answer `RRSIG` records are only preserved
           when `qc.q.Qtype == dns.TypeRRSIG`.
  1.29.0 - [FIX] Passed `cacheHit = false` into `enforceForSaleResponseCheck` and
           `enforceParkedResponseCheck` after upstream resolution.
  1.28.0 - [FIX] Emitted Simple Logging Mode (`logSimple: true`) audit log lines
           in `enforceQnameLabelBounds` when `globalBlockAction == BlockActionLog`.
  1.27.0 - [FIX] Recorded `IncrPolicyBlock()` and `RecordBlockEvent()` and emitted
           Simple Logging Mode (`logSimple: true`) audit log lines when a
           `strategy: "secure"` consensus validation failure occurs in
           `block_action: "LOG"` mode (`isConsensusLog`).
  1.26.0 - [FEAT] Added `qc.enforceRFCComplianceResponseCheck(finalResp, false)`
           after upstream resolution.
  1.25.0 - [SECURITY/FIX] Supported `block_action: "LOG"` on `strategy: "secure"`
           consensus validation failures (`upstream_race.go` 2.64.0).
  1.24.0 - [SECURITY/FIX] Detected synthetic consensus blocks (`strings.HasPrefix(addr, "consensus(")`)
           in `serveFromUpstream`.
  1.23.0 - [PERF/FIX] Pre-sorted upstream answers before `CacheSet` inside the
           `sfGroup.Do` closure when `cfg.Cache.AnswerSort == "ip-sort"`.
*/

package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

func effectiveUpstreamGroup(routeName string) *UpstreamGroup {
	group, exists := routeUpstreams[routeName]
	if !exists || group == nil || len(group.Servers) == 0 {
		group = routeUpstreams["default"]
	}
	if group == nil || len(group.Servers) == 0 {
		return nil
	}
	return group
}

func (qc *queryCtx) resolveUpstreamGroup() bool {
	if qc.group == nil {
		qc.group = effectiveUpstreamGroup(qc.route.routeName)
	}
	if qc.group == nil {
		if logSimple {
			log.Printf("[DNS] [%s] %s -> %s %s | SERVFAIL | Policy: %s | Cache: MISS | FAILED: no upstreams configured",
				qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), qc.effectivePolicyLabel())
		} else {
			log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | NO UPSTREAMS CONFIGURED",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
				qc.route.routeName, qc.route.routeOriginType)
		}
		IncrReturnCode(dns.RcodeServerFailure, false)
		dns.HandleFailed(qc.w, qc.r)
		return false
	}
	return true
}

func (qc *queryCtx) enforceQnameLabelBounds() bool {
	if qc.group.IgnoreQnameLabels {
		return false
	}

	labels := countDomainLabels(qc.qNameTrimmed)
	if labels >= cfg.Server.QnameMinLabels && labels <= cfg.Server.QnameMaxLabels {
		return false
	}

	IncrPolicyBlock()

	reason := fmt.Sprintf("QNAME Label Bounds (%d labels)", labels)
	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		reason += fmt.Sprintf(" (Target: %s)", qc.qNameTrimmed)
	}
	RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)

	if globalBlockAction == BlockActionLog {
		if logQueries {
			if logSimple {
				log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY): %s",
					qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), reason)
			} else {
				statusMark := qc.annotateAlias("POLICY BLOCK (LOG ONLY)")
				log.Printf("[DNS] [%s] %s -> %s %s | %s (%s) | LOG ONLY",
					qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), statusMark, reason)
			}
		}
		return false
	}

	dropped := writePolicyAction(qc.w, qc.r, PolicyActionBlock)

	if cacheSynthFlag && !dropped && globalBlockAction != BlockActionDrop {
		synthMsg := buildSynthCacheMsg(qc.r, qc.q, PolicyActionBlock)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg)
	}

	if logQueries {
		var actionLogStr string
		if globalBlockAction == BlockActionDrop {
			actionLogStr = "DROP"
		} else {
			actionLogStr = getBlockActionLogStr(qc.q.Qtype)
		}

		if logSimple {
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), actionLogStr, "QNAME Label Bounds", false)
		} else {
			statusMark := "POLICY BLOCK"
			if dropped {
				statusMark = "POLICY DROP"
			}
			statusMark = qc.annotateAlias(statusMark)

			log.Printf("[DNS] [%s] %s -> %s %s | %s (Label Bounds) | %s",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), statusMark, actionLogStr)
		}
	}
	return true
}

func (qc *queryCtx) serveFromUpstream() {
	sfClientName := ""
	if qc.group.HasClientName {
		sfClientName = qc.clientName
	}

	sfKey := buildSFKey(qc.qNameTrimmed, qc.q.Qtype, qc.q.Qclass, qc.route.routeIdx,
		qc.cacheKey.DoBit, qc.r.CheckingDisabled, qc.bypassGlobal, qc.bypassPolicies, qc.route.bypassLocal, qc.r.RecursionDesired, sfClientName, qc.cacheKey.ECS)

	didUpstream := false

	v, sfErr, shared := sfGroup.Do(sfKey, func() (any, error) {
		didUpstream = true
		IncrUpstreamCall()

		ctx, cancel := newUpstreamCtx()
		defer cancel()

		msg, addr, err := qc.group.Exchange(ctx, qc.r, qc.clientID, qc.clientName, qc.clientAddr)
		if err != nil || msg == nil {
			if cfg.Cache.ServeStaleInfinite && !errors.Is(err, ErrSilentDrop) {
				fallbackMsg := new(dns.Msg)
				if CacheGetExpired(qc.cacheKey, qc.q.Name, fallbackMsg) {
					return sfResult{msg: fallbackMsg, addr: "stale-fallback"}, nil
				}
			}
			return sfResult{msg: msg, addr: addr}, err
		}

		isConsensusBlock := strings.HasPrefix(addr, "consensus(") || strings.HasPrefix(addr, "consensus-log(")
		if !isConsensusBlock {
			if cfg.Cache.AnswerSort == "ip-sort" {
				applyAnswerSort(msg, "ip-sort")
			}

			isRcodeOnly := len(msg.Answer) == 0 || msg.Rcode != dns.RcodeSuccess
			if !isRcodeOnly || cacheUpstreamNeg {
				CacheSet(qc.cacheKey, msg, qc.route.routeName)
			}
		}
		return sfResult{msg: msg, addr: addr}, nil
	})

	if shared && !didUpstream {
		coalescedTotal.Add(1)
	}

	if didUpstream {
		IncrUpstream(qc.route.routeName)
	}

	var finalResp *dns.Msg
	var upstreamUsed string
	if v != nil {
		if res, ok := v.(sfResult); ok {
			upstreamUsed = res.addr
			if res.msg != nil && sfErr == nil {
				finalResp = res.msg.Copy()
			}
		}
	}

	if finalResp == nil {
		if sfErr != nil && errors.Is(sfErr, ErrSilentDrop) {
			IncrPolicyBlock()
			RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Consensus Validation ("+qc.route.routeName+")")
			if logQueries {
				if logSimple {
					logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), "DROP", "Consensus ("+qc.route.routeName+")", false)
				} else {
					log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | CONSENSUS DROP | DROP",
						qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
						qc.route.routeName, qc.route.routeOriginType)
				}
			}
			return
		}

		if logSimple {
			log.Printf("[DNS] [%s] %s -> %s %s | SERVFAIL | Policy: %s | Cache: MISS | FAILED: %v",
				qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(),
				qc.effectivePolicyLabel(), sfErr)
		} else {
			upstreamLog := ""
			if upstreamUsed != "" {
				upstreamLog = " | UPSTREAM: " + cleanUpstreamHost(upstreamUsed)
			}
			log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s)%s | FAILED: %v",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
				qc.route.routeName, qc.route.routeOriginType, upstreamLog, sfErr)
		}
		IncrReturnCode(dns.RcodeServerFailure, false)
		dns.HandleFailed(qc.w, qc.r)
		return
	}

	isConsensusLog := false
	if strings.HasPrefix(upstreamUsed, "consensus-log(") {
		isConsensusLog = true
		upstreamUsed = strings.TrimSuffix(strings.TrimPrefix(upstreamUsed, "consensus-log("), ")")
		IncrPolicyBlock()
		RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Consensus Validation ("+qc.route.routeName+")")
		if logQueries {
			if logSimple {
				log.Printf("[DNS] [%s] %s -> %s %s | CONSENSUS BLOCK (LOG ONLY): Consensus (%s)",
					qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), qc.route.routeName)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | CONSENSUS BLOCK (LOG ONLY) | Allowing fallback response",
					qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
					qc.route.routeName, qc.route.routeOriginType)
			}
		}
	}

	isConsensusBlock := strings.HasPrefix(upstreamUsed, "consensus(")
	if isConsensusBlock {
		IncrPolicyBlock()
		RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Consensus Validation ("+qc.route.routeName+")")
		finalResp.Id = qc.originalID
		recordBlockMsgStats(finalResp, qc.originalQNameTrimmed)
		enforceUDPDefenses(qc.r, finalResp, qc.protocol, qc.clientAddr, qc.group)
		qc.w.WriteMsg(finalResp)
		if logQueries {
			rcStr := getBlockActionLogStr(qc.q.Qtype)
			if logSimple {
				logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), rcStr, "Consensus ("+qc.route.routeName+")", false)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | CONSENSUS BLOCK | %s",
					qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
					qc.route.routeName, qc.route.routeOriginType, rcStr)
			}
		}
		return
	}

	if !qc.doBit {
		if qc.q.Qtype != dns.TypeRRSIG {
			finalResp.Answer = stripRRSIGRecords(finalResp.Answer)
		}
		finalResp.Ns = stripRRSIGRecords(finalResp.Ns)
		if !qc.r.AuthenticatedData {
			finalResp.AuthenticatedData = false
		}
	}

	syncQuestionCasing(finalResp, qc.q.Name)

	// ── Passive For-Sale, Parked & RFC Compliance Response Inspection ─────
	if qc.enforceForSaleResponseCheck(finalResp, false) {
		return
	}
	if qc.enforceParkedResponseCheck(finalResp, false) {
		return
	}
	if qc.enforceRFCComplianceResponseCheck(finalResp, false) {
		return
	}

	// ── Answer sorting ────────────────────────────────────────────────────
	if cfg.Cache.AnswerSort != "none" && (cfg.Cache.AnswerSort != "ip-sort" || isConsensusLog) {
		var lAddr netip.Addr
		if cfg.Cache.AnswerSort == "proximity" {
			if ip := localAddrIP(qc.w); ip != nil {
				if a, ok := netip.AddrFromSlice(ip); ok {
					lAddr = a.Unmap()
				}
			}
		}
		applyAnswerSort(finalResp, cfg.Cache.AnswerSort, lAddr)
	}

	// ── Post-response policy ──────────────────────────────────────────────
	if checkTargetNames(qc.w, qc.r, finalResp, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.protoEndpoint, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, false) {
		return
	}

	finalResp = transformResponse(finalResp, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, finalResp, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.protoEndpoint, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, qc.originalQNameTrimmed, false) {
		return
	}

	if filterRebinding(qc.w, qc.r, finalResp, qc.clientIP, qc.clientID,
		qc.protocol, qc.protoEndpoint, qc.originalQName, qc.originalQNameTrimmed, false) {
		return
	}

	if upstreamUsed != "stale-fallback" {
		applyRcodeOnlyWireTTL(finalResp)
	}

	isNullIP := false
	for _, rr := range finalResp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if r.A.IsUnspecified() {
				isNullIP = true
				break
			}
		case *dns.AAAA:
			if r.AAAA.IsUnspecified() {
				isNullIP = true
				break
			}
		}
		if isNullIP {
			break
		}
	}

	if isNullIP {
		IncrPolicyBlock()
		RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Upstream NULL-IP ("+qc.route.routeName+")")
	}

	upstreamSize, clientAdvertised := enforceUDPDefenses(qc.r, finalResp, qc.protocol, qc.clientAddr, qc.group)

	// ── Final reply ───────────────────────────────────────────────────────
	if qc.parentalForcedTTL > 0 {
		CapResponseTTL(finalResp, qc.parentalForcedTTL)
	}
	finalResp.Id = qc.originalID

	IncrReturnCode(finalResp.Rcode, isNullIP)
	if finalResp.Rcode == dns.RcodeNameError {
		IncrNXDomain(qc.originalQNameTrimmed)
	}
	if upstreamUsed != "" {
		IncrUpstreamHost(cleanUpstreamHost(upstreamUsed))
	}

	qc.w.WriteMsg(finalResp)

	if logQueries {
		rcodeStr := RcodeStr(finalResp.Rcode)
		if isNullIP {
			rcodeStr += " (NULL-IP)"
		}

		if logSimple {
			if qc.parentalReason == "ACTIVATING_UNTRIGGER" {
				qc.scheduleUntriggerExpiry()
			}
			isHit := upstreamUsed == "stale-fallback"
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), rcodeStr, qc.effectivePolicyLabel(), isHit)
			return
		}

		var status string
		switch {
		case shared && !didUpstream:
			status = "COALESCED | " + rcodeStr
		case isNullIP:
			status = rcodeStr
		case finalResp.Truncated:
			status = fmt.Sprintf("TRUNCATED (TC=1, Upstream:%dB, Client:%dB) | %s",
				upstreamSize, clientAdvertised, rcodeStr)
		default:
			status = "MISS | " + rcodeStr
			if upstreamUsed != "" {
				status = "OK | " + rcodeStr
			}
		}

		if upstreamUsed == "stale-fallback" {
			status = "INFINITE STALE FALLBACK | " + status
		}

		status = qc.annotateParental(status)
		status = qc.annotateAlias(status)
		status = qc.annotateECS(status)

		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | UPSTREAM: %s (%s) | %s",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType,
			cleanUpstreamHost(upstreamUsed), qc.route.routeName, status)
	}
}
