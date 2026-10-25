/*
File:    process_upstream.go
Version: 1.12.0
Last Updated: 25-Oct-2026 15:40 CET

Description:
  Upstream exchange stage for the sdproxy resolution pipeline — the cache-miss
  path. Owns upstream group resolution, QNAME label-bounds enforcement,
  SingleFlight coalescing, the outbound dial, the post-response policy checks
  and the final client write.

Changes:
  1.12.0 - [SECURITY/FIX] Passed `qc.r` into `buildSynthCacheMsg` in
           `enforceQnameLabelBounds` so cached synthetic label-bounds blocks
           preserve the client's `RecursionDesired` flag.
  1.11.0 - [SECURITY/FIX] Propagated `qc.bypassPolicies` and `qc.route.bypassLocal`
           into `buildSFKey` so SingleFlight coalescing respects policy and
           local-resolution boundaries.
  1.10.0 - [FEAT] Passed `qc.ednsMAC` to `checkTargetNames` and `filterResponseIPs`
           so post-upstream policy checks preserve EDNS0 Option 65001 (`mac:`)
           parental state resolution.
  1.9.0  - [FIX] Passed `qc.ecsAddr` to `checkTargetNames` and `filterResponseIPs`
           so post-upstream policy checks preserve `ecs:` parental state resolution.
  1.8.1  - [BUG/FIX] Removed stray `true_dummy()` call in `serveFromUpstream` return path.
  1.8.0  - [SECURITY/FIX] Synchronized Question and Answer owner-name casing via
           `syncQuestionCasing(finalResp, qc.q.Name)` after SingleFlight coalescing.
  1.7.0  - [SECURITY/FIX] Restored `finalResp.Question[0].Name = qc.q.Name` after
           SingleFlight coalescing and passed `qc.q.Name` to `CacheGetExpired`.
  1.6.0  - [FIX] Passed `qc.localPort` to `checkTargetNames` and `filterResponseIPs`
           so post-upstream policy checks preserve port-based parental state resolution.
*/

package main

import (
	"errors"
	"fmt"
	"log"

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
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | NO UPSTREAMS CONFIGURED",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType)
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

	dropped := writePolicyAction(qc.w, qc.r, PolicyActionBlock)

	if cacheSynthFlag && !dropped && globalBlockAction != BlockActionDrop {
		synthMsg := buildSynthCacheMsg(qc.r, qc.q, PolicyActionBlock)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg)
	}

	if logQueries {
		var actionLogStr string
		switch globalBlockAction {
		case BlockActionLog:
			actionLogStr = "LOG ONLY"
		case BlockActionDrop:
			actionLogStr = "DROP"
		default:
			actionLogStr = getBlockActionLogStr(qc.q.Qtype)
		}

		statusMark := "POLICY BLOCK"
		if dropped {
			statusMark = "POLICY DROP"
		}
		statusMark = qc.annotateAlias(statusMark)

		log.Printf("[DNS] [%s] %s -> %s %s | %s (Label Bounds) | %s",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), statusMark, actionLogStr)
	}
	return true
}

func (qc *queryCtx) serveFromUpstream() {
	sfClientName := ""
	if qc.group.HasClientName {
		sfClientName = qc.clientName
	}

	sfKey := buildSFKey(qc.qNameTrimmed, qc.q.Qtype, qc.q.Qclass, qc.route.routeIdx,
		qc.doBit, qc.r.CheckingDisabled, qc.bypassGlobal, qc.bypassPolicies, qc.route.bypassLocal, qc.r.RecursionDesired, sfClientName, qc.cacheKey.ECS)

	didUpstream := false

	v, sfErr, shared := sfGroup.Do(sfKey, func() (any, error) {
		didUpstream = true
		IncrUpstreamCall()

		ctx, cancel := newUpstreamCtx()
		defer cancel()

		msg, addr, err := qc.group.Exchange(ctx, qc.r, qc.clientID, qc.clientName, qc.clientAddr)
		if err != nil || msg == nil {
			if cfg.Cache.ServeStaleInfinite {
				fallbackMsg := new(dns.Msg)
				if CacheGetExpired(qc.cacheKey, qc.q.Name, fallbackMsg) {
					return sfResult{msg: fallbackMsg, addr: "stale-fallback"}, nil
				}
			}
			return sfResult{msg: msg, addr: addr}, err
		}

		isNeg := msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
		if !isNeg || cacheUpstreamNeg {
			CacheSet(qc.cacheKey, msg, qc.route.routeName)
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
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | CONSENSUS DROP | DROP",
					qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
					qc.route.routeName, qc.route.routeOriginType)
			}
			return
		}

		upstreamLog := ""
		if upstreamUsed != "" {
			upstreamLog = " | UPSTREAM: " + cleanUpstreamHost(upstreamUsed)
		}
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s)%s | FAILED: %v",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType, upstreamLog, sfErr)
		dns.HandleFailed(qc.w, qc.r)
		return
	}

	syncQuestionCasing(finalResp, qc.q.Name)

	// ── Answer sorting ────────────────────────────────────────────────────
	if cfg.Cache.AnswerSort != "none" {
		if applyAnswerSort(finalResp, cfg.Cache.AnswerSort) {
			if cfg.Cache.AnswerSort != "random" && !cacheRotateAnswers && (!shared || didUpstream) {
				CacheUpdateOrder(qc.cacheKey, finalResp)
			}
		}
	}

	// ── Post-response policy ──────────────────────────────────────────────
	if checkTargetNames(qc.w, qc.r, finalResp, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName) {
		return
	}

	finalResp = transformResponse(finalResp, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, finalResp, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, qc.originalQNameTrimmed) {
		return
	}

	if filterRebinding(qc.w, qc.r, finalResp, qc.clientIP, qc.clientID,
		qc.protocol, qc.originalQName, qc.originalQNameTrimmed) {
		return
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

	upstreamSize, clientAdvertised := enforceUDPDefenses(qc.r, finalResp, qc.protocol)

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
