/*
File:    process_cachehit.go
Version: 1.37.0 (Split)
Last Updated: 18-Nov-2026 16:17 CET

Description:
  Cache-hit serving stage for the sdproxy resolution pipeline.

  Owns everything between "the cache had this answer" and "the client has it":
  cache-key derivation, the lookup itself, per-client answer ordering, the
  post-cache policy re-checks, and the response write.

Changes:
  1.37.0 - [SECURITY/FIX] Extended `isCachedSynthBlock` so any cached synthetic
           `NOERROR` (`len(resp.Answer) == 0`) item (`routeName == ""`) that is
           not a local-identity `NODATA` response is classified as a synthetic
           policy block, covering `rtype_policy` or `domain_policy` rules
           configured with `NOERROR` even when `globalBlockAction` is not
           `BlockActionRcode`.
  1.36.0 - [SECURITY/FIX] Aligned `RRSIG` stripping in `serveFromCache` with
           `CacheSet` (`cache_rw.go`) so authority `RRSIG` records (`poolMsg.Ns`)
           are stripped whenever `!qc.doBit`, while answer `RRSIG` records are
           only preserved when `qc.q.Qtype == dns.TypeRRSIG`.
  1.35.0 - [SECURITY/FIX] Added `isLocalIdentityPTR` helper in `isCachedSynthBlock`
           so cached local-identity `PTR` responses (`cache_local_identity: true`)
           are never misclassified if `block_action` is configured to return a
           non-`NOERROR` RCODE, and checked `cfg.Server.FilterAAAA && qc.q.Qtype == dns.TypeAAAA`
           ahead of `globalBlockAction == BlockActionRcode` in `isCachedSynthBlock`.
  1.34.0 - [SECURITY/FIX] Excluded cached `Filter AAAA` synthetic NODATA
           responses from `checkCachedIDNViolation` inside `isCachedSynthBlock`.
  1.33.0 - [SECURITY/FIX] Added `isLocalIdentityNODATA` helper in `isCachedSynthBlock`
           so cached local-identity `NODATA` responses (`cache_local_identity: true`)
           are never misclassified as synthetic `Filter AAAA` or `NODATA` policy
           blocks.
  1.32.0 - [SECURITY/FIX] Excluded cached local-identity `NODATA` responses
           (`cache_local_identity: true`) for non-A/AAAA query types in
           `isCachedSynthBlock`.
  1.31.0 - [SECURITY/FIX] Excluded cached local-identity `NULL-IP` responses
           (`cache_local_identity: true`) in `serveFromCache` from triggering
           `checkCachedIDNViolation`.
  1.30.0 - [SECURITY/FIX] Extended `isCachedSynthBlock` so cached synthetic
           `NULL-IP` responses (`routeName == ""` with `0.0.0.0` / `::`) also
           check `AnalyzeIDNHomograph`.
  1.29.0 - [SECURITY/FIX] Updated `isCachedSynthBlock` to query the live cache
           item's `routeName` (`isCachedSyntheticItem(qc.cacheKey)`).
  1.28.0 - [SECURITY/FIX] Added `isCachedSynthBlock` to accurately distinguish
           cached synthetic policy blocks (`cache_synthetic: true`) from
           authoritative upstream `NXDOMAIN` responses and from `block_action: "IP"`
           sinkhole responses.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/miekg/dns"
)

func (qc *queryCtx) deriveCacheKey() {
	qc.group = effectiveUpstreamGroup(qc.route.routeName)

	clientNameForCache := ""
	if qc.group != nil && qc.group.HasClientName {
		clientNameForCache = qc.clientName
	}

	ecsForCache := ""
	var clientSentECS bool
	var clientECSStr string
	if qc.ecsAddr.IsValid() {
		clientSentECS = true
		if qc.ecsPrefix.IsValid() {
			clientECSStr = qc.ecsPrefix.String()
		} else {
			clientECSStr = qc.ecsAddr.String()
		}
	}

	if qc.group != nil {
		if qc.group.ECSAction == "add" && qc.clientAddr.IsValid() {
			var m int
			if qc.clientAddr.Is4() {
				m = qc.group.ECSV4Mask
			} else {
				m = qc.group.ECSV6Mask
			}
			prefix, _ := qc.clientAddr.Prefix(m)
			ecsForCache = prefix.Masked().String()
		} else if qc.group.ECSAction == "pass" && clientSentECS {
			if clientECSStr != "" {
				ecsForCache = clientECSStr
			} else {
				ecsForCache = "passed-ecs"
			}
		}
	}

	effectiveDo := qc.doBit || (qc.group != nil && qc.group.RequireDNSSECAD)

	qc.cacheKey = DNSCacheKey{
		Name:             qc.qNameTrimmed,
		ClientName:       clientNameForCache,
		ECS:              ecsForCache,
		Qtype:            qc.q.Qtype,
		Qclass:           qc.q.Qclass,
		RouteIdx:         qc.route.routeIdx,
		DoBit:            effectiveDo,
		CdBit:            qc.r.CheckingDisabled,
		BypassGlobal:     qc.bypassGlobal,
		BypassPolicies:   qc.bypassPolicies,
		BypassLocal:      qc.route.bypassLocal,
		RecursionDesired: qc.r.RecursionDesired,
	}
}

func isCachedSyntheticItem(key DNSCacheKey) bool {
	if !cfg.Cache.Enabled {
		return false
	}
	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	return found && item.routeName == ""
}

func hasLocalFamilyAddr(addrs []netip.Addr, qtype uint16) bool {
	for _, a := range addrs {
		if qtype == dns.TypeA && a.Is4() {
			return true
		}
		if qtype == dns.TypeAAAA && a.Is6() && !a.Is4In6() {
			return true
		}
	}
	return false
}

func hasLocalUnspecifiedFamilyAddr(addrs []netip.Addr, qtype uint16) bool {
	for _, a := range addrs {
		if !a.IsUnspecified() {
			continue
		}
		if qtype == dns.TypeA && a.Is4() {
			return true
		}
		if qtype == dns.TypeAAAA && a.Is6() && !a.Is4In6() {
			return true
		}
	}
	return false
}

func (qc *queryCtx) isLocalIdentityNODATA() bool {
	if !cacheLocalIdentity || qc.route.bypassLocal || qc.q.Qtype == dns.TypePTR {
		return false
	}
	if cfg.Server.FilterAAAA && qc.q.Qtype == dns.TypeAAAA && !qc.bypassPolicies && !qc.bypassGlobal {
		return false
	}
	addrs, _ := LookupIPsByNameLower(qc.qNameTrimmed)
	return len(addrs) > 0 && !hasLocalFamilyAddr(addrs, qc.q.Qtype)
}

func (qc *queryCtx) isLocalIdentityPTR() bool {
	if !cacheLocalIdentity || qc.route.bypassLocal || qc.q.Qtype != dns.TypePTR {
		return false
	}
	return len(LookupNamesByARPA(qc.qNameTrimmed)) > 0
}

func (qc *queryCtx) checkCachedIDNViolation() (bool, string) {
	if !hasIDNHomograph || idnAction == "LOG" || qc.bypassPolicies || qc.bypassGlobal {
		return false, ""
	}
	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if v, r := AnalyzeIDNHomograph(qc.originalQNameTrimmed); v {
			return true, r
		}
	}
	if v, r := AnalyzeIDNHomograph(qc.qNameTrimmed); v {
		return true, r
	}
	return false, ""
}

// isCachedSynthBlock reports whether resp is a cached synthetic policy block
// (`cache_synthetic: true`) rather than an authoritative upstream response or
// a cached local-identity response.
func (qc *queryCtx) isCachedSynthBlock(resp *dns.Msg) (isBlock bool, isCustomIP bool, isIDN bool, reason string) {
	if !cacheSynthFlag || resp == nil || !resp.Authoritative || qc.bypassPolicies || qc.bypassGlobal {
		return false, false, false, ""
	}
	if !isCachedSyntheticItem(qc.cacheKey) {
		return false, false, false, ""
	}
	if qc.isLocalIdentityPTR() {
		return false, false, false, ""
	}

	if resp.Rcode != dns.RcodeSuccess {
		if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
			return true, false, true, idnReason
		}
		return true, false, false, "Cached Policy (" + RcodeStr(resp.Rcode) + ")"
	}

	if len(resp.Answer) == 0 {
		if qc.isLocalIdentityNODATA() {
			return false, false, false, ""
		}
		if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
			return true, false, true, idnReason
		}
		if cfg.Server.FilterAAAA && qc.q.Qtype == dns.TypeAAAA {
			return true, false, false, "Cached Policy (Filter AAAA)"
		}
		if globalBlockAction == BlockActionIP && ((qc.q.Qtype == dns.TypeA && len(globalBlockIPv4) == 0) || (qc.q.Qtype == dns.TypeAAAA && len(globalBlockIPv6) == 0)) {
			return true, false, false, "Cached Policy (Custom-IP NODATA)"
		}
		return true, false, false, "Cached Policy (NODATA)"
	}

	if globalBlockAction == BlockActionIP {
		if cacheLocalIdentity && !qc.route.bypassLocal {
			if addrs, _ := LookupIPsByNameLower(qc.qNameTrimmed); hasLocalFamilyAddr(addrs, qc.q.Qtype) {
				return false, false, false, ""
			}
		}
		if qc.q.Qtype == dns.TypeA && len(globalBlockIPv4) > 0 && len(resp.Answer) == len(globalBlockIPv4) {
			allMatch := true
			for i, rr := range resp.Answer {
				a, ok := rr.(*dns.A)
				if !ok || !a.A.Equal(globalBlockIPv4[i]) {
					allMatch = false
					break
				}
			}
			if allMatch {
				if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
					return true, true, true, idnReason
				}
				return true, true, false, "Cached Custom-IP (" + qc.route.routeName + ")"
			}
		} else if qc.q.Qtype == dns.TypeAAAA && len(globalBlockIPv6) > 0 && len(resp.Answer) == len(globalBlockIPv6) {
			allMatch := true
			for i, rr := range resp.Answer {
				aaaa, ok := rr.(*dns.AAAA)
				if !ok || !aaaa.AAAA.Equal(globalBlockIPv6[i]) {
					allMatch = false
					break
				}
			}
			if allMatch {
				if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
					return true, true, true, idnReason
				}
				return true, true, false, "Cached Custom-IP (" + qc.route.routeName + ")"
			}
		}
	}

	return false, false, false, ""
}

func (qc *queryCtx) serveFromCache() bool {
	poolMsg := msgPool.Get().(*dns.Msg)
	*poolMsg = dns.Msg{}

	isStale, isPrefetch, cacheOK, _ := CacheGet(qc.cacheKey, qc.q.Name, poolMsg)
	if !cacheOK {
		msgPool.Put(poolMsg)
		return false
	}

	defer msgPool.Put(poolMsg)

	if !poolMsg.Authoritative {
		if qc.enforceForSaleResponseCheck(poolMsg, true) {
			return true
		}
		if qc.enforceParkedResponseCheck(poolMsg, true) {
			return true
		}
		if qc.enforceRFCComplianceResponseCheck(poolMsg, true) {
			return true
		}
	}

	IncrCacheHit()

	if !qc.doBit {
		if qc.q.Qtype != dns.TypeRRSIG {
			poolMsg.Answer = stripRRSIGRecords(poolMsg.Answer)
		}
		poolMsg.Ns = stripRRSIGRecords(poolMsg.Ns)
		if !qc.r.AuthenticatedData {
			poolMsg.AuthenticatedData = false
		}
	}

	if cfg.Cache.AnswerSort != "none" && !cacheRotateAnswers {
		var lAddr netip.Addr
		if cfg.Cache.AnswerSort == "proximity" {
			if ip := localAddrIP(qc.w); ip != nil {
				if a, ok := netip.AddrFromSlice(ip); ok {
					lAddr = a.Unmap()
				}
			}
		}
		applyAnswerSort(poolMsg, cfg.Cache.AnswerSort, lAddr)
	}

	if qc.parentalForcedTTL > 0 {
		CapResponseTTL(poolMsg, qc.parentalForcedTTL)
	}
	poolMsg.Id = qc.originalID

	// ── Post-cache policy re-evaluation ───────────────────────────────────
	if checkTargetNames(qc.w, qc.r, poolMsg, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.protoEndpoint, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, true) {
		return true
	}

	resp := transformResponse(poolMsg, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, resp, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.protoEndpoint, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, qc.originalQNameTrimmed, true) {
		return true
	}

	if filterRebinding(qc.w, qc.r, resp, qc.clientIP, qc.clientID,
		qc.protocol, qc.protoEndpoint, qc.originalQName, qc.originalQNameTrimmed, true) {
		return true
	}

	// ── Telemetry ─────────────────────────────────────────────────────────
	isNullIP := false
	for _, rr := range resp.Answer {
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

	isSynthBlock := false
	isCustomBlockIP := false
	if isNullIP {
		isSynthBlock = true
		isLocalNull := false
		if cacheLocalIdentity && !qc.route.bypassLocal {
			if addrs, _ := LookupIPsByNameLower(qc.qNameTrimmed); hasLocalUnspecifiedFamilyAddr(addrs, qc.q.Qtype) {
				isLocalNull = true
			}
		}
		if isLocalNull {
			IncrPolicyBlock()
			RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Local Hosts (NULL-IP)")
		} else if isCachedSyntheticItem(qc.cacheKey) {
			if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
				IncrIDNHomographBlock()
				RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, idnReason)
			} else {
				IncrPolicyBlock()
				RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Cached NULL-IP ("+qc.route.routeName+")")
			}
		} else {
			IncrPolicyBlock()
			RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Cached NULL-IP ("+qc.route.routeName+")")
		}
	} else if sb, customIP, idnHit, reason := qc.isCachedSynthBlock(resp); sb {
		isSynthBlock = true
		isCustomBlockIP = customIP
		if idnHit {
			IncrIDNHomographBlock()
		} else {
			IncrPolicyBlock()
		}
		RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)
	}

	IncrReturnCode(resp.Rcode, isNullIP)
	if resp.Rcode == dns.RcodeNameError {
		IncrNXDomain(qc.originalQNameTrimmed)
	}

	upstreamSize, clientAdvertised := enforceUDPDefenses(qc.r, resp, qc.protocol, qc.clientAddr, qc.group)

	qc.w.WriteMsg(resp)

	if logQueries {
		rcodeStr := RcodeStr(resp.Rcode)
		if isNullIP {
			rcodeStr += " (NULL-IP)"
		} else if isCustomBlockIP {
			rcodeStr += " (CUSTOM-IP)"
		} else if isSynthBlock && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			rcodeStr += " (NODATA)"
		}

		if logSimple {
			if qc.parentalReason == "ACTIVATING_UNTRIGGER" {
				qc.scheduleUntriggerExpiry()
			}
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), rcodeStr, qc.effectivePolicyLabel(), true)
			return true
		}

		var status string
		switch {
		case isStale:
			status = "STALE (revalidating) | " + rcodeStr
		case isPrefetch:
			status = "CACHE HIT (prefetching) | " + rcodeStr
		case resp.Truncated:
			status = fmt.Sprintf("CACHE HIT (Truncated TC=1, Upstream:%dB, Client:%dB) | %s",
				upstreamSize, clientAdvertised, rcodeStr)
		default:
			status = "CACHE HIT | " + rcodeStr
		}

		status = qc.annotateParental(status)
		status = qc.annotateAlias(status)
		status = qc.annotateECS(status)

		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType, status)
	}

	return true
}
