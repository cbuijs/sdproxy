/*
File:    process_cachehit.go
Version: 1.40.0 (Split)
Last Updated: 27-Nov-2026 13:30 CET

Description:
  Cache-hit serving stage for the sdproxy resolution pipeline.
  Handles cache-key derivation, lookup, per-client answer ordering,
  post-cache policy re-checks, and client response dispatch.

Changes:
  1.40.0 - [CLEANUP/PERF] Used `fullMsgRcode` when recording `IncrReturnCode` and
           formatting RCODE telemetry on cache hits so cached Extended RCODEs
           (>=16) are reported accurately, and simplified `isCachedSynthBlock`
           now that `CacheSetLocal` tags local-identity items with `routeLocalTag`.
  1.39.0 - [FIX] Recorded `IncrCacheLookup()` in `serveFromCache`.
  1.38.0 - [SECURITY/PERF] Consumed `isSynth` directly from `CacheGet`.
  1.37.0 - [SECURITY/FIX] Extended `isCachedSynthBlock` for cached synthetic
           `NOERROR` (`len(resp.Answer) == 0`) items.
  1.36.0 - [SECURITY/FIX] Aligned `RRSIG` stripping in `serveFromCache` with
           `CacheSet`.
  1.35.0 - [SECURITY/FIX] Added `isLocalIdentityPTR` helper in `isCachedSynthBlock`.
  1.34.0 - [SECURITY/FIX] Excluded cached `Filter AAAA` synthetic NODATA
           responses from `checkCachedIDNViolation`.
  1.33.0 - [SECURITY/FIX] Added `isLocalIdentityNODATA` helper in `isCachedSynthBlock`.
  1.32.0 - [SECURITY/FIX] Excluded cached local-identity `NODATA` responses.
  1.31.0 - [SECURITY/FIX] Excluded cached local-identity `NULL-IP` responses.
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

func (qc *queryCtx) isLocalCacheEntry() bool {
	if !cacheLocalIdentity {
		return false
	}
	shard := getShard(qc.cacheKey)
	shard.RLock()
	item, ok := shard.items[qc.cacheKey]
	shard.RUnlock()
	return ok && item.routeName == routeLocalTag
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

func (qc *queryCtx) isCachedSynthBlock(resp *dns.Msg, isSynth bool, isLocal bool) (isBlock bool, isCustomIP bool, isIDN bool, reason string) {
	if !isSynth || isLocal || !cacheSynthFlag || resp == nil || !resp.Authoritative || qc.bypassPolicies || qc.bypassGlobal {
		return false, false, false, ""
	}

	effRcode := fullMsgRcode(resp)
	if effRcode != dns.RcodeSuccess {
		if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
			return true, false, true, idnReason
		}
		return true, false, false, "Cached Policy (" + RcodeStr(effRcode) + ")"
	}

	if len(resp.Answer) == 0 {
		if cfg.Server.FilterAAAA && qc.q.Qtype == dns.TypeAAAA {
			return true, false, false, "Cached Policy (Filter AAAA)"
		}
		if idnHit, idnReason := qc.checkCachedIDNViolation(); idnHit {
			return true, false, true, idnReason
		}
		if globalBlockAction == BlockActionIP && ((qc.q.Qtype == dns.TypeA && len(globalBlockIPv4) == 0) || (qc.q.Qtype == dns.TypeAAAA && len(globalBlockIPv6) == 0)) {
			return true, false, false, "Cached Policy (Custom-IP NODATA)"
		}
		return true, false, false, "Cached Policy (NODATA)"
	}

	if globalBlockAction == BlockActionIP {
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
	if !cfg.Cache.Enabled {
		return false
	}

	IncrCacheLookup()

	poolMsg := msgPool.Get().(*dns.Msg)
	*poolMsg = dns.Msg{}

	isStale, isPrefetch, cacheOK, isSynth := CacheGet(qc.cacheKey, qc.q.Name, poolMsg)
	if !cacheOK {
		msgPool.Put(poolMsg)
		return false
	}

	defer msgPool.Put(poolMsg)

	IncrCacheHit()

	if !isSynth {
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

	isLocalEntry := isSynth && qc.isLocalCacheEntry()
	isSynthBlock := false
	isCustomBlockIP := false
	if isNullIP {
		isSynthBlock = true
		isLocalNull := false
		if isLocalEntry && !qc.route.bypassLocal {
			if addrs, _ := LookupIPsByNameLower(qc.qNameTrimmed); hasLocalUnspecifiedFamilyAddr(addrs, qc.q.Qtype) {
				isLocalNull = true
			} else {
				isLocalNull = true
			}
		}
		if isLocalNull {
			IncrPolicyBlock()
			RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Local Hosts (NULL-IP)")
		} else if isSynth {
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
	} else if sb, customIP, idnHit, reason := qc.isCachedSynthBlock(resp, isSynth, isLocalEntry); sb {
		isSynthBlock = true
		isCustomBlockIP = customIP
		if idnHit {
			IncrIDNHomographBlock()
		} else {
			IncrPolicyBlock()
		}
		RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)
	}

	effRcode := fullMsgRcode(resp)
	IncrReturnCode(effRcode, isNullIP)
	if effRcode == dns.RcodeNameError {
		IncrNXDomain(qc.originalQNameTrimmed)
	}

	upstreamSize, clientAdvertised := enforceUDPDefenses(qc.r, resp, qc.protocol, qc.clientAddr, qc.group)

	qc.w.WriteMsg(resp)

	if logQueries {
		rcodeStr := RcodeStr(effRcode)
		if isNullIP {
			rcodeStr += " (NULL-IP)"
		} else if isCustomBlockIP {
			rcodeStr += " (CUSTOM-IP)"
		} else if (isSynthBlock || isLocalEntry) && effRcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			rcodeStr += " (NODATA)"
		}

		if logSimple {
			if qc.parentalReason == "ACTIVATING_UNTRIGGER" {
				qc.scheduleUntriggerExpiry()
			}
			polLabel := qc.effectivePolicyLabel()
			if isLocalEntry {
				if isNullIP {
					polLabel = "Local Identity Block"
				} else {
					polLabel = "Local Identity"
				}
			}
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), rcodeStr, polLabel, true)
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
