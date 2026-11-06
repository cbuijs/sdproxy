/*
File:    process_cachehit.go
Version: 1.22.0 (Split)
Last Updated: 05-Nov-2026 16:55 CET

Description:
  Cache-hit serving stage for the sdproxy resolution pipeline.

  Owns everything between "the cache had this answer" and "the client has it":
  cache-key derivation, the lookup itself, per-client answer ordering, the
  post-cache policy re-checks, and the response write.

Changes:
  1.22.0 - [SECURITY/FIX] Restricted `CacheUpdateOrder` in `serveFromCache` to
           `cfg.Cache.AnswerSort == "ip-sort"`. Because `"proximity"` depends on
           the per-request listener IP (`lAddr`), writing proximity-sorted order
           back into the shared cache caused redundant cache repacks when queries
           arrived on different listener interfaces.
  1.21.0 - [PERF/FIX] Persisted sorted answer ordering via `CacheUpdateOrder` in
           `serveFromCache`.
  1.20.0 - [FEAT] Passed the incoming listener address (`localAddrIP(qc.w)`) into
           `applyAnswerSort` so `answer_sort: "proximity"` includes the active
           listener socket IP when computing address-space distance.
  1.19.0 - [SECURITY/FIX] Cleared `poolMsg.AuthenticatedData = false` in `serveFromCache`
           when the querying client specified neither `DO=1` (`!qc.doBit`) nor
           `AD=1` (`!qc.r.AuthenticatedData`), per RFC 6840 §5.8.
  1.18.0 - [SECURITY/FIX] Aligned `deriveCacheKey` with `group.RequireDNSSECAD`.
  1.17.0 - [FEAT] Added Simple Logging Mode (`logSimple` / `logQuerySimple`)
           support on cache hits.
  1.16.0 - [SECURITY/FIX] Passed `qc.clientAddr` and `qc.group` to `enforceUDPDefenses`.
  1.15.0 - [FEAT/FIX] Added `qc.enforceForSaleResponseCheck(poolMsg)` on non-synthetic
           cache hits.
  1.14.0 - [FEAT] Added `qc.enforceParkedCheck()` and `qc.enforceParkedResponseCheck(poolMsg)`
           on non-synthetic cache hits.
  1.13.0 - [PERF/CLEANUP] Moved the cached-only RFC 10023 `_for-sale.` parent/apex
           check to step 3.6 in `ProcessDNS`.
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
		if qc.enforceForSaleResponseCheck(poolMsg) {
			return true
		}
		if qc.enforceForSaleCheck() {
			return true
		}
		if qc.enforceParkedResponseCheck(poolMsg) {
			return true
		}
		if qc.enforceParkedCheck() {
			return true
		}
	}

	IncrCacheHit()

	if !qc.doBit && qc.q.Qtype != dns.TypeRRSIG && qc.q.Qtype != dns.TypeANY {
		poolMsg.Answer = stripRRSIGRecords(poolMsg.Answer)
		poolMsg.Ns = stripRRSIGRecords(poolMsg.Ns)
	}
	if !qc.doBit && !qc.r.AuthenticatedData {
		poolMsg.AuthenticatedData = false
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
		if applyAnswerSort(poolMsg, cfg.Cache.AnswerSort, lAddr) {
			if cfg.Cache.AnswerSort == "ip-sort" {
				CacheUpdateOrder(qc.cacheKey, poolMsg)
			}
		}
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

	if isNullIP {
		RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Cached NULL-IP ("+qc.route.routeName+")")
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
