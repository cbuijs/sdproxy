/*
File:    process_cachehit.go
Version: 1.10.0 (Split)
Last Updated: 22-Oct-2026 13:35 CEST

Description:
  Cache-hit serving stage for the sdproxy resolution pipeline.

  Owns everything between "the cache had this answer" and "the client has it":
  cache-key derivation, the lookup itself, per-client answer ordering, the
  post-cache policy re-checks, and the response write.

Changes:
  1.10.0 - [FEAT] Propagated `qc.ednsMAC` to `checkTargetNames` and `filterResponseIPs`
           so post-cache policy checks preserve EDNS0 Option 65001 (`mac:`) parental
           state resolution.
  1.9.0  - [FIX] Passed `qc.ecsAddr` to `checkTargetNames` and `filterResponseIPs`,
           and normalized `ecsForCache` via `qc.ecsPrefix` / `qc.ecsAddr` in
           `deriveCacheKey` so incoming IPv4-in-IPv6 or unmasked ECS options
           do not fragment the cache.
  1.8.0  - [SECURITY/FIX] Passed `qc.q.Name` into `CacheGet` so the unpacked cached
           message restores the requesting client's exact Question casing (0x20 bit
           encoding / RFC 1035).
  1.7.0  - [FIX] Passed `qc.localPort` to `checkTargetNames` and `filterResponseIPs`
           so post-cache policy checks preserve port-based parental state resolution.
  1.6.0  - [PERF] Inlined `responseContainsNullIP` evaluation natively within `serveFromCache`.
           Eradicates the external function call overhead on the cache-miss hot path organically.
  1.5.0  - [CLEANUP] Updated `filterRebinding` call organically to match the 
           optimized dead-code-free signature natively.
  1.4.0  - [SECURITY/FIX] Added RecursionDesired to the cache key so recursive and
           non-recursive queries cannot share cached responses.
  1.3.0  - [PERF/FIX] Eradicated a massive, redundant `msg.Copy()` heap allocation natively.
  1.2.0  - [SECURITY/FIX] Resolved a severe cache payload modification vulnerability.
  1.1.0  - [SECURITY/FIX] deriveCacheKey and resolveUpstreamGroup resolved the
           upstream group INDEPENDENTLY, out of the same map, with different
           fallback rules.
*/

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// deriveCacheKey computes the cache key for this query and stores it on the
// context, along with the effective upstream group the key was derived from.
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
	} else if opt := qc.r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_SUBNET); ok {
				clientSentECS = true
				break
			}
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

	qc.cacheKey = DNSCacheKey{
		Name:             qc.qNameTrimmed,
		ClientName:       clientNameForCache,
		ECS:              ecsForCache,
		Qtype:            qc.q.Qtype,
		Qclass:           qc.q.Qclass,
		RouteIdx:         qc.route.routeIdx,
		DoBit:            qc.doBit,
		CdBit:            qc.r.CheckingDisabled,
		BypassGlobal:     qc.bypassGlobal,
		RecursionDesired: qc.r.RecursionDesired,
	}
}

// serveFromCache attempts to answer entirely from cache.
func (qc *queryCtx) serveFromCache() bool {
	poolMsg := msgPool.Get().(*dns.Msg)
	*poolMsg = dns.Msg{}

	isStale, isPrefetch, cacheOK, _ := CacheGet(qc.cacheKey, qc.q.Name, poolMsg)
	if !cacheOK {
		msgPool.Put(poolMsg)
		return false
	}

	defer msgPool.Put(poolMsg)

	IncrCacheHit()

	if cfg.Cache.AnswerSort != "none" && !cacheRotateAnswers {
		if applyAnswerSort(poolMsg, cfg.Cache.AnswerSort) {
			if cfg.Cache.AnswerSort != "random" {
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
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName) {
		return true
	}

	resp := transformResponse(poolMsg, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, resp, qc.sk, qc.clientGroup, qc.clientMAC, qc.ednsMAC, qc.clientIP, qc.clientAddr, qc.ecsAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, qc.originalQNameTrimmed) {
		return true
	}

	if filterRebinding(qc.w, qc.r, resp, qc.clientIP, qc.clientID,
		qc.protocol, qc.originalQName, qc.originalQNameTrimmed) {
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

	upstreamSize, clientAdvertised := enforceUDPDefenses(qc.r, resp, qc.protocol)

	qc.w.WriteMsg(resp)

	if logQueries {
		rcodeStr := RcodeStr(resp.Rcode)
		if isNullIP {
			rcodeStr += " (NULL-IP)"
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
