/*
File:    process_cachehit.go
Version: 1.8.0 (Split)
Last Updated: 17-Oct-2026 20:06 CEST

Description:
  Cache-hit serving stage for the sdproxy resolution pipeline.

  Owns everything between "the cache had this answer" and "the client has it":
  cache-key derivation, the lookup itself, per-client answer ordering, the
  post-cache policy re-checks, and the response write.

  The policy re-checks are the reason this stage is not a two-line lookup. A
  cached payload is a payload from a DIFFERENT client's query, so it has to be
  re-evaluated against THIS client's target-name policy, IP filters and
  rebinding rules before it can be served. Skipping that would let one client's
  permitted answer leak to a client whose policy forbids it.

Changes:
  1.8.0 - [SECURITY/FIX] Passed `qc.q.Name` into `CacheGet` so the unpacked cached
          message restores the requesting client's exact Question casing (0x20 bit
          encoding / RFC 1035).
  1.7.0 - [FIX] Passed `qc.localPort` to `checkTargetNames` and `filterResponseIPs`
          so post-cache policy checks preserve port-based parental state resolution.
  1.6.0 - [PERF] Inlined `responseContainsNullIP` evaluation natively within `serveFromCache`.
          Eradicates the external function call overhead on the cache-miss hot path organically.
  1.5.0 - [CLEANUP] Updated `filterRebinding` call organically to match the 
          optimized dead-code-free signature natively.
  1.4.0 - [SECURITY/FIX] Added RecursionDesired to the cache key so recursive and
           non-recursive queries cannot share cached responses.
  1.3.0 - [PERF/FIX] Eradicated a massive, redundant `msg.Copy()` heap allocation natively.
          `CacheGet` unpacks messages directly from wire-format byte slices,
          guaranteeing that the returned `poolMsg` is completely isolated from the master
          memory arrays. Bypassing the deep-clone directly before `transformResponse`
          slashes Garbage Collection (GC) thrashing organically on the cache-hit hot path.
  1.2.0 - [SECURITY/FIX] Resolved a severe cache payload modification vulnerability.
          `serveFromCache` correctly cloned responses, but failed to deeply clone the
          `Answer` slice prior to calling `transformResponse` when `inPlace` was false.
  1.1.0 - [SECURITY/FIX] deriveCacheKey and resolveUpstreamGroup resolved the
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
	if opt := qc.r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
				clientSentECS = true
				if ecs.Address != nil {
					clientECSStr = fmt.Sprintf("%s/%d", ecs.Address.String(), ecs.SourceNetmask)
				}
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
	if checkTargetNames(qc.w, qc.r, poolMsg, qc.sk, qc.clientGroup, qc.clientMAC, qc.clientIP, qc.clientAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower, qc.localPort,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName) {
		return true
	}

	resp := transformResponse(poolMsg, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, resp, qc.sk, qc.clientGroup, qc.clientMAC, qc.clientIP, qc.clientAddr,
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

