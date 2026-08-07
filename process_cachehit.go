/*
File:    process_cachehit.go
Version: 1.0.0
Last Updated: 05-Aug-2026 23:10 CEST

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
  1.0.0 - [REFACTOR] Extracted from process.go 3.90.0 as part of splitting a
          1.031-line file. Behaviour preserved except where process_status.go
          1.0.0 documents a deliberate unification of two drifted log renderings.
*/

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// deriveCacheKey computes the cache key for this query and stores it on the
// context.
//
// The key is deliberately wide. Every field below partitions the cache to stop
// one client's answer being served to another client who would not have been
// entitled to it:
//
//	ClientName   — upstreams templated with {client-name} (NextDNS, ControlD)
//	               return per-profile answers; sharing them across profiles
//	               would cross-contaminate filtering policy.
//	ECS          — subnet-optimised CDN answers are only valid for the subnet
//	               they were requested for.
//	RouteIdx     — different upstream groups legitimately disagree.
//	DoBit/CdBit  — signed vs unsigned and validated vs unvalidated payloads are
//	               not interchangeable.
//	BypassGlobal — a client exempt from global rrs:/domain policy must not seed
//	               the cache for clients who are not, nor read from theirs.
func (qc *queryCtx) deriveCacheKey() {
	clientNameForCache := ""
	if grp, exists := routeUpstreams[qc.route.routeName]; exists && grp.HasClientName {
		clientNameForCache = qc.clientName
	}

	// [SECURITY] Extract the ECS footprint that will partition this entry.
	//
	// Two distinct cases produce a subnet-specific answer, and both must be
	// reflected in the key:
	//   "add"  — sdproxy injects the client's masked prefix itself.
	//   "pass" — the client supplied its own ECS and we forward it verbatim.
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

	if grp, exists := routeUpstreams[qc.route.routeName]; exists {
		if grp.ECSAction == "add" && qc.clientAddr.IsValid() {
			var m int
			if qc.clientAddr.Is4() {
				m = grp.ECSV4Mask
			} else {
				m = grp.ECSV6Mask
			}
			prefix, _ := qc.clientAddr.Prefix(m)
			ecsForCache = prefix.Masked().String()
		} else if grp.ECSAction == "pass" && clientSentECS {
			// [SECURITY/FIX] Forwarded ECS must carry its actual subnet into the
			// key. A static "passed-ecs" marker (as used before) made every
			// origin subnet share one cache slot, so the first querier's regional
			// answer was served to everyone — the exact contamination ECS
			// partitioning exists to prevent.
			if clientECSStr != "" {
				ecsForCache = clientECSStr
			} else {
				// Unparseable ECS option. Fall back to the shared marker rather
				// than to no partitioning at all: one degraded bucket is far
				// better than silently merging subnet-specific answers into the
				// general cache.
				ecsForCache = "passed-ecs"
			}
		}
	}

	qc.cacheKey = DNSCacheKey{
		Name:         qc.qNameTrimmed,
		ClientName:   clientNameForCache,
		ECS:          ecsForCache,
		Qtype:        qc.q.Qtype,
		Qclass:       qc.q.Qclass,
		RouteIdx:     qc.route.routeIdx,
		DoBit:        qc.doBit,
		CdBit:        qc.r.CheckingDisabled,
		BypassGlobal: qc.bypassGlobal,
	}
}

// serveFromCache attempts to answer entirely from cache.
//
// Returns true when the query has been fully handled — either answered, or
// intercepted by one of the post-cache policy checks — and the pipeline must
// stop. Returns false on a miss, leaving the caller to continue to the upstream
// stage.
func (qc *queryCtx) serveFromCache() bool {
	poolMsg := msgPool.Get().(*dns.Msg)
	*poolMsg = dns.Msg{}

	isStale, isPrefetch, cacheOK, _ := CacheGet(qc.cacheKey, poolMsg)
	if !cacheOK {
		msgPool.Put(poolMsg)
		return false
	}

	// Every remaining path through this function must return the pooled message.
	// A defer is used rather than repeating msgPool.Put at each of the five exit
	// points, which is how a leak gets introduced by a later edit.
	defer msgPool.Put(poolMsg)

	IncrCacheHit()

	// [PERF 3.89.0] Round-robin ordering is applied inside CacheGet from the
	// entry's own rotation counter, without rewriting the stored bytes — so
	// there is nothing to do here and nothing to persist.
	//
	// The other modes still run: "random" reshuffles per client and is never
	// written back; "ip-sort" is deterministic, so it converges after a single
	// write-back and applyAnswerSort returns false from then on.
	if cfg.Cache.AnswerSort != "none" && !cacheRotateAnswers {
		if applyAnswerSort(poolMsg, cfg.Cache.AnswerSort) {
			if cfg.Cache.AnswerSort != "random" {
				CacheUpdateOrder(qc.cacheKey, poolMsg)
			}
		}
	}

	// Cap the TTL to the remaining parental budget window. Without this a client
	// could cache an answer locally for longer than the window it was granted
	// under and keep resolving after the window closed.
	if qc.parentalForcedTTL > 0 {
		CapResponseTTL(poolMsg, qc.parentalForcedTTL)
	}
	poolMsg.Id = qc.originalID

	// ── Post-cache policy re-evaluation ───────────────────────────────────
	// This payload was produced for a different client. It must clear THIS
	// client's policy before it can be served, or the cache becomes a channel
	// for bypassing per-client filtering.
	if checkTargetNames(qc.w, qc.r, poolMsg, qc.sk, qc.clientGroup, qc.clientMAC, qc.clientIP, qc.clientAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName) {
		return true
	}

	// transformResponse with inPlace=true returns poolMsg itself; resp is an
	// alias, not a new allocation, and the deferred Put remains correct.
	resp := transformResponse(poolMsg, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, resp, qc.sk, qc.clientGroup, qc.clientMAC, qc.clientIP, qc.clientAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, qc.originalQNameTrimmed) {
		return true
	}

	if filterRebinding(qc.w, qc.r, resp, qc.clientIP, qc.clientAddr, qc.clientName, qc.clientID,
		qc.protocol, qc.originalQName, qc.originalQNameTrimmed) {
		return true
	}

	// ── Telemetry ─────────────────────────────────────────────────────────
	// NULL-IP is evaluated BEFORE the UDP defenses below, because truncation can
	// strip the answer section outright and a truncated block would otherwise
	// vanish from the block counters entirely.
	isNullIP := responseContainsNullIP(resp)
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

		// Shared with the upstream path — see process_status.go. Two divergent
		// copies of this annotation is what the split removed.
		status = qc.annotateParental(status)
		status = qc.annotateAlias(status)

		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType, status)
	}

	return true
}
