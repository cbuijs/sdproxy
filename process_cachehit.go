/*
File:    process_cachehit.go
Version: 1.3.0 (Split)
Last Updated: 04-Sep-2026 09:50 CEST

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
  1.3.0 - [PERF/FIX] Eradicated a massive, redundant `msg.Copy()` heap allocation natively.
          `CacheGet` unpacks messages directly from wire-format byte slices, 
          guaranteeing that the returned `poolMsg` is completely isolated from the master 
          memory arrays. Bypassing the deep-clone directly before `transformResponse` 
          slashes Garbage Collection (GC) thrashing organically on the cache-hit hot path.
  1.2.0 - [SECURITY/FIX] Resolved a severe cache payload modification vulnerability.
          `serveFromCache` correctly cloned responses, but failed to deeply clone the 
          `Answer` slice prior to calling `transformResponse` when `inPlace` was false. 
          `flattenCNAME` and `applyAnswerSort` thus mutated shared Answer slices residing 
          in the raw cache structure natively. This caused round-robin shifts or flattened 
          aliases to instantly corrupt active cached arrays across all clients organically.
  1.1.0 - [SECURITY/FIX] deriveCacheKey and resolveUpstreamGroup resolved the
          upstream group INDEPENDENTLY, out of the same map, with different
          fallback rules. deriveCacheKey did a bare
          `routeUpstreams[routeName]`; resolveUpstreamGroup (process_upstream.go)
          additionally fell back to the "default" group whenever the named entry
          was missing OR had zero servers.

          A configured-but-empty group therefore split the query in two: the
          answer was fetched through "default" — including any ECS prefix
          "default" is configured to inject — while the cache key carried the
          empty group's settings, which is to say no ECS component and no
          client-name component at all.

          The consequences are cache contamination of exactly the kind the wide
          key exists to prevent:
            • Subnet-optimised answers obtained WITH an ECS prefix were stored
              in an unpartitioned slot and served to every other subnet.
            • The SingleFlight footprint in serveFromUpstream reads
              qc.group.HasClientName while the key read the other lookup's, so
              two per-profile queries could coalesce into one key or split
              across two, depending on which group answered.

          Both call sites now go through effectiveUpstreamGroup() and the result
          is stored once on qc.group at stage 4. There is exactly one answer to
          "which group is this query using".
        - [FIX] The cache-hit log line now carries the ECS disposition, matching
          the upstream path. process_status.go 1.0.0's header lists ECS as one
          of the three annotations it unified across both paths; only two were
          ever wired up here. Now possible because qc.group is populated before
          the lookup — see above.
*/

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// deriveCacheKey computes the cache key for this query and stores it on the
// context, along with the effective upstream group the key was derived from.
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
	// [SECURITY/FIX 1.1.0] Resolve the group ONCE, here, through the same
	// helper the dial path uses, and keep it.
	//
	// The two lookups this replaces agreed on every configuration an operator
	// is likely to have and disagreed on the one they are most likely to reach
	// by accident: a group that exists in the config but ended up with no
	// usable servers (all failed to parse, all filtered out by ip_version, a
	// typo'd server list). In that state the query was dialled through
	// "default" but keyed as though it had been dialled through the empty
	// group, so ECS and client-name partitioning silently vanished from the key
	// while remaining fully in effect on the wire.
	qc.group = effectiveUpstreamGroup(qc.route.routeName)

	clientNameForCache := ""
	if qc.group != nil && qc.group.HasClientName {
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
			// [SECURITY/FIX] Forwarded ECS must carry its actual subnet into the
			// key. A static "passed-ecs" marker (as used before) made every
			// origin subnet share one cache slot, so the first querier's regional
			// answer was served to everyone — the exact contamination ECS
			// partitioning exists to prevent.
			if clientECSStr != "" {
				ecsForCache = clientECSStr
			} else {
				// Unparseable ECS option. Fallback to the shared marker rather
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

	// [PERF/FIX 1.3.0] Eradicated redundant heap allocations natively.
	// `CacheGet` unpacks the message directly from wire-format byte slices, 
	// meaning `poolMsg` is already entirely isolated from the master cache memory. 
	// Mutating it in-place eliminates a massive `msg.Copy()` GC bottleneck on the cache-hit hot path.
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
		//
		// [FIX 1.1.0] annotateECS added. process_status.go has claimed since
		// 1.0.0 that it unifies "the parental verdict, the rrs: alias marker and
		// the ECS disposition" across both terminal paths; only the first two
		// were ever called from here, so an ECS-partitioned cache hit logged
		// nothing about the subnet that selected the entry — precisely the case
		// where an operator debugging a wrong regional answer needs it. Safe now
		// that deriveCacheKey populates qc.group.
		status = qc.annotateParental(status)
		status = qc.annotateAlias(status)
		status = qc.annotateECS(status)

		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType, status)
	}

	return true
}
