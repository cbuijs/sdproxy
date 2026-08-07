/*
File:    process_upstream.go
Version: 1.0.0
Last Updated: 05-Aug-2026 23:10 CEST

Description:
  Upstream exchange stage for the sdproxy resolution pipeline — the cache-miss
  path. Owns upstream group resolution, QNAME label-bounds enforcement,
  SingleFlight coalescing, the outbound dial, the post-response policy checks
  and the final client write.

  NAMING: this file is deliberately NOT called process_exchange.go. That name
  belonged to a 406-line file which held a second, unreferenced copy of this
  stage; it drifted out of sync with the live implementation and silently took
  the qname_min_labels / qname_max_labels enforcement down with it when it died.
  Reusing the name would invite the assumption that the dead file came back. It
  did not — this is the single live implementation, reached from ProcessDNS.

Changes:
  1.0.0 - [REFACTOR] Extracted from process.go 3.90.0 as part of splitting a
          1.031-line file. Behaviour preserved, including the 3.88.0 SingleFlight
          ownership rule and the 3.89.0 IncrUpstream and answer-order fixes.
*/

package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// resolveUpstreamGroup selects the upstream group for this query and stores it
// on the context.
//
// Returns false when no group can serve the query, having already responded
// with SERVFAIL — the caller must stop.
//
// Runs BEFORE the SingleFlight dispatch rather than inside it, for three
// reasons:
//   1. QNAME label bounds (below) is a per-group policy, gated by the group's
//      IgnoreQnameLabels flag, so the group must be known before we can decide
//      whether to dial at all.
//   2. The SingleFlight closure executes only for the first caller, so any
//      validation placed inside it is silently skipped for every waiter.
//   3. It collapses what were three separate routeUpstreams lookups into one.
func (qc *queryCtx) resolveUpstreamGroup() bool {
	group, exists := routeUpstreams[qc.route.routeName]
	if !exists || len(group.Servers) == 0 {
		group = routeUpstreams["default"]
	}
	if group == nil || len(group.Servers) == 0 {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | NO UPSTREAMS CONFIGURED",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType)
		dns.HandleFailed(qc.w, qc.r)
		return false
	}
	qc.group = group
	return true
}

// enforceQnameLabelBounds rejects questions whose label count falls outside the
// configured window.
//
// Returns true when the query was blocked and the pipeline must stop.
//
// [SECURITY] Restored to the live path in 3.88.0. Before that, this guard
// existed only inside the dead process_exchange.go, so server.qname_min_labels
// and server.qname_max_labels were parsed, defaulted and clamped at boot yet
// never applied to a single query.
//
// The bound does real work at both ends:
//   Lower — rejects degenerate bare-label probes.
//   Upper — rejects the deep label chains characteristic of DNS tunnelling and
//           data exfiltration, BEFORE the payload is forwarded upstream and
//           before an outbound socket is allocated for it.
//
// A group may opt out with ignore_qname_labels: true, which is necessary for
// upstreams that legitimately serve deep hierarchies — DNSBL/RBL lookups encode
// a full IPv6 address as 32 separate labels.
func (qc *queryCtx) enforceQnameLabelBounds() bool {
	if qc.group.IgnoreQnameLabels {
		return false
	}

	labels := countDomainLabels(qc.qNameTrimmed)
	if labels >= cfg.Server.QnameMinLabels && labels <= cfg.Server.QnameMaxLabels {
		return false
	}

	IncrPolicyBlock()

	// [SECURITY] Name the rewritten target when the violation came from an rrs:
	// CNAME alias. Reporting only the original QNAME would leave the operator
	// unable to tell which name actually breached the bound.
	reason := fmt.Sprintf("QNAME Label Bounds (%d labels)", labels)
	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		reason += fmt.Sprintf(" (Target: %s)", qc.qNameTrimmed)
	}
	RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)

	dropped := writePolicyAction(qc.w, qc.r, PolicyActionBlock)

	if cacheSynthFlag && !dropped && globalBlockAction != BlockActionDrop {
		synthMsg := buildSynthCacheMsg(qc.q, PolicyActionBlock)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg) // [PERF] Zero-allocation memory recycling
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

// serveFromUpstream performs the cache-miss exchange and writes the response.
//
// Terminal: the pipeline ends here regardless of outcome.
func (qc *queryCtx) serveFromUpstream() {
	sfClientName := ""
	if qc.group.HasClientName {
		sfClientName = qc.clientName
	}

	// Deterministic coalescing footprint. Every field that could make two
	// otherwise-identical questions deserve DIFFERENT answers must appear here,
	// or SingleFlight will hand one client another client's answer.
	sfKey := buildSFKey(qc.qNameTrimmed, qc.q.Qtype, qc.q.Qclass, qc.route.routeIdx,
		qc.doBit, qc.r.CheckingDisabled, qc.bypassGlobal, sfClientName, qc.cacheKey.ECS)

	// didUpstream is written inside the closure, which x/sync/singleflight runs
	// in THIS goroutine for the owner and never runs at all for waiters. There
	// is no race: waiters observe it as false, which is correct.
	didUpstream := false

	v, sfErr, shared := sfGroup.Do(sfKey, func() (any, error) {
		didUpstream = true
		IncrUpstreamCall()

		ctx, cancel := newUpstreamCtx()
		defer cancel()

		msg, addr, err := qc.group.Exchange(ctx, qc.r, qc.clientID, qc.clientName, qc.clientAddr)
		if err != nil || msg == nil {
			// [FEAT] Infinite serve-stale fallback. On a total upstream failure,
			// probe the cache for an expired record as an absolute last resort —
			// a stale answer beats no answer when the upstream is simply down.
			if cfg.Cache.ServeStaleInfinite {
				// new(dns.Msg) rather than msgPool.Get(): this message escapes the
				// closure and is never returned to the pool, so drawing from it
				// would leave the pool permanently unbalanced.
				fallbackMsg := new(dns.Msg)
				if CacheGetExpired(qc.cacheKey, fallbackMsg) {
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

	// [FIX 3.89.0] One upstream dispatch counted per query that actually dialled.
	// Counting before the Do call inflated this by the coalescing factor.
	if didUpstream {
		IncrUpstream(qc.route.routeName)
	}

	var finalResp *dns.Msg
	var upstreamUsed string
	if v != nil {
		if res, ok := v.(sfResult); ok {
			upstreamUsed = res.addr
			if res.msg != nil && sfErr == nil {
				// [SECURITY/FIX 3.88.0] Ownership rule for the coalesced payload.
				//
				// `shared` is true for EVERY participant of a coalesced group, the
				// dialing goroutine included — singleflight returns c.dups > 0 to
				// the owner and a hardcoded true to each waiter. It is NOT an
				// "am I a waiter" flag.
				//
				// That matters because everything below this point mutates
				// finalResp in place (answer sorting, response transforms, UDP
				// defenses, TTL capping, the ID write) while waiters may still be
				// copying it. 3.87.0 handed the dialer the raw pointer and so
				// produced a genuine read/write race on a shared dns.Msg.
				//
				// Zero-copy survives where it is safe: shared == false means no
				// other goroutine ever observed this payload, which is the
				// overwhelmingly common case.
				if shared {
					finalResp = res.msg.Copy()
				} else {
					finalResp = res.msg
				}
			}
		}
	}

	if finalResp == nil {
		if sfErr != nil && errors.Is(sfErr, ErrSilentDrop) {
			// Consensus shed the query deliberately. No response is owed.
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

	// ── Answer sorting ────────────────────────────────────────────────────
	// MUST run BEFORE any client-specific mutation (TTL caps, DNSSEC stripping)
	// so the bytes persisted below stay canonical for the next client.
	if cfg.Cache.AnswerSort != "none" {
		if applyAnswerSort(finalResp, cfg.Cache.AnswerSort) {
			// "random" is per-client and must never be written back.
			// "round-robin" is applied at read time from the entry's rotation
			// counter (3.89.0), so persisting one client's rotation would achieve
			// nothing but an extra pack.
			// On a coalesced miss only the dialer persists, so parallel
			// participants do not stampede the shard with identical rewrites.
			if cfg.Cache.AnswerSort != "random" && !cacheRotateAnswers && (!shared || didUpstream) {
				CacheUpdateOrder(qc.cacheKey, finalResp)
			}
		}
	}

	// ── Post-response policy ──────────────────────────────────────────────
	if checkTargetNames(qc.w, qc.r, finalResp, qc.sk, qc.clientGroup, qc.clientMAC, qc.clientIP, qc.clientAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName) {
		return
	}

	finalResp = transformResponse(finalResp, qc.q.Qtype, qc.doBit, true)

	if filterResponseIPs(qc.w, qc.r, finalResp, qc.sk, qc.clientGroup, qc.clientMAC, qc.clientIP, qc.clientAddr,
		qc.clientName, qc.clientNameLower, qc.clientID, qc.protocol, qc.sni, qc.sniLower, qc.path, qc.pathLower,
		qc.bypassPolicies, qc.bypassGlobal, qc.originalQName, qc.originalQNameTrimmed) {
		return
	}

	if filterRebinding(qc.w, qc.r, finalResp, qc.clientIP, qc.clientAddr, qc.clientName, qc.clientID,
		qc.protocol, qc.originalQName, qc.originalQNameTrimmed) {
		return
	}

	// NULL-IP is evaluated BEFORE the UDP defenses, so an answer section removed
	// by truncation cannot make a block disappear from the counters.
	isNullIP := responseContainsNullIP(finalResp)
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

	// [MEMORY LIFECYCLE & GC]
	// finalResp originates from a network Unpack() (or a Copy() during
	// coalescing). It is intentionally NOT returned to msgPool: doing so would
	// pollute the pool with externally-sized network buffers and destroy the
	// pristine baseline capacities that locally synthesised messages rely on.
	// It is left to the garbage collector.

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

		// Shared with the cache-hit path — see process_status.go.
		status = qc.annotateParental(status)
		status = qc.annotateAlias(status)
		status = qc.annotateECS(status)

		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | UPSTREAM: %s (%s) | %s",
			qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
			qc.route.routeName, qc.route.routeOriginType,
			cleanUpstreamHost(upstreamUsed), qc.route.routeName, status)
	}
}
