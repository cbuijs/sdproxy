/*
File:    process.go
Version: 3.91.0
Last Updated: 07-Aug-2026 21:30 CEST

Description:
  Master orchestrator for the sdproxy per-query DNS resolution pipeline.

  This file owns the pipeline SHAPE — the order in which stages run and the
  conditions under which each is skipped — and nothing else. Each stage lives in
  its own file so that the ordering here stays readable at a glance, which
  matters because several of the orderings are load-bearing security properties
  rather than arbitrary sequencing (see the numbered notes on ProcessDNS).

  Pipeline stages and their homes:
    process_query.go     queryCtx — the per-query state carrier
    process_security.go  admission, ACLs, DGA, exfiltration, anti-amplification
    process_spoof.go     rrs: record overrides and CNAME aliasing
    process_routing.go   client and domain routing
    process_cachehit.go  cache key derivation and the cache-hit path
    process_policy.go    policy exits (rtype, domain policy, AAAA filter)
    process_local.go     local A/AAAA/PTR answers from hosts and leases
    process_upstream.go  SingleFlight coalescing and the upstream exchange
    process_status.go    shared log-status annotation
    process_cache.go     background revalidation and synthetic message builders

Changes:
  3.91.0 - [FIX] An admission-throttler shed now answers on connection-oriented
           transports instead of vanishing. `if !AcquireQuery() { return }` wrote
           nothing at all, which is the correct behaviour for UDP — the datagram
           is simply not answered and the stub retries — but is wrong for every
           other transport we speak:
             TCP/DoT — the client holds an idle connection until its own read
                       timeout expires, occupying one of the max_tcp_connections
                       slots for the entire duration. Shedding to save capacity
                       while pinning a connection slot is self-defeating.
             DoH     — net/http finalises the handler with 200 OK and a
                       zero-length body. A 200 carrying no application/dns-message
                       payload is a protocol violation (RFC 8484 §4.2.1), and
                       clients report it as a parse failure rather than as
                       "resolver busy".
             DoQ     — the stream closes with no framed response, which the peer
                       cannot distinguish from a truncated or spliced reply.
           Stream transports now receive a SERVFAIL, which is the response DNS
           already defines for "I cannot answer this right now" and which every
           stub retries or fails over on. UDP is unchanged: silence there is the
           correct and cheapest shed, and writing a SERVFAIL would hand an
           attacker an amplification primitive at exactly the moment the
           throttler exists to conserve resources.
         - [FIX] The parental PTR block reason opened with "(" and closed with
           "]". Cosmetic, but it lands in RecordBlockEvent and therefore in the
           Web UI block list and any log grep an operator writes against it.
  3.90.0 - [REFACTOR] Split a 1.031-line file into focused stages. ProcessDNS
           drops to the orchestration it was always supposed to be; the cache-hit
           path, the upstream exchange and the log annotation move out.
           The enabler is queryCtx (process_query.go). Without a shared state
           carrier the extracted stages would need twenty-parameter signatures —
           which is not a hypothetical objection: the file this replaces once
           carried exactly such a function, it drifted out of sync with the live
           inline copy, and it took the qname_min_labels / qname_max_labels
           enforcement into the grave with it when it was found to be dead.
           Two latent defects surfaced during the extraction and are fixed in
           process_status.go 1.0.0: a parental verdict that rendered under two
           different names depending on whether the answer was cached, and the
           untrigger window-expiry timer never arming on the cache-hit path.
           No other behaviour changes.
  3.89.0 - [PERF/FIX] Stopped persisting answer order on every cache hit.
           `answer_sort: round-robin` rotates by one position each time it is
           applied, so applyAnswerSort reported "changed" on EVERY hit and the
           pipeline called CacheUpdateOrder — a msg copy, an OPT strip, a 64KB
           pool round-trip, a PackBuffer, a fresh allocation, a shard lock and an
           atomic store — on the hottest path in the daemon, per query. Rotation
           now happens at unpack time from a per-entry counter (cache.go 2.51.0,
           cache_rw.go 1.3.0).
         - [FIX] IncrUpstream no longer counted for coalesced queries. It ran
           unconditionally before sfGroup.Do, so every SingleFlight participant
           incremented the per-route counter though only one dialled.
  3.88.0 - [SECURITY/FIX] Reverted the 3.87.0 SingleFlight "ownership" change,
           which was a data race: `shared` is returned to every participant
           INCLUDING the dialer, so handing the dialer the raw payload let it
           mutate an object the waiters were still copying.
         - [DEAD-CODE/FIX] Deleted the original process_exchange.go (406 lines,
           zero callers) and restored the three behaviours it had silently taken
           out of service: QNAME label bounds, the per-group ignore_qname_labels
           opt-out, and the UNTRIGGER window-expiry timer.
  3.87.0 - [PERF/FIX] SingleFlight dialer assumed ownership of the payload.
           [SUPERSEDED BY 3.88.0 — this was a data race.]
  3.86.0 - [FEAT] Extracted client route resolution to bypass global policies and RRS early.
  3.85.0 - [PERF] Eradicated redundant IP string allocations on the hot path.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// ProcessDNS — the master pipeline
// ---------------------------------------------------------------------------
//
// Stage order is deliberate. Several of these orderings are security
// properties, not conveniences, and reordering them silently breaks guarantees:
//
//	0.  Panic recovery and admission throttling — bounds goroutine growth
//	    before any per-query allocation happens.
//	1.  Security guards (ACL, rate limit, DGA, exfiltration, anti-amplification).
//	    MUST precede everything: an inadmissible client should consume nothing.
//	1.5 DDR interception. MUST precede domain policy, or a policy rule could
//	    shadow the resolver-discovery response and break client bootstrapping.
//	1.6 Identity and client route resolution, which yields the global-bypass
//	    verdict the later stages depend on.
//	1.7 rrs: spoofed records. May rewrite the question.
//	1.8 Custom rules. Evaluated against the ORIGINAL name, not the rewritten
//	    one, so an explicit admin ALLOW/BLOCK cannot be evaded by aliasing.
//	2.  Routing. May override the client identity, which forces a re-resolve of
//	    the parental state key.
//	3.  Parental controls. MUST precede the cache lookup — a blocked query must
//	    never be served from cache, and the budget verdict caps the TTL of one
//	    that is not.
//	4.  Cache lookup. Serves and returns on a hit.
//	5.  Policy exits (rtype, domain policy, AAAA filter, obsolete qtypes).
//	6.  Local identity (hosts/leases A/AAAA/PTR).
//	6.5 Strict PTR leakage prevention. AFTER local identity, so an internal PTR
//	    that resolves locally is answered rather than sinkholed.
//	7.  Upstream group resolution and QNAME label bounds.
//	8.  SingleFlight coalescing, the upstream exchange, and the reply.
func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP, protocol, sni, path string) {
	var clientAddr netip.Addr

	if clientIP != "" {
		if a, err := netip.ParseAddr(clientIP); err == nil {
			clientAddr = a.Unmap().WithZone("") // Cleanse interface indexes natively

			// [PERF/FIX] Prevent redundant string allocations on the hot path natively.
			// Network listeners already pass canonical IP strings. We only forcefully
			// allocate a new string if the address required structural unmapping
			// (IPv4-in-IPv6) or Zone-Index cleansing organically.
			if clientAddr != a {
				clientIP = clientAddr.String()
			}

			// [SECURITY/FIX] Universally reject structurally invalid or spoofed origin IPs
			// across ALL protocol transports natively. Thwarts Encrypted SSRF tunneling.
			// Explicitly enforcing `.IsValid()` guarantees malformed structural data
			// cannot bypass the internal evaluations gracefully.
			if clientAddr.IsValid() && (clientAddr.IsMulticast() || clientAddr.IsUnspecified() || (clientAddr.Is4() && clientAddr.As4() == [4]byte{255, 255, 255, 255})) {
				IncrDroppedRateLimit()
				return
			}
		}
	}

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[PANIC] Recovered in ProcessDNS (%s / %s): %v", protocol, clientIP, rec)

			// [SECURITY/FIX] Wrap the entirety of the error handling and punishment
			// routines in a secondary anonymous closure with its own panic recovery.
			// Ensures that cascading panics (e.g., closed socket writers or map collisions)
			// do not escape the primary defer block and catastrophically crash the server natively.
			func() {
				defer func() {
					if r2 := recover(); r2 != nil {
						log.Printf("[PANIC] Secondary panic recovered during error handling: %v", r2)
					}
				}()

				PenalizeClient(clientIP, clientAddr, -1)
				if r != nil {
					dns.HandleFailed(w, r)
				}
			}()
		}
	}()

	// ── 0. Sanity + throttle ──────────────────────────────────────────────
	if r == nil || len(r.Question) != 1 {
		if r != nil {
			dns.HandleFailed(w, r)
		}
		return
	}
	if !AcquireQuery() {
		// [FIX 3.91.0] Answer the shed on connection-oriented transports.
		//
		// Silence is the right shed for UDP: the datagram is unacknowledged,
		// the stub retries, and we spend nothing. Writing a response there
		// would additionally hand an attacker a reflection primitive at
		// precisely the moment the throttler is trying to conserve capacity.
		//
		// Every other transport we speak holds state that our silence strands.
		// A stream client waits out its own read timeout while occupying one of
		// the max_tcp_connections slots this shed was meant to protect; a DoH
		// client receives a 200 OK with an empty body, which is not a valid
		// application/dns-message and reads as corruption rather than as load;
		// a DoQ stream closes mid-frame, which is indistinguishable from a
		// spliced response. SERVFAIL is the answer DNS already has for "not
		// right now", and stubs act on it immediately instead of stalling.
		if protocol != "UDP" {
			dns.HandleFailed(w, r)
		}
		return
	}
	defer ReleaseQuery()

	q := r.Question[0]
	qNameTrimmed := lowerTrimDot(q.Name)
	originalQName := q.Name
	originalQNameTrimmed := qNameTrimmed

	clientMAC := LookupMAC(clientIP)
	clientName := LookupNameByMACOrIP(clientMAC, clientIP)

	// [PERF/OPTIMIZATION] Pre-compute globally normalized lowercase identities safely natively.
	// Drastically neutralizes heap-allocation overhead across the entire pipeline boundary,
	// eradicating millions of redundant strings.ToLower invocations during multi-level DPI filtering.
	clientNameLower := ""
	if clientName != "" {
		clientNameLower = strings.ToLower(clientName)
	}
	sniLower := ""
	if sni != "" {
		sniLower = strings.ToLower(sni)
	}
	pathLower := ""
	if path != "" {
		pathLower = strings.ToLower(path)
	}

	clientID := buildClientID(clientIP, clientName, clientAddr)

	// ── 1. Security & Admission ───────────────────────────────────────────
	if enforceSecurityGuards(w, r, q, originalQNameTrimmed, clientIP, clientAddr, clientMAC, clientName, clientID, protocol) {
		return
	}

	originalID := r.Id
	doBit := false
	if opt := r.IsEdns0(); opt != nil {
		doBit = opt.Do()
	}

	// ── 1.5 DDR interception ──────────────────────────────────────────────
	if handleDDR(w, r, q, originalQNameTrimmed, clientID, protocol) {
		return
	}

	// [PERF/FIX] Evaluate Routing Constraints and Group mappings immediately here
	// natively, propagating `sk` and `clientGroup` continuously downstream to organically
	// sidestep massive string-allocation overheads during multi-DPI evaluations.
	sk, clientGroup := ResolveStateKeyAndGroup(clientMAC, clientIP, clientAddr, clientName, clientNameLower, sni, sniLower, path, pathLower)

	// Pre-resolve Client Identity parameters organically to orchestrate global bypass bounds natively.
	clientRoute, clientRouteMatched, routeOriginType := resolveClientRoute(clientMAC, clientIP, clientAddr, clientNameLower, sniLower, pathLower)
	bypassGlobal := clientRouteMatched && clientRoute.BypassGlobal

	var spoofedAlias string

	// ── 1.6 Spoofed Records (RRs) ─────────────────────────────────────────
	if hasRRs {
		// handleSpoofedRecords may organically wrap 'w' or update '*q' natively.
		// If it returns true, the query has been successfully intercepted and delivered.
		var intercepted bool
		intercepted, spoofedAlias = handleSpoofedRecords(&w, r, &q, &qNameTrimmed, clientGroup, clientID, protocol, bypassGlobal)
		if intercepted {
			return
		}
	}

	// ── 1.8 Custom Rules Engine ───────────────────────────────────────────
	// Evaluate Custom Rules against the ORIGINAL requested domain natively,
	// rather than the spoofed alias target. Guarantees that explicit ALLOW/BLOCK
	// overrides configured by the admin are accurately enforced before RRs alias mappings.
	ruleAction, ruleMatch := CheckRules(originalQNameTrimmed, clientGroup)

	if ruleAction == "BLOCK" {
		IncrPolicyBlock()
		reason := "Custom Rule (" + ruleMatch + ")"
		if clientGroup != "" && clientGroup != "global" {
			reason += " [" + clientGroup + "]"
		}
		RecordBlockEvent(clientIP, originalQNameTrimmed, reason)

		if globalBlockAction == BlockActionDrop {
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE DROP | DROP", protocol, clientID, originalQName, dns.TypeToString[q.Qtype])
			}
			return
		} else if globalBlockAction == BlockActionLog {
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE BLOCK (LOG ONLY) | %s", protocol, clientID, originalQName, dns.TypeToString[q.Qtype], getBlockActionLogStr(q.Qtype))
			}
		} else {
			resp := generateBlockMsg(r, syntheticTTL)
			w.WriteMsg(resp)
			msgPool.Put(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE BLOCK | %s", protocol, clientID, originalQName, dns.TypeToString[q.Qtype], getBlockActionLogStr(q.Qtype))
			}
			return
		}
	}

	bypassPolicies := (ruleAction == "ALLOW")
	if bypassPolicies && logQueries {
		log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE ALLOW | Bypassing policies", protocol, clientID, originalQName, dns.TypeToString[q.Qtype])
	}

	// ── 2. Routing Engine ─────────────────────────────────────────────────
	// [SECURITY/FIX] Execute deterministic routing using both the evaluated target
	// AND the originally requested domain to preserve reporting integrity post-spoofing.
	routeCtx, intercepted := determineRouting(w, r, q, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP, clientAddr, clientMAC, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, bypassPolicies, bypassGlobal, clientRoute, clientRouteMatched, routeOriginType)
	if intercepted {
		return
	}

	if routeCtx.clientName != clientName {
		clientName = routeCtx.clientName

		// Align optimized variables to the actively resolved Identity bounds natively
		clientNameLower = ""
		if clientName != "" {
			clientNameLower = strings.ToLower(clientName)
		}

		clientID = buildClientID(clientIP, clientName, clientAddr)

		// Map identities cleanly if structural overrides modified the client profile upstream
		sk, clientGroup = ResolveStateKeyAndGroup(clientMAC, clientIP, clientAddr, clientName, clientNameLower, sni, sniLower, path, pathLower)
	}

	// ── 3. Parental Controls ──────────────────────────────────────────────
	var parentalForcedTTL uint32
	var parentalReason string
	var parentalCategory string
	var parentalMatchedApex string

	if hasParental && (clientMAC != "" || clientIP != "" || clientName != "" || sni != "" || path != "") {
		checkTarget := qNameTrimmed
		isPTR := false
		var targetAddr netip.Addr

		if q.Qtype == dns.TypePTR {
			if extractedIP := extractIPFromPTR(qNameTrimmed); extractedIP != "" {
				if a, err := netip.ParseAddr(extractedIP); err == nil {
					targetAddr = a.Unmap()
					checkTarget = ""
				} else {
					checkTarget = extractedIP
				}
				isPTR = true
			}
		}

		blocked, blockTTL, forcedTTL, reason, cat, matchedApex := CheckParental(sk, clientGroup, clientMAC, clientIP, clientAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, checkTarget, targetAddr, false, bypassPolicies)
		if blocked {
			IncrParentalBlock()

			blockReason := reason
			if isPTR {
				ptrTarget := checkTarget
				if targetAddr.IsValid() {
					ptrTarget = targetAddr.String()
				}
				// [FIX 3.91.0] Matched brackets. This string is not log-only:
				// it is the reason recorded against the block event, so it is
				// what the Web UI renders and what an operator's log filters
				// have to match on.
				blockReason += " (PTR IP: " + ptrTarget + ")"
			}

			RecordBlockEvent(clientIP, originalQNameTrimmed, blockReason)

			if globalBlockAction == BlockActionDrop {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL DROP | DROP", protocol, clientID, originalQName, dns.TypeToString[q.Qtype])
				}
				return
			} else if globalBlockAction == BlockActionLog {
				if logQueries {
					catStr := ""
					if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, apex: %s)", cat, matchedApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK (LOG ONLY)%s | %s",
						protocol, clientID, originalQName, dns.TypeToString[q.Qtype], catStr, getBlockActionLogStr(q.Qtype))
				}
			} else {
				resp := generateBlockMsg(r, blockTTL)
				w.WriteMsg(resp)

				if logQueries {
					rcodeStr := getBlockActionLogStr(q.Qtype)
					catStr := ""
					if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, apex: %s)", cat, matchedApex)
					}

					ptrLogStr := ""
					if isPTR {
						ptrTarget := checkTarget
						if targetAddr.IsValid() {
							ptrTarget = targetAddr.String()
						}
						ptrLogStr = " [PTR Target IP: " + ptrTarget + "]"
					}

					log.Printf("[DNS] [%s] %s -> %s %s%s | PARENTAL BLOCK%s | %s",
						protocol, clientID,
						originalQName, dns.TypeToString[q.Qtype], ptrLogStr, catStr, rcodeStr)
				}
				msgPool.Put(resp)
				return
			}
		}
		parentalForcedTTL = forcedTTL
		parentalReason = reason
		parentalCategory = cat
		parentalMatchedApex = matchedApex
	} else {
		IncrGroup("default")
	}

	// ── 3.5 Assemble the query context ────────────────────────────────────
	// Everything above operates on locals because it is building the values the
	// context is made of. From here down the pipeline is stage calls, and the
	// context is what they share.
	qc := &queryCtx{
		w: w, r: r, q: q,

		qNameTrimmed:         qNameTrimmed,
		originalQName:        originalQName,
		originalQNameTrimmed: originalQNameTrimmed,
		originalID:           originalID,
		doBit:                doBit,

		clientIP:        clientIP,
		clientAddr:      clientAddr,
		clientMAC:       clientMAC,
		clientName:      clientName,
		clientNameLower: clientNameLower,
		clientID:        clientID,

		protocol:  protocol,
		sni:       sni,
		sniLower:  sniLower,
		path:      path,
		pathLower: pathLower,

		sk:          sk,
		clientGroup: clientGroup,

		bypassGlobal:   bypassGlobal,
		bypassPolicies: bypassPolicies,
		spoofedAlias:   spoofedAlias,

		route: routeCtx,

		parentalForcedTTL:   parentalForcedTTL,
		parentalReason:      parentalReason,
		parentalCategory:    parentalCategory,
		parentalMatchedApex: parentalMatchedApex,
	}

	// ── 4. Cache lookup ───────────────────────────────────────────────────
	// deriveCacheKey must run even on a miss: the key is reused by the policy
	// exits, local identity and the upstream stage to store synthetic entries.
	// It also resolves and stores the effective upstream group (qc.group), which
	// is what guarantees the key and the eventual dial describe the same group —
	// see process_cachehit.go 1.1.0.
	qc.deriveCacheKey()
	if qc.serveFromCache() {
		return
	}

	// ── 5. Policy exits ───────────────────────────────────────────────────
	if !qc.bypassPolicies && !qc.bypassGlobal && handlePolicyExits(qc.w, qc.r, qc.q, qc.qNameTrimmed, qc.clientIP, qc.clientID, qc.protocol, qc.cacheKey, qc.originalQName, qc.originalQNameTrimmed, qc.spoofedAlias) {
		return
	}

	// ── 6. Local A/AAAA/PTR answers ───────────────────────────────────────
	if handleLocalIdentity(qc.w, qc.r, qc.q, qc.qNameTrimmed, qc.clientID, qc.clientIP, qc.protocol, qc.route.routeName, qc.route.routeOriginType, qc.route.bypassLocal, qc.cacheKey, qc.parentalForcedTTL, qc.originalQName, qc.spoofedAlias) {
		return
	}

	// ── 6.5 Strict PTR Leakage Prevention ─────────────────────────────────
	if cfg.Server.StrictPTR && qc.q.Qtype == dns.TypePTR && !qc.bypassPolicies && !qc.bypassGlobal {
		if ipStr := extractIPFromPTR(qc.qNameTrimmed); ipStr != "" {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				// [SECURITY/FIX] Sinkhole RFC1918/Local Reverse PTR queries dynamically.
				// If a private PTR query wasn't resolved internally by `handleLocalIdentity`,
				// intercepting it here prevents transmitting internal LAN topologies
				// blindly to public upstream providers natively.
				if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
					IncrPolicyBlock()
					RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, "Strict PTR (LAN Leakage Prevention)")

					dropped := writePolicyAction(qc.w, qc.r, dns.RcodeNameError)

					if cacheSynthFlag && !dropped && globalBlockAction != BlockActionDrop {
						synthMsg := buildSynthCacheMsg(qc.q, dns.RcodeNameError)
						CacheSetSynth(qc.cacheKey, synthMsg)
						msgPool.Put(synthMsg)
					}

					if logQueries {
						statusMark := "POLICY BLOCK"
						if dropped {
							statusMark = "POLICY DROP"
						}
						statusMark = qc.annotateAlias(statusMark)
						log.Printf("[DNS] [%s] %s -> %s PTR | %s (Strict PTR Leakage) | NXDOMAIN",
							qc.protocol, qc.clientID, qc.originalQName, statusMark)
					}
					return
				}
			}
		}
	}

	// ── 7. Upstream group resolution & QNAME label bounds ─────────────────
	if !qc.resolveUpstreamGroup() {
		return
	}
	if qc.enforceQnameLabelBounds() {
		return
	}

	// ── 8. Upstream exchange ──────────────────────────────────────────────
	qc.serveFromUpstream()
}
