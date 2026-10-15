/*
File:    process.go
Version: 3.97.0
Last Updated: 15-Oct-2026 18:35 CEST

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
  3.97.0 - [FIX] Stored `localPort` in `queryCtx` and passed it to `CheckParental`
           so port-identified clients in `device` budget tracking mode have a valid
           device key across all pipeline stages.
  3.96.0 - [FEAT/FIX] Propagated `localPort` into `ResolveStateKeyAndGroup` so
           `port:` and `force-and` parental group routes evaluate accurately,
           and allowed `hasParental` checks to run for port-identified clients.
  3.95.0 - [SECURITY/FIX] Addressed an undeclared memory leak within the error 
           handling branches natively. Explicitly enforced `msgPool.Put()` returns 
           on all synthetic block generations constructed during panic handling and 
           validation short-circuits.
  3.94.0 - [SECURITY/FIX] Passed `localPort` to `enforceSecurityGuards` dynamically
           so that the `clientRoute` extraction occurring later in the pipeline natively
           benefits from fully pre-parsed port boundaries.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP, protocol, sni, path string) {
	var clientAddr netip.Addr

	if clientIP != "" {
		if a, err := netip.ParseAddr(clientIP); err == nil {
			clientAddr = a.Unmap().WithZone("") // Cleanse interface indexes natively

			if clientAddr != a {
				clientIP = clientAddr.String()
			}

			if clientAddr.IsValid() && (clientAddr.IsMulticast() || clientAddr.IsUnspecified() || (clientAddr.Is4() && clientAddr.As4() == [4]byte{255, 255, 255, 255})) {
				IncrDroppedRateLimit()
				return
			}
		}
	}

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[PANIC] Recovered in ProcessDNS (%s / %s): %v", protocol, clientIP, rec)

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

	var localPort string
	if w.LocalAddr() != nil {
		if _, p, err := net.SplitHostPort(w.LocalAddr().String()); err == nil {
			localPort = p
		} else {
			if p, err := strconv.ParseUint(w.LocalAddr().String(), 10, 16); err == nil {
				localPort = strconv.FormatUint(p, 10)
			}
		}
	}

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
	if enforceSecurityGuards(w, r, q, originalQNameTrimmed, clientIP, clientAddr, clientMAC, clientName, clientID, protocol, localPort) {
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

	sk, clientGroup := ResolveStateKeyAndGroup(clientMAC, clientIP, clientAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort)

	clientRoute, clientRouteMatched, routeOriginType := resolveClientRoute(clientMAC, clientIP, clientAddr, clientNameLower, sniLower, pathLower, localPort)
	bypassGlobal := clientRouteMatched && clientRoute.BypassGlobal

	if clientRouteMatched && clientRoute.ClientName != "" && clientRoute.ClientName != clientName {
		effectiveClientName := clientRoute.ClientName
		effectiveClientNameLower := strings.ToLower(effectiveClientName)
		sk, clientGroup = ResolveStateKeyAndGroup(clientMAC, clientIP, clientAddr, effectiveClientName, effectiveClientNameLower, sni, sniLower, path, pathLower, localPort)
	}

	var spoofedAlias string

	// ── 1.6 Spoofed Records (RRs) ─────────────────────────────────────────
	if hasRRs {
		var intercepted bool
		intercepted, spoofedAlias = handleSpoofedRecords(&w, r, &q, &qNameTrimmed, clientGroup, clientID, protocol, bypassGlobal)
		if intercepted {
			return
		}
	}

	// ── 1.8 Custom Rules Engine ───────────────────────────────────────────
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
	routeCtx, intercepted := determineRouting(w, r, q, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP, clientAddr, clientMAC, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, localPort, bypassPolicies, bypassGlobal, clientRoute, clientRouteMatched, routeOriginType)
	if intercepted {
		return
	}

	if routeCtx.clientName != clientName {
		clientName = routeCtx.clientName

		clientNameLower = ""
		if clientName != "" {
			clientNameLower = strings.ToLower(clientName)
		}

		clientID = buildClientID(clientIP, clientName, clientAddr)
		sk, clientGroup = ResolveStateKeyAndGroup(clientMAC, clientIP, clientAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort)
	}

	// ── 3. Parental Controls ──────────────────────────────────────────────
	var parentalForcedTTL uint32
	var parentalReason string
	var parentalCategory string
	var parentalMatchedApex string

	if hasParental && (clientMAC != "" || clientIP != "" || clientName != "" || sni != "" || path != "" || localPort != "") {
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

		blocked, blockTTL, forcedTTL, reason, cat, matchedApex := CheckParental(sk, clientGroup, clientMAC, clientIP, clientAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort, checkTarget, targetAddr, false, bypassPolicies)
		if blocked {
			IncrParentalBlock()

			blockReason := reason
			if isPTR {
				ptrTarget := checkTarget
				if targetAddr.IsValid() {
					ptrTarget = targetAddr.String()
				}
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
		localPort: localPort,

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
