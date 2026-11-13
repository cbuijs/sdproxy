/*
File:    process.go
Version: 3.125.0
Last Updated: 13-Nov-2026 12:35 CET

Description:
  Master orchestrator for the sdproxy per-query DNS resolution pipeline.

Changes:
  3.125.0 - [SECURITY/FIX] Preserved non-empty `Upstream`, `HasRcode`/`Rcode`,
            `BypassLocal`, and `BypassGlobal` fields from the primary route when
            a `client_name` override triggers a secondary `cr2` match with
            `cr2.Force == true` that leaves those fields unset.
  3.124.0 - [SECURITY/FIX] Re-evaluated `clientGroup` upstream/bypass_local
            fallback in `ProcessDNS` unconditionally after a `client_name`
            override re-runs `ResolveStateKeyAndGroup`, even when the initial
            route had `force: true` and `upstream: ""`.
  3.123.0 - [SECURITY/FIX] Re-evaluated `resolveClientRoute` unconditionally when
            a matched client route overrides `client_name`. Previously, when a
            higher-precedence route (e.g., IP or CIDR) set `client_name: "alice"`
            without setting `upstream` or `rcode`, a `client-name` route for `"alice"`
            with `force: false` was ignored because `resolveClientRoute` was only
            accepted when `cr2.Force` was true, and merged `cr2`'s `Upstream`,
            `HasRcode`/`Rcode`, `BypassLocal`, and `BypassGlobal` into `clientRoute`.
  3.122.0 - [CLEANUP] Removed unused `localPort` parameter from `enforceSecurityGuards`
            and unused `clientMAC`, `clientNameLower`, `sni`, `sniLower`, `path`,
            `pathLower`, and `localPort` parameters from `determineRouting`.
  3.121.0 - [SECURITY/FIX] Re-evaluated per-group `handleSpoofedRecords` (`rrs:`)
            after `ResolveStateKeyAndGroup` when a client route's `client_name`
            override assigns the client to a parental group after global `rrs:`
            already ran, and verified `walkDomainMaps` against `originalQNameTrimmed`
            as well as `qNameTrimmed` in `determineRouting` so a global `rrs:` CNAME
            rewrite cannot bypass a `domain_policy` block on the original queried
            domain.
  3.120.0 - [CLEANUP] Removed unreachable step 2 `routeCtx.clientName != clientName`
            re-evaluation block.
  3.119.0 - [SECURITY/FIX] Re-evaluated per-group `handleSpoofedRecords` (`rrs:`),
            Custom Rules (`CheckRules`), and `determineRouting` in step 2 whenever
            a client route's `client_name` override changes `clientGroup`.
  3.118.0 - [SECURITY/FIX] Re-evaluated `CheckParental` against `qNameTrimmed`
            in step 2 even when the original query was a `PTR` query if a group
            `rrs:` CNAME alias rewrote `qNameTrimmed` to a domain target.
  3.117.0 - [SECURITY/FIX] Permitted per-group `rrs:` evaluation in step 2 when
            a client route's `client_name` override changes `clientGroup`.
  3.116.0 - [SECURITY/FIX] Re-evaluated `determineRouting` when a client route's
            `client_name` override in step 2 changes `clientGroup`.
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

func recordBlockMsgStats(resp *dns.Msg, qNameTrimmed string) {
	if resp == nil {
		return
	}
	isNull := false
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if a.A.IsUnspecified() {
				isNull = true
			}
		case *dns.AAAA:
			if a.AAAA.IsUnspecified() {
				isNull = true
			}
		}
	}
	IncrReturnCode(resp.Rcode, isNull)
	if resp.Rcode == dns.RcodeNameError && qNameTrimmed != "" {
		IncrNXDomain(qNameTrimmed)
	}
}

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP, protocol, sni, path string) {
	var clientAddr netip.Addr

	if clientIP != "" {
		if a, err := netip.ParseAddr(clientIP); err == nil {
			clientAddr = a.Unmap().WithZone("")

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
					IncrReturnCode(dns.RcodeServerFailure, false)
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

	originalID := r.Id
	doBit := false
	var ecsAddr netip.Addr
	var ecsPrefix netip.Prefix
	var ednsMAC string
	trustedForwarder := isTrustedProxy(clientAddr)
	if !cfg.Server.AllowCDBit && !trustedForwarder {
		r.CheckingDisabled = false
	}
	if opt := r.IsEdns0(); opt != nil {
		doBit = opt.Do()
		if trustedForwarder {
			for _, o := range opt.Option {
				switch v := o.(type) {
				case *dns.EDNS0_SUBNET:
					if !ecsAddr.IsValid() && v.Address != nil {
						if addr, ok := netip.AddrFromSlice(v.Address); ok {
							ecsAddr = addr.Unmap()
							bits := int(v.SourceNetmask)
							maxBits := 128
							if ecsAddr.Is4() {
								maxBits = 32
							}
							if bits >= 0 && bits <= maxBits {
								if p, err := ecsAddr.Prefix(bits); err == nil {
									ecsPrefix = p.Masked()
								}
							}
						}
					}
				case *dns.EDNS0_LOCAL:
					if v.Code == edns0OptMAC && ednsMAC == "" {
						ednsMAC = parseEDNS0MAC(v.Data)
					}
				}
			}
		}
	}

	clientMAC := LookupMAC(clientIP)
	lookupMAC := clientMAC
	if lookupMAC == "" {
		lookupMAC = ednsMAC
	}
	clientName := LookupNameByMACOrIP(lookupMAC, clientIP)

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

	protoEndpoint := formatProtoEndpoint(protocol, localPort, path)

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

	clientID := appendClientEDNS(buildClientID(clientIP, clientName, clientAddr), ecsAddr, ecsPrefix, ednsMAC)

	// ── 1. Security & Admission ───────────────────────────────────────────
	if enforceSecurityGuards(w, r, q, originalQNameTrimmed, clientIP, clientAddr, clientMAC, ednsMAC, clientName, clientID, protocol, protoEndpoint) {
		return
	}

	// ── 1.5 DDR interception ──────────────────────────────────────────────
	if handleDDR(w, r, q, originalQNameTrimmed, clientIP, clientID, protocol, protoEndpoint) {
		return
	}

	sk, clientGroup := ResolveStateKeyAndGroup(clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, ecsPrefix, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort)

	clientRoute, clientRouteMatched, routeOriginType := resolveClientRoute(clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, ecsPrefix, clientNameLower, sniLower, pathLower, localPort)
	bypassGlobal := clientRouteMatched && clientRoute.BypassGlobal

	if clientRouteMatched && clientRoute.ClientName != "" && clientRoute.ClientName != clientName {
		clientName = clientRoute.ClientName
		clientNameLower = strings.ToLower(clientName)
		clientID = appendClientEDNS(buildClientID(clientIP, clientName, clientAddr), ecsAddr, ecsPrefix, ednsMAC)
		sk, clientGroup = ResolveStateKeyAndGroup(clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, ecsPrefix, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort)
		if !clientRoute.Force {
			if cr2, ok2, orig2 := resolveClientRoute(clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, ecsPrefix, clientNameLower, sniLower, pathLower, localPort); ok2 {
				if cr2.Force {
					if cr2.ClientName == "" {
						cr2.ClientName = clientName
					}
					if cr2.Upstream == "" && clientRoute.Upstream != "" && !cr2.HasRcode {
						cr2.Upstream = clientRoute.Upstream
					}
					if !cr2.HasRcode && clientRoute.HasRcode {
						cr2.HasRcode = true
						cr2.Rcode = clientRoute.Rcode
					}
					if !cr2.BypassLocal && clientRoute.BypassLocal {
						cr2.BypassLocal = true
					}
					if !cr2.BypassGlobal && clientRoute.BypassGlobal {
						cr2.BypassGlobal = true
					}
					clientRoute, clientRouteMatched, routeOriginType = cr2, ok2, orig2
				} else {
					if clientRoute.Upstream == "" && cr2.Upstream != "" {
						clientRoute.Upstream = cr2.Upstream
					}
					if !clientRoute.HasRcode && cr2.HasRcode {
						clientRoute.HasRcode = true
						clientRoute.Rcode = cr2.Rcode
					}
					if !clientRoute.BypassLocal && cr2.BypassLocal {
						clientRoute.BypassLocal = true
					}
					if !clientRoute.BypassGlobal && cr2.BypassGlobal {
						clientRoute.BypassGlobal = true
					}
				}
				bypassGlobal = clientRoute.BypassGlobal
			}
		}
	}
	if clientRouteMatched && clientRoute.Upstream == "" && clientGroup != "" && !clientRoute.HasRcode {
		if grp, ok := cfg.Groups[clientGroup]; ok {
			if grp.Upstream != "" {
				clientRoute.Upstream = grp.Upstream
			}
			if !clientRoute.BypassLocal && grp.BypassLocal {
				clientRoute.BypassLocal = true
			}
		}
	}

	var spoofedAlias string

	// ── 1.6 Spoofed Records (RRs) ─────────────────────────────────────────
	if hasRRs {
		var intercepted bool
		intercepted, spoofedAlias = handleSpoofedRecords(&w, r, &q, &qNameTrimmed, clientGroup, clientIP, clientID, protocol, protoEndpoint, bypassGlobal)
		if intercepted {
			return
		}
	}

	// ── 1.8 Custom Rules Engine ───────────────────────────────────────────
	ruleAction, ruleMatch := CheckRules(originalQNameTrimmed, clientGroup)
	if ruleAction == "" && qNameTrimmed != originalQNameTrimmed {
		ruleAction, ruleMatch = CheckRules(qNameTrimmed, clientGroup)
	}

	if ruleAction == "BLOCK" {
		IncrPolicyBlock()
		reason := "Custom Rule (" + ruleMatch + ")"
		if clientGroup != "" && clientGroup != "global" {
			reason += " [" + clientGroup + "]"
		}
		RecordBlockEvent(clientIP, originalQNameTrimmed, reason)

		if globalBlockAction == BlockActionDrop {
			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), "DROP", reason, false)
				} else {
					log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE DROP | DROP", protocol, clientID, originalQName, qtypeName(q.Qtype))
				}
			}
			return
		} else if globalBlockAction == BlockActionLog {
			if logQueries && !logSimple {
				log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE BLOCK (LOG ONLY) | %s", protocol, clientID, originalQName, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype))
			}
		} else {
			resp := generateBlockMsg(r, syntheticTTL)
			recordBlockMsgStats(resp, originalQNameTrimmed)
			enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
			w.WriteMsg(resp)
			msgPool.Put(resp)
			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype), reason, false)
				} else {
					log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE BLOCK | %s", protocol, clientID, originalQName, qtypeName(q.Qtype))
				}
			}
			return
		}
	}

	bypassPolicies := (ruleAction == "ALLOW")
	if bypassPolicies && logQueries && !logSimple {
		log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE ALLOW | Bypassing policies", protocol, clientID, originalQName, qtypeName(q.Qtype))
	}

	// ── 2. Routing Engine ─────────────────────────────────────────────────
	routeCtx, intercepted := determineRouting(w, r, q, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP, clientAddr, ecsAddr, ecsPrefix, ednsMAC, clientName, clientID, protocol, protoEndpoint, bypassPolicies, bypassGlobal, clientRoute, clientRouteMatched, routeOriginType)
	if intercepted {
		return
	}

	// ── 3. Parental Controls ──────────────────────────────────────────────
	var parentalForcedTTL uint32
	var parentalReason string
	var parentalCategory string
	var parentalMatchedApex string

	if hasParental && (clientMAC != "" || ednsMAC != "" || clientIP != "" || ecsAddr.IsValid() || clientName != "" || sni != "" || path != "" || localPort != "") {
		checkTarget := originalQNameTrimmed
		isPTR := false
		var targetAddr netip.Addr

		if q.Qtype == dns.TypePTR {
			if extractedIP := extractIPFromPTR(originalQNameTrimmed); extractedIP != "" {
				if a, err := netip.ParseAddr(extractedIP); err == nil {
					targetAddr = a.Unmap()
					checkTarget = ""
				} else {
					checkTarget = extractedIP
				}
				isPTR = true
			}
		}

		blocked, blockTTL, forcedTTL, reason, cat, matchedApex := CheckParental(sk, clientGroup, clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort, checkTarget, targetAddr, false, bypassPolicies)
		if !blocked && qNameTrimmed != originalQNameTrimmed {
			b2, btl2, ftl2, r2, c2, ma2 := CheckParental(sk, clientGroup, clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort, qNameTrimmed, netip.Addr{}, true, bypassPolicies)
			if b2 {
				blocked, blockTTL, forcedTTL, reason, cat, matchedApex = b2, btl2, ftl2, r2, c2, ma2
				isPTR = false
			} else if c2 != "" && cat == "" {
				forcedTTL, reason, cat, matchedApex = ftl2, r2, c2, ma2
			}
		}
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
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), "DROP", "Parental ("+blockReason+")", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL DROP | DROP", protocol, clientID, originalQName, qtypeName(q.Qtype))
					}
				}
				return
			} else if globalBlockAction == BlockActionLog {
				if logQueries && !logSimple {
					catStr := ""
					if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, apex: %s)", cat, matchedApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK (LOG ONLY)%s | %s",
						protocol, clientID, originalQName, qtypeName(q.Qtype), catStr, getBlockActionLogStr(q.Qtype))
				}
			} else {
				resp := generateBlockMsg(r, blockTTL)
				recordBlockMsgStats(resp, originalQNameTrimmed)
				enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
				w.WriteMsg(resp)

				if logQueries {
					rcodeStr := getBlockActionLogStr(q.Qtype)
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), rcodeStr, "Parental ("+blockReason+")", false)
					} else {
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
							originalQName, qtypeName(q.Qtype), ptrLogStr, catStr, rcodeStr)
					}
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
		ecsAddr:         ecsAddr,
		ecsPrefix:       ecsPrefix,
		clientMAC:       clientMAC,
		ednsMAC:         ednsMAC,
		clientName:      clientName,
		clientNameLower: clientNameLower,
		clientID:        clientID,

		protocol:      protocol,
		protoEndpoint: protoEndpoint,
		sni:           sni,
		sniLower:      sniLower,
		path:          path,
		pathLower:     pathLower,
		localPort:     localPort,

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

	qc.deriveCacheKey()

	// ── 3.6 Immediate Cached RFC 10023 "_for-sale." Parent/Apex Check ─────
	if qc.enforceForSaleCachedOnly() {
		return
	}

	// ── 3.65 Immediate Cached Parked Parent/Apex Check ────────────────────
	if qc.enforceParkedCachedOnly() {
		return
	}

	// ── 4. Cache lookup ───────────────────────────────────────────────────
	if qc.serveFromCache() {
		return
	}

	// ── 5. Policy exits ───────────────────────────────────────────────────
	if !qc.bypassPolicies && !qc.bypassGlobal && handlePolicyExits(qc.w, qc.r, qc.q, qc.qNameTrimmed, qc.clientIP, qc.clientID, qc.protocol, qc.protoEndpoint, qc.cacheKey, qc.originalQName, qc.originalQNameTrimmed, qc.spoofedAlias) {
		return
	}

	// ── 6. Local A/AAAA/PTR answers ───────────────────────────────────────
	if handleLocalIdentity(qc.w, qc.r, qc.q, qc.qNameTrimmed, qc.clientID, qc.clientIP, qc.protocol, qc.protoEndpoint, qc.route.routeName, qc.route.routeOriginType, qc.route.bypassLocal, qc.cacheKey, qc.parentalForcedTTL, qc.originalQName, qc.spoofedAlias) {
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
						synthMsg := buildSynthCacheMsg(qc.r, qc.q, dns.RcodeNameError)
						CacheSetSynth(qc.cacheKey, synthMsg)
						msgPool.Put(synthMsg)
					}

					if logQueries {
						if logSimple {
							rcStr := "NXDOMAIN"
							if dropped {
								rcStr = "DROP"
							}
							logQuerySimple(qc.protoEndpoint, clientIP, qc.originalQName, "PTR", rcStr, "Strict PTR", false)
						} else {
							statusMark := "POLICY BLOCK"
							if dropped {
								statusMark = "POLICY DROP"
							}
							statusMark = qc.annotateAlias(statusMark)
							log.Printf("[DNS] [%s] %s -> %s PTR | %s (Strict PTR Leakage) | NXDOMAIN",
								qc.protocol, qc.clientID, qc.originalQName, statusMark)
						}
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

	// ── 7.5 RFC 10023 "_for-sale." domain check (upstream probe on miss) ──
	if qc.enforceForSaleCheck() {
		return
	}

	// ── 7.6 Parked domain check (upstream NS/SOA/TXT probe on miss) ───────
	if qc.enforceParkedCheck() {
		return
	}

	// ── 8. Upstream exchange ──────────────────────────────────────────────
	qc.serveFromUpstream()
}
