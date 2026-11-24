/*
File:    process.go
Version: 3.157.0
Last Updated: 18-Nov-2026 16:00 CET

Description:
  Master orchestrator for the sdproxy per-query DNS resolution pipeline.

Changes:
  3.157.0 - [SECURITY/FIX] Re-evaluated group-specific `rrs:` in Step 1.6
            (`handleSpoofedRecords`) whenever a global `rrs:` CNAME alias
            rewrote `qNameTrimmed`, and ensured `ResolveStateKeyAndGroup` is
            consistent before Step 1.8 (`CheckRules`).
  3.156.0 - [SECURITY/FIX] Re-evaluated `ResolveStateKeyAndGroup` (`sk`, `clientGroup`)
            after `handleSpoofedRecords` whenever a global `rrs:` CNAME alias
            happened to match the initial query and rewrote `qNameTrimmed`, and
            verified whether the client's parental `clientGroup` has its own
            group-specific `rrs:` targeting the rewritten domain (up to 4 hops).
  3.155.0 - [CLEANUP] Removed unreachable dead code in Step 2 (`if routeCtx.clientName != "" && routeCtx.clientName != clientName`).
            Because the 3-hop `resolveClientRoute` loop prior to Step 1.6 already
            resolves all `client_name` overrides to a fixed point and passes the
            resolved `clientName` and `clientRoute` into `determineRouting`,
            `routeCtx.clientName` is always identical to `clientName` on return.
  3.154.0 - [SECURITY/FIX] Executed `handleSpoofedRecords` (`hasRRs`) inside
            Step 1.6 whenever a client route (`resolveClientRoute`) overrides
            `clientName` and assigns the client to a new parental `clientGroup`
            with group-specific `rrs:`. Previously, if `determineRouting` did
            not further change `routeCtx.clientName`, group `rrs:` were only
            evaluated against the pre-override `clientGroup`.
  3.153.0 - [SECURITY/FIX] Added `lateForce` and `lateBypassLocal` propagation
            across multi-hop `resolveClientRoute` loops in `ProcessDNS`.
  3.152.0 - [SECURITY/FIX] Prevented an unforced `client_name` route (`!crNext.Force`)
            from overriding `HasRcode`, `BypassLocal`, or `BypassGlobal` on a
            higher-precedence `force: true` route (`clientRoute.Force == true`)
            during multi-hop `client_name` resolution in `ProcessDNS`.
  3.151.0 - [SECURITY/FIX] Re-evaluated `routeCtx.routeName` and `routeCtx.routeIdx`
            against `domainRoutes` (`walkDomainMaps`) when a late group `rrs:`
            CNAME rewrite (`lateQNameChanged`) changes `qNameTrimmed` from a
            domain that previously matched a `domain_routes` entry to an alias
            that does not match `domain_routes`.
  3.150.0 - [REFACTOR/FIX] Consolidated multi-hop `client_name` override
            propagation in `ProcessDNS` into bounded 3-hop resolution loops
            for both the initial client-route lookup and the post-`determineRouting`
            late client-route lookup.
  3.149.0 - [SECURITY/FIX] Added third-hop `ClientName` propagation and
            `resolveClientRoute` (`crLate3`) lookup inside `ProcessDNS`.
  3.148.0 - [SECURITY/FIX] Implemented a second-hop `resolveClientRoute` (`crLate2`)
            pass inside `ProcessDNS`.
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

func mergeClientRouteAttrs(dst *ParsedRoute, src ParsedRoute) {
	if dst.Upstream == "" && src.Upstream != "" && !dst.HasRcode {
		dst.Upstream = src.Upstream
	}
	if !dst.HasRcode && src.HasRcode {
		dst.HasRcode = true
		dst.Rcode = src.Rcode
	}
	if !dst.BypassLocal && src.BypassLocal {
		dst.BypassLocal = true
	}
	if !dst.BypassGlobal && src.BypassGlobal {
		dst.BypassGlobal = true
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

	for hop := 0; hop < 3 && clientRouteMatched && clientRoute.ClientName != "" && clientRoute.ClientName != clientName; hop++ {
		clientName = clientRoute.ClientName
		clientNameLower = strings.ToLower(clientName)
		clientID = appendClientEDNS(buildClientID(clientIP, clientName, clientAddr), ecsAddr, ecsPrefix, ednsMAC)
		sk, clientGroup = ResolveStateKeyAndGroup(clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, ecsPrefix, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort)

		crNext, okNext, origNext := resolveClientRoute(clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, ecsPrefix, clientNameLower, sniLower, pathLower, localPort)
		if !okNext {
			break
		}
		if crNext.Force && (!clientRoute.Force || origNext == "CLIENT-NAME") {
			if crNext.ClientName == "" {
				crNext.ClientName = clientName
			}
			mergeClientRouteAttrs(&crNext, clientRoute)
			clientRoute, clientRouteMatched, routeOriginType = crNext, okNext, origNext
		} else {
			if !clientRoute.Force {
				mergeClientRouteAttrs(&clientRoute, crNext)
				if crNext.ClientName != "" && crNext.ClientName != clientName {
					clientRoute.ClientName = crNext.ClientName
					bypassGlobal = clientRoute.BypassGlobal
					continue
				}
			} else if clientRoute.Upstream == "" && crNext.Upstream != "" && !clientRoute.HasRcode {
				clientRoute.Upstream = crNext.Upstream
			}
			bypassGlobal = clientRoute.BypassGlobal
			break
		}
		bypassGlobal = clientRoute.BypassGlobal
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
		for rrHop := 0; rrHop < 4; rrHop++ {
			prevQName := qNameTrimmed
			intercepted, alias := handleSpoofedRecords(&w, r, &q, &qNameTrimmed, clientGroup, clientIP, clientID, protocol, protoEndpoint, bypassGlobal)
			if intercepted {
				return
			}
			if alias != "" {
				spoofedAlias = alias
			}
			if qNameTrimmed == prevQName {
				break
			}
			if handleDDR(w, r, q, qNameTrimmed, clientIP, clientID, protocol, protoEndpoint) {
				return
			}
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
			if logQueries {
				if logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE BLOCK (LOG ONLY): %s",
						protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), reason)
				} else {
					log.Printf("[DNS] [%s] %s -> %s %s | CUSTOM RULE BLOCK (LOG ONLY) | %s", protocol, clientID, originalQName, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype))
				}
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

	if hasParental && (sk != "" || clientGroup != "" || clientMAC != "" || ednsMAC != "" || clientIP != "" || ecsAddr.IsValid() || clientName != "" || sni != "" || path != "" || localPort != "") {
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
				if logQueries {
					if logSimple {
						log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK (LOG ONLY): %s",
							protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), blockReason)
					} else {
						catStr := ""
						if cat != "" {
							catStr = fmt.Sprintf(" (Category: %s, apex: %s)", cat, matchedApex)
						}
						log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK (LOG ONLY)%s | %s",
							protocol, clientID, originalQName, qtypeName(q.Qtype), catStr, getBlockActionLogStr(q.Qtype))
					}
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

	// ── 3.55 IDN Homograph, Punycode/ACE & Brand Impersonation ────────────
	if qc.enforceIDNHomographCheck() {
		return
	}

	// ── 3.6 Immediate Cached RFC 10023 "_for-sale." Parent/Apex Check ─────
	if qc.enforceForSaleCachedOnly() {
		return
	}

	// ── 3.65 Immediate Cached Parked Parent/Apex Check ────────────────────
	if qc.enforceParkedCachedOnly() {
		return
	}

	// ── 3.7 Immediate Cached RFC Compliance Parent/Apex Check ─────────────
	if qc.enforceRFCComplianceCachedOnly() {
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

	// ── 7.7 RFC compliance & NS CNAME indirection check (on miss) ─────────
	if qc.enforceRFCComplianceCheck() {
		return
	}

	// ── 8. Upstream exchange ──────────────────────────────────────────────
	qc.serveFromUpstream()
}
