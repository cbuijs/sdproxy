/*
File:    process.go
Version: 3.84.0
Updated: 12-Jun-2026 14:27 CEST

Description:
  Per-query DNS processing pipeline for sdproxy.
  Acts as the master core orchestrator for the resolution flow.

  The architecture has been modularized into highly focused execution units:
    - process_security.go (Admission, ACLs, DGA, Exfil, Anti-Amp)
    - process_routing.go  (Client and Domain Routing rules)
    - process_exchange.go (SingleFlight Upstream networking and mutations)
    - process_spoof.go    (Explicit Record Overrides and Aliasing)

Changes:
  3.84.0 - [PERF] Extracted and propagated `ResolveStateKeyAndGroup` natively. 
           Eradicates excessive map allocations and recursive routing arrays evaluated 
           across the DPI filters. The pipeline now natively maps the state key and group 
           exactly once, dramatically slashing GC memory pressure.
  3.83.0 - [PERF/FIX] Eradicated a redundant `dns.Msg.Copy()` heap allocation 
           during SingleFlight coalescing natively. The primary dialing goroutine 
           (`didUpstream`) now safely takes direct ownership of the pristine 
           unpacked network payload, drastically mitigating Garbage Collection (GC) 
           thrashing during massive cache-miss floods.
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
// ProcessDNS — The Master Core Pipeline
// ---------------------------------------------------------------------------
// Pipeline topological execution order guarantees optimized security and performance:
//
//  1. Panic Recovery & Admission Throttling (Limits Goroutines)
//  2. Anti-Spoofing & Pre-routing Security Guards (ACL, BPS Exfiltration, DGA, Anti-Amp)
//  3. DDR Interception (SVCB Discovery - Runs before Domain Policy intercepts)
//  4. Client Group Resolution (Routes mapping)
//  5. Spoofed Records (RRs) Interception (A/AAAA/CNAME overrides)
//  6. Custom Rules Engine
//  7. Route Determination (Domain suffixes vs MAC/IP/ASN routing constraints)
//  8. Parental Controls (Budget / Scheduling constraints)
//  9. Cache Retrieval (Serves payload natively if hit)
//  10. Policy Exits (RTYPE, FilterAAAA, Strict PTR, Obsolete Types)
//  11. Identity Subsystems (Local LAN Resolvers)
//  12. SingleFlight Coalescing & Upstream Exchange
func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP, protocol, sni, path string) {
	var clientAddr netip.Addr

	if clientIP != "" {
		if a, err := netip.ParseAddr(clientIP); err == nil {
			clientAddr = a.Unmap().WithZone("") // Cleanse interface indexes natively
			
			// [SECURITY/FIX] Forcefully normalize the global string representation natively.
			// Prevents protocol transports (TCP/DoH/DoQ) from passing IPv4-mapped-IPv6 strings 
			// (e.g., ::ffff:192.168.1.42) or Link-Local IPv6 Zones (e.g., fe80::1%eth0) 
			// down the pipeline. Ensures absolute alignment across Identity parsing, 
			// Exfiltration monitoring, and Analytic aggregations.
			clientIP = clientAddr.String()

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

	var spoofedAlias string

	// ── 1.6 Spoofed Records (RRs) ─────────────────────────────────────────
	if hasRRs {
		// handleSpoofedRecords may organically wrap 'w' or update '*q' natively.
		// If it returns true, the query has been successfully intercepted and delivered.
		var intercepted bool
		intercepted, spoofedAlias = handleSpoofedRecords(&w, r, &q, &qNameTrimmed, clientGroup, clientID, protocol)
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
	routeCtx, intercepted := determineRouting(w, r, q, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP, clientAddr, clientMAC, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, bypassPolicies)
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
				blockReason += " (PTR IP: " + ptrTarget + "]"
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

	// ── 4. Cache Lookup ───────────────────────────────────────────────────
	clientNameForCache := ""
	if grp, exists := routeUpstreams[routeCtx.routeName]; exists && grp.HasClientName {
		clientNameForCache = clientName
	}

	// [SECURITY/FIX] Dynamically extract ECS boundaries for cache isolation
	// Prevents cross-contamination of subnet-optimized upstream responses natively.
	// Extracts the precise IP and Netmask footprint from the EDNS0 envelope.
	ecsForCache := ""
	var clientSentECS bool
	var clientECSStr string
	if opt := r.IsEdns0(); opt != nil {
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
	
	if grp, exists := routeUpstreams[routeCtx.routeName]; exists {
		if grp.ECSAction == "add" && clientAddr.IsValid() {
			var m int
			if clientAddr.Is4() {
				m = grp.ECSV4Mask
			} else {
				m = grp.ECSV6Mask
			}
			prefix, _ := clientAddr.Prefix(m)
			ecsForCache = prefix.Masked().String()
		} else if grp.ECSAction == "pass" && clientSentECS {
			// [SECURITY/FIX] Passively forwarded ECS structures MUST inject their 
			// unique subnet topologies into the Cache Key cleanly natively.
			// Replaces the fatally flawed static "passed-ecs" identifier to ensure 
			// entirely different origin subnets do not share and hijack cache hits.
			if clientECSStr != "" {
				ecsForCache = clientECSStr
			} else {
				ecsForCache = "passed-ecs" // Fallback guard for unparseable arrays
			}
		}
	}

	cacheKey := DNSCacheKey{
		Name:       qNameTrimmed,
		ClientName: clientNameForCache,
		ECS:        ecsForCache,
		Qtype:      q.Qtype,
		Qclass:     q.Qclass,
		RouteIdx:   routeCtx.routeIdx,
		DoBit:      doBit,
		CdBit:      r.CheckingDisabled,
	}

	{
		poolMsg := msgPool.Get().(*dns.Msg)
		*poolMsg = dns.Msg{}
		if isStale, isPrefetch, cacheOK, _ := CacheGet(cacheKey, poolMsg); cacheOK {
			IncrCacheHit() 

			if cfg.Cache.AnswerSort != "none" {
				if applyAnswerSort(poolMsg, cfg.Cache.AnswerSort) {
					if cfg.Cache.AnswerSort != "random" {
						CacheUpdateOrder(cacheKey, poolMsg)
					}
				}
			}

			if parentalForcedTTL > 0 {
				CapResponseTTL(poolMsg, parentalForcedTTL)
			}
			poolMsg.Id = originalID

			if checkTargetNames(w, r, poolMsg, sk, clientGroup, clientMAC, clientIP, clientAddr, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, bypassPolicies, originalQName) {
				msgPool.Put(poolMsg)
				return
			}

			resp := transformResponse(poolMsg, q.Qtype, doBit, true)

			if filterResponseIPs(w, r, resp, sk, clientGroup, clientMAC, clientIP, clientAddr, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, bypassPolicies, originalQName, originalQNameTrimmed) {
				msgPool.Put(poolMsg)
				return
			}

			if filterRebinding(w, r, resp, clientIP, clientAddr, clientName, clientID, protocol, originalQName, originalQNameTrimmed) {
				msgPool.Put(poolMsg)
				return
			}
			
			isNullIP := responseContainsNullIP(resp)
			if isNullIP {
				RecordBlockEvent(clientIP, originalQNameTrimmed, "Cached NULL-IP ("+routeCtx.routeName+")") 
			}
			
			IncrReturnCode(resp.Rcode, isNullIP)
			if resp.Rcode == dns.RcodeNameError {
				IncrNXDomain(originalQNameTrimmed)
			}
			
			upstreamSize, clientAdvertised := enforceUDPDefenses(r, resp, protocol)

			w.WriteMsg(resp)
			
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
					status = fmt.Sprintf("CACHE HIT (Truncated TC=1, Upstream:%dB, Client:%dB) | %s", upstreamSize, clientAdvertised, rcodeStr)
				default:
					status = "CACHE HIT | " + rcodeStr
				}

				if parentalReason == "FREE" {
					if parentalCategory != "" {
						status += fmt.Sprintf(" (PARENTAL FREE: %s, apex: %s)", parentalCategory, parentalMatchedApex)
					} else {
						status += " (PARENTAL FREE)"
					}
				} else if parentalReason == "ALLOW" {
					if parentalCategory != "" {
						status += fmt.Sprintf(" (PARENTAL ALLOW: %s, apex: %s)", parentalCategory, parentalMatchedApex)
					} else {
						status += " (PARENTAL ALLOW)"
					}
				} else if parentalReason == "LOG" {
					if parentalCategory != "" {
						status += fmt.Sprintf(" (PARENTAL LOG: %s, apex: %s)", parentalCategory, parentalMatchedApex)
					} else {
						status += " (PARENTAL LOG)"
					}
				} else if parentalReason == "UNTRIGGER" {
					if parentalCategory != "" {
						status += fmt.Sprintf(" (PARENTAL UNTRIGGER: %s, apex: %s)", parentalCategory, parentalMatchedApex)
					} else {
						status += " (PARENTAL UNTRIGGER)"
					}
				} else if parentalCategory != "" {
					status += fmt.Sprintf(" (CATEGORY: %s, apex: %s)", parentalCategory, parentalMatchedApex)
				}
				
				if spoofedAlias != "" {
					status = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, status)
				}
				
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s",
					protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
					routeCtx.routeName, routeCtx.routeOriginType, status)
			}
			msgPool.Put(poolMsg)
			return
		}
		msgPool.Put(poolMsg)
	}

	// ── 5. Policy exits ───────────────────────────────────────────────────
	if !bypassPolicies && handlePolicyExits(w, r, q, qNameTrimmed, clientIP, clientID, protocol, cacheKey, originalQName, originalQNameTrimmed, spoofedAlias) {
		return
	}

	// ── 6. Local A/AAAA/PTR answers ───────────────────────────────────────
	if handleLocalIdentity(w, r, q, qNameTrimmed, clientID, clientIP, protocol, routeCtx.routeName, routeCtx.routeOriginType, routeCtx.bypassLocal, cacheKey, parentalForcedTTL, originalQName, spoofedAlias) {
		return
	}

	// ── 6.5 Strict PTR Leakage Prevention ─────────────────────────────────
	if cfg.Server.StrictPTR && q.Qtype == dns.TypePTR && !bypassPolicies {
		if ipStr := extractIPFromPTR(qNameTrimmed); ipStr != "" {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				// [SECURITY/FIX] Sinkhole RFC1918/Local Reverse PTR queries dynamically.
				// If a private PTR query wasn't resolved internally by `handleLocalIdentity`,
				// intercepting it here prevents transmitting internal LAN topologies 
				// blindly to public upstream providers natively.
				if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
					IncrPolicyBlock()
					RecordBlockEvent(clientIP, originalQNameTrimmed, "Strict PTR (LAN Leakage Prevention)")
					
					dropped := writePolicyAction(w, r, dns.RcodeNameError)
					
					if cacheSynthFlag && !dropped && globalBlockAction != BlockActionDrop {
						synthMsg := buildSynthCacheMsg(q, dns.RcodeNameError)
						CacheSetSynth(cacheKey, synthMsg)
						msgPool.Put(synthMsg)
					}
					
					if logQueries {
						statusMark := "POLICY BLOCK"
						if dropped {
							statusMark = "POLICY DROP"
						}
						if spoofedAlias != "" {
							statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
						}
						log.Printf("[DNS] [%s] %s -> %s PTR | %s (Strict PTR Leakage) | NXDOMAIN",
							protocol, clientID, originalQName, statusMark)
					}
					return
				}
			}
		}
	}

	// ── 7. Upstream Exchange ──────────────────────────────────────────────
	// Increment active networking allocations organically post-cache resolution to prevent stat dilution
	IncrUpstream(routeCtx.routeName)
	executeUpstreamExchange(
		w, r, q, qNameTrimmed, doBit, originalID, cacheKey, 
		routeCtx.routeName, routeCtx.routeIdx, routeCtx.routeOriginType, 
		sk, clientGroup,
		clientID, clientName, clientNameLower, clientMAC, clientIP, clientAddr, 
		protocol, sni, sniLower, path, pathLower, 
		parentalForcedTTL, parentalReason, parentalCategory, parentalMatchedApex,
		bypassPolicies, originalQName, originalQNameTrimmed, spoofedAlias,
	)
}

