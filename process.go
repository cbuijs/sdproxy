/*
File:    process.go
Version: 3.63.0
Updated: 07-May-2026 12:13 CEST

Description:
  Per-query DNS processing pipeline for sdproxy.
  Acts as the master core orchestrator for the resolution flow.

  The architecture has been modularized into highly focused execution units:
    - process_security.go (Admission, ACLs, DGA, Exfil, Anti-Amp)
    - process_routing.go  (Client and Domain Routing rules)
    - process_exchange.go (SingleFlight Upstream networking and mutations)
    - process_spoof.go    (Explicit Record Overrides and Aliasing)

Changes:
  3.63.0 - [FIX] Addressed severe telemetry skew within the `Top Upstreams` metrics 
           tracker. Extracted the `IncrUpstream` call sequence natively below the 
           cache validation mechanisms to verify upstream allocations strictly tally 
           against live network connections, nullifying local cache inflations organically.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"

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
			clientAddr = a.Unmap()

			if protocol == "UDP" {
				if clientAddr.IsMulticast() || clientAddr.IsUnspecified() || (clientAddr.Is4() && clientAddr.As4() == [4]byte{255, 255, 255, 255}) {
					IncrDroppedRateLimit() 
					return
				}
			}
		}
	}

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[PANIC] Recovered in ProcessDNS (%s / %s): %v", protocol, clientIP, rec)
			PenalizeClient(clientIP, clientAddr, -1) 
			
			defer func() { recover() }() 
			if r != nil {
				dns.HandleFailed(w, r)
			}
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

	// Determine client constraints early for granular per-group spoofing
	clientGroup := ResolveClientGroup(clientMAC, clientIP, clientAddr, clientName, sni, path)

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
	ruleAction, ruleMatch := CheckRules(qNameTrimmed, clientGroup)

	if ruleAction == "BLOCK" {
		IncrPolicyBlock()
		reason := "Custom Rule (" + ruleMatch + ")"
		if clientGroup != "" && clientGroup != "global" {
			reason += " [" + clientGroup + "]"
		}
		IncrBlockedDomain(originalQNameTrimmed, reason)
		recordRecentBlock(clientIP, originalQNameTrimmed, reason)
		
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
	routeCtx, intercepted := determineRouting(w, r, q, qNameTrimmed, clientIP, clientAddr, clientMAC, clientName, clientID, protocol, sni, path, bypassPolicies)
	if intercepted {
		return
	}

	if routeCtx.clientName != clientName {
		clientName = routeCtx.clientName
		clientID = buildClientID(clientIP, clientName, clientAddr)
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

		blocked, blockTTL, forcedTTL, reason, cat, matchedApex := CheckParental(clientMAC, clientIP, clientAddr, clientName, sni, path, checkTarget, targetAddr, false, bypassPolicies)
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
			
			IncrBlockedDomain(originalQNameTrimmed, blockReason) 
			recordRecentBlock(clientIP, originalQNameTrimmed, blockReason) 
			
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
	cacheKey := DNSCacheKey{Name: qNameTrimmed, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeCtx.routeIdx, DoBit: doBit, CdBit: r.CheckingDisabled}
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

			if checkTargetNames(w, r, poolMsg, clientMAC, clientIP, clientAddr, clientName, clientID, protocol, sni, path, bypassPolicies, originalQName) {
				msgPool.Put(poolMsg)
				return
			}

			resp := transformResponse(poolMsg, q.Qtype, doBit, true)

			if filterResponseIPs(w, r, resp, clientMAC, clientIP, clientAddr, clientName, clientID, protocol, sni, path, bypassPolicies, originalQName, originalQNameTrimmed) {
				msgPool.Put(poolMsg)
				return
			}

			if filterRebinding(w, r, resp, clientIP, clientAddr, clientName, clientID, protocol, originalQName, originalQNameTrimmed) {
				msgPool.Put(poolMsg)
				return
			}
			
			isNullIP := responseContainsNullIP(resp)
			if isNullIP {
				IncrPolicyBlock()
				IncrBlockedDomain(originalQNameTrimmed, "Cached NULL-IP ("+routeCtx.routeName+")")
				recordRecentBlock(clientIP, originalQNameTrimmed, "Cached NULL-IP ("+routeCtx.routeName+")") 
			}
			
			IncrReturnCode(resp.Rcode, isNullIP)
			if resp.Rcode == dns.RcodeNameError {
				IncrNXDomain(originalQNameTrimmed)
			}
			
			upstreamSize, clientAdvertised := enforceUDPDefenses(r, resp, protocol)

			w.WriteMsg(resp)
			
			if logQueries {
				rcodeStr := dns.RcodeToString[resp.Rcode]
				if rcodeStr == "" {
					rcodeStr = fmt.Sprintf("RCODE:%d", resp.Rcode)
				}
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
	if !bypassPolicies && handlePolicyExits(w, r, q, qNameTrimmed, clientID, protocol, cacheKey, originalQName, originalQNameTrimmed, spoofedAlias) {
		return
	}

	// ── 6. Local A/AAAA/PTR answers ───────────────────────────────────────
	if handleLocalIdentity(w, r, q, qNameTrimmed, clientID, clientIP, protocol, routeCtx.routeName, routeCtx.routeOriginType, routeCtx.bypassLocal, cacheKey, parentalForcedTTL, originalQName, spoofedAlias) {
		return
	}

	// ── 7. Upstream Exchange ──────────────────────────────────────────────
	// Increment active networking allocations organically post-cache resolution to prevent stat dilution
	IncrUpstream(routeCtx.routeName)
	executeUpstreamExchange(
		w, r, q, qNameTrimmed, doBit, originalID, cacheKey, 
		routeCtx.routeName, routeCtx.routeIdx, routeCtx.routeOriginType, 
		clientID, clientName, clientMAC, clientIP, clientAddr, 
		protocol, sni, path, 
		parentalForcedTTL, parentalReason, parentalCategory, parentalMatchedApex,
		bypassPolicies, originalQName, originalQNameTrimmed, spoofedAlias,
	)
}

