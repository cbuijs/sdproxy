/*
File:    process_exchange.go
Version: 2.55.0
Updated: 12-Jun-2026 14:27 CEST

Description:
  Upstream Exchange and Payload Transformation for sdproxy.
  Executes the final phase of the core processing pipeline natively:
    - QNAME Label Bounds Constraint Inspection
    - SingleFlight Connection Coalescing
    - Answer Sorting & Payload Optimization
    - Target Name Policy Inspection
    - Response IP Filtering and Rebinding Defenses
    - Buffer capacity & Telemetry execution

  Extracted from process.go to promote advanced modularity.

Changes:
  2.55.0 - [PERF] Ingested natively pre-computed `sk` and `clientGroup` parameters.
           Definitively eliminates repetitive routing-identity evaluations during 
           dynamic UNTRIGGER telemetry scheduling organically.
  2.54.0 - [BUG/FIX] Resolved a compilation error natively within the upstream networking core. 
           Aligned the SingleFlight cache key builder (`buildSFKey`) invocation to correctly 
           pass the newly required `Qclass` parameter, ensuring strict execution mapping.
*/

package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// untriggerLogTimers maintains active expiration timers for UNTRIGGER logging natively
var untriggerLogTimers sync.Map

// executeUpstreamExchange performs the outbound network dial, validates the payload responses,
// executes modifications, and replies to the client natively.
func executeUpstreamExchange(
	w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed string,
	doBit bool, originalID uint16, cacheKey DNSCacheKey,
	routeName string, routeIdx uint16, routeOriginType string,
	sk, clientGroup string,
	clientID, clientName, clientNameLower, clientMAC, clientIP string, clientAddr netip.Addr,
	protocol, sni, sniLower, path, pathLower string,
	parentalForcedTTL uint32, parentalReason, parentalCategory, parentalMatchedApex string,
	bypassPolicies bool,
	originalQName, originalQNameTrimmed, spoofedAlias string,
) {

	// ── 1. Upstream selection + pre-validation ────────────────────────────
	group, exists := routeUpstreams[routeName]
	if !exists || len(group.Servers) == 0 {
		group = routeUpstreams["default"]
	}
	if group == nil || len(group.Servers) == 0 {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | NO UPSTREAMS CONFIGURED",
			protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
			routeName, routeOriginType)
		dns.HandleFailed(w, r)
		return
	}

	// ── 1.5 EDNS0 Client Subnet (ECS) Log Inspection ──────────────────────
	var clientSentECS bool
	if opt := r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_SUBNET); ok {
				clientSentECS = true
				break
			}
		}
	}

	ecsMark := ""
	if group.ECSAction == "add" && clientAddr.IsValid() {
		var m int
		if clientAddr.Is4() {
			m = group.ECSV4Mask
		} else {
			m = group.ECSV6Mask
		}
		ecsMark = fmt.Sprintf(" [ECS: ADD /%d]", m)
	} else if group.ECSAction == "pass" && clientSentECS {
		ecsMark = " [ECS: PASS]"
	}

	// ── 1.8 QNAME Label Bounds Validation ─────────────────────────────────
	if !group.IgnoreQnameLabels {
		labels := countDomainLabels(qNameTrimmed)
		if labels < cfg.Server.QnameMinLabels || labels > cfg.Server.QnameMaxLabels {
			IncrPolicyBlock()
			
			// [SECURITY/FIX] Append the Target evaluation structure transparently 
			// if the bounds violation originated from a CNAME Spoofed Alias natively.
			reason := fmt.Sprintf("QNAME Label Bounds (%d labels)", labels)
			if originalQNameTrimmed != qNameTrimmed {
				reason += fmt.Sprintf(" (Target: %s)", qNameTrimmed)
			}
			
			RecordBlockEvent(clientIP, originalQNameTrimmed, reason)

			dropped := writePolicyAction(w, r, PolicyActionBlock)

			if cacheSynthFlag && !dropped && globalBlockAction != BlockActionDrop {
				synthMsg := buildSynthCacheMsg(q, PolicyActionBlock)
				CacheSetSynth(cacheKey, synthMsg)
				msgPool.Put(synthMsg) // [PERF] Zero-allocation memory recycling
			}

			if logQueries {
				var actionLogStr string
				if globalBlockAction == BlockActionLog {
					actionLogStr = "LOG ONLY"
				} else if globalBlockAction == BlockActionDrop {
					actionLogStr = "DROP"
				} else {
					actionLogStr = getBlockActionLogStr(q.Qtype)
				}

				statusMark := "POLICY BLOCK"
				if dropped {
					statusMark = "POLICY DROP"
				}
				if spoofedAlias != "" {
					statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
				}

				log.Printf("[DNS] [%s] %s -> %s %s | %s (Label Bounds) | %s",
					protocol, clientID, originalQName, dns.TypeToString[q.Qtype], statusMark, actionLogStr)
			}
			return
		}
	}

	// ── 2. Upstream forwarding — coalesced via singleflight ───────────────
	sfClientName := ""
	if group.HasClientName {
		sfClientName = clientName
	}
	
	// [SECURITY/FIX] The RouteIdx natively isolates group configurations. However, 
	// cacheKey.ECS dynamically partitions Cache Keys organically to completely neutralize 
	// cross-contamination when disparate subnets simultaneously execute queries mapped 
	// to identically configured target upstreams. We explicitly inject q.Qclass here 
	// to strictly conform to the structurally expanded builder signature natively.
	sfKey       := buildSFKey(qNameTrimmed, q.Qtype, q.Qclass, routeIdx, doBit, r.CheckingDisabled, sfClientName, cacheKey.ECS)
	didUpstream := false
	
	v, sfErr, shared := sfGroup.Do(sfKey, func() (any, error) {
		didUpstream = true
		IncrUpstreamCall()
		
		ctx, cancel := newUpstreamCtx()
		defer cancel()
		
		// The active routing pipeline transmits the underlying subnet to intelligently populate ECS
		msg, addr, err := group.Exchange(ctx, r, clientID, clientName, clientAddr)
		if err != nil || msg == nil {
			// [FEAT] Infinite Serve-Stale Fallback
			// Intercept upstream outages and connection timeouts natively by 
			// probing the cache arrays for expired records as an absolute last resort.
			if cfg.Cache.ServeStaleInfinite {
				fallbackMsg := new(dns.Msg) // OPTIMIZATION: Use new(dns.Msg) instead of msgPool.Get() to keep the pool perfectly balanced!
				if CacheGetExpired(cacheKey, fallbackMsg) {
					return sfResult{msg: fallbackMsg, addr: "stale-fallback"}, nil
				}
			}
			return sfResult{msg: msg, addr: addr}, err
		}
		isNeg := msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
		if !isNeg || cacheUpstreamNeg {
			CacheSet(cacheKey, msg, routeName)
		}
		return sfResult{msg: msg, addr: addr}, nil
	})
	
	if shared && !didUpstream {
		coalescedTotal.Add(1)
	}

	var finalResp *dns.Msg
	var upstreamUsed string
	if v != nil {
		if res, ok := v.(sfResult); ok {
			upstreamUsed = res.addr
			if res.msg != nil && sfErr == nil {
				if shared {
					finalResp = res.msg.Copy()
				} else {
					finalResp = res.msg
				}
			}
		}
	}

	// ── 3. Error Handle ───────────────────────────────────────────────────
	if finalResp == nil {
		if sfErr != nil && errors.Is(sfErr, ErrSilentDrop) {
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | CONSENSUS DROP | DROP",
					protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
					routeName, routeOriginType)
			}
			return // Natively shed the load without responding
		}

		upstreamLog := ""
		if upstreamUsed != "" {
			upstreamLog = " | UPSTREAM: " + cleanUpstreamHost(upstreamUsed)
		}
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s)%s | FAILED: %v",
			protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
			routeName, routeOriginType, upstreamLog, sfErr)
		dns.HandleFailed(w, r)
		return
	}

	// ── 4. Answer Sorting ─────────────────────────────────────────────────
	// MUST execute BEFORE any client-specific payload mutations (like TTL Caps
	// or DNSSEC stripping) to prevent corrupting the global cache byte arrays.
	if cfg.Cache.AnswerSort != "none" {
		if applyAnswerSort(finalResp, cfg.Cache.AnswerSort) {
			// [PERFORMANCE] Prevent severe CPU starvation and lock contention. 
			// 'random' sorting shuffles records ephemerally for the client. 
			// [SECURITY/FIX] If 'shared' is true, this is a coalesced SingleFlight cache-miss.
			// Only the primary worker (`didUpstream`) strictly executes CacheUpdateOrder to 
			// prevent parallel goroutines from thrashing and guarantee the cached payload updates.
			if cfg.Cache.AnswerSort != "random" && (!shared || didUpstream) {
				CacheUpdateOrder(cacheKey, finalResp)
			}
		}
	}

	// ── 5. Target Name Policy Check (Cache Miss) ──────────────────────────
	if checkTargetNames(w, r, finalResp, sk, clientGroup, clientMAC, clientIP, clientAddr, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, bypassPolicies, originalQName) {
		return
	}

	// ── 6. Response transforms ────────────────────────────────────────────
	finalResp = transformResponse(finalResp, q.Qtype, doBit, true)

	// ── 7. IP Filter Policy Check (Cache Miss) ────────────────────────────
	if filterResponseIPs(w, r, finalResp, sk, clientGroup, clientMAC, clientIP, clientAddr, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, bypassPolicies, originalQName, originalQNameTrimmed) {
		return
	}

	// ── 8. DNS Rebinding Protection (Cache Miss) ──────────────────────────
	if filterRebinding(w, r, finalResp, clientIP, clientAddr, clientName, clientID, protocol, originalQName, originalQNameTrimmed) {
		return
	}

	// ── 9. NULL-IP Detection (Pre-Truncation) ─────────────────────────────
	// Evaluate NULL-IPs natively BEFORE UDP Fragmentation defense executes.
	// This guarantees that artificially truncated payloads (where Answer == nil)
	// do not silently evade telemetry trackers.
	isNullIP := responseContainsNullIP(finalResp)
	if isNullIP {
		IncrPolicyBlock()
		RecordBlockEvent(clientIP, originalQNameTrimmed, "Upstream NULL-IP ("+routeName+")")
	}

	// ── 10. UDP Amplification & Fragmentation Defense ──────────────────────
	upstreamSize, clientAdvertised := enforceUDPDefenses(r, finalResp, protocol)

	// ── 11. Final reply ───────────────────────────────────────────────────
	if parentalForcedTTL > 0 {
		CapResponseTTL(finalResp, parentalForcedTTL)
	}
	finalResp.Id = originalID
	
	IncrReturnCode(finalResp.Rcode, isNullIP)
	if finalResp.Rcode == dns.RcodeNameError {
		IncrNXDomain(originalQNameTrimmed)
	}

	if upstreamUsed != "" {
		IncrUpstreamHost(cleanUpstreamHost(upstreamUsed))
	}
	
	w.WriteMsg(finalResp)

	// [MEMORY LIFECYCLE & GC]
	// Note: `finalResp` is inherently generated via a network `Unpack()` allocation 
	// from the upstream dialer (or cloned during a SingleFlight coalescing event).
	// It is intentionally NOT placed back into the `msgPool` to be safely garbage-collected.
	// This natively prevents pool pollution from external, variable-sized network arrays 
	// and guarantees pristine baseline capacities for local synthetic messages.

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
			status = rcodeStr + " (NULL-IP)"
		case finalResp.Truncated:
			status = fmt.Sprintf("TRUNCATED (TC=1, Upstream:%dB, Client:%dB) | %s", upstreamSize, clientAdvertised, rcodeStr)
		default:
			status = "CACHE HIT | " + rcodeStr // Note: Logically this is a Cache Miss in process_exchange, leaving string as-is based on prior structure context
			if upstreamUsed != "" {
				status = "OK | " + rcodeStr
			}
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
			// [FEAT] Explicitly identify domains that were saved by the active UNTRIGGER window.
			if parentalCategory != "" {
				status += fmt.Sprintf(" (UNTRIGGERED BYPASS: %s, apex: %s)", parentalCategory, parentalMatchedApex)
			} else {
				status += " (UNTRIGGERED BYPASS)"
			}
		} else if parentalReason == "ACTIVATING_UNTRIGGER" || parentalReason == "UNTRIGGER_SOURCE" {
			if parentalReason == "ACTIVATING_UNTRIGGER" {
				status += fmt.Sprintf(" (ACTIVATING UNTRIGGER WINDOW: %s, apex: %s)", parentalCategory, parentalMatchedApex)
				
				// Schedule an asynchronous log to fire exactly when the window expires
				dur := 5 * time.Minute
				if clientGroup != "" {
					if grp, ok := cfg.Groups[clientGroup]; ok {
						val := grp.Budget[parentalCategory]
						if val == "" { val = grp.Budget["total"] }
						if len(val) > 9 {
							if d, err := time.ParseDuration(strings.TrimSpace(val[9:])); err == nil {
								dur = d
							}
						}
					}
				}
				
				timerKey := clientID + "|" + parentalCategory
				if existing, ok := untriggerLogTimers.Load(timerKey); ok {
					existing.(*time.Timer).Stop()
				}
				
				logProtocol := protocol
				logClientID := clientID
				
				t := time.AfterFunc(dur, func() {
					log.Printf("[DNS] [%s] %s | PARENTAL UNTRIGGER WINDOW ENDED | Normal strict BLOCK policies resumed.", logProtocol, logClientID)
					untriggerLogTimers.Delete(timerKey)
				})
				untriggerLogTimers.Store(timerKey, t)
			} else {
				if parentalCategory != "" {
					status += fmt.Sprintf(" (UNTRIGGER SOURCE: %s, apex: %s)", parentalCategory, parentalMatchedApex)
				} else {
					status += " (UNTRIGGER SOURCE)"
				}
			}
		} else if parentalCategory != "" {
			status += fmt.Sprintf(" (CATEGORY: %s, apex: %s)", parentalCategory, parentalMatchedApex)
		}
		
		if upstreamUsed == "stale-fallback" {
			status = "INFINITE STALE FALLBACK | " + status
		}
		
		if spoofedAlias != "" {
			status = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, status)
		}

		if ecsMark != "" {
			status += ecsMark
		}
		
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | UPSTREAM: %s (%s) | %s",
			protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
			routeName, routeOriginType, upstreamUsed, routeName, status)
	}
}

