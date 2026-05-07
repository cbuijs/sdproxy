/*
File:    process_exchange.go
Version: 2.36.0
Updated: 07-May-2026 12:20 CEST

Description:
  Upstream Exchange and Payload Transformation for sdproxy.
  Executes the final phase of the core processing pipeline natively:
    - SingleFlight Connection Coalescing
    - Answer Sorting & Payload Optimization
    - Target Name Policy Inspection
    - Response IP Filtering and Rebinding Defenses
    - Buffer capacity & Telemetry execution

  Extracted from process.go to promote advanced modularity.

Changes:
  2.36.0 - [SECURITY/FIX] Resolved a severe telemetry bypass regression. Evaluated 
           `responseContainsNullIP` natively BEFORE the `enforceUDPDefenses` layer 
           executes. This guarantees that `NULL-IP` blocks returned by upstream resolvers 
           are accurately recorded in the analytics dashboard even if the underlying 
           stateless UDP payload is artificially truncated to prevent IP fragmentation.
  1.5.0  - [SECURITY/FIX] Chained `originalQName` and `spoofedAlias` parameters deeply 
           into the Upstream Exchange logging pipeline natively. Fully shields analytical 
           tracking structures from recording false targets when CNAME spoofing 
           mechanisms aggressively mutate the structural payload.
  1.4.0  - [SECURITY/FIX] Propagated `bypassPolicies` deeply into the security 
           pipeline natively. Protects explicit Custom Rule `ALLOW` overrides 
           from being incorrectly dropped downstream by Deep Packet Inspection 
           routines evaluating nested CNAMEs and IP payloads (`checkTargetNames`, `filterResponseIPs`).
  1.3.0  - [FEAT] Integrated Infinite Serve-Stale capability. If enabled in config,
           upstream network failures natively interrogate the cache memory shards 
           for expired records, actively mitigating connectivity deadlocks for clients.
  1.2.0  - [PERF] Chained the native `clientID` buffer down into the security filters 
           (`checkTargetNames`, `filterResponseIPs`, `filterRebinding`) to completely 
           circumvent localized string allocations on the hot path during block scenarios.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/miekg/dns"
)

// executeUpstreamExchange performs the outbound network dial, validates the payload responses,
// executes modifications, and replies to the client natively.
func executeUpstreamExchange(
	w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed string,
	doBit bool, originalID uint16, cacheKey DNSCacheKey,
	routeName string, routeIdx uint16, routeOriginType string,
	clientID, clientName, clientMAC, clientIP string, clientAddr netip.Addr,
	protocol, sni, path string,
	parentalForcedTTL uint32, parentalReason, parentalCategory, parentalMatchedApex string,
	bypassPolicies bool,
	originalQName, originalQNameTrimmed, spoofedAlias string,
) {

	// ── 1. Upstream selection + pre-validation ────────────────────────────
	group, exists := routeUpstreams[routeName]
	if !exists || len(group.Servers) == 0 {
		group = routeUpstreams["default"]
	}
	if len(group.Servers) == 0 {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | NO UPSTREAMS CONFIGURED",
			protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
			routeName, routeOriginType)
		dns.HandleFailed(w, r)
		return
	}

	// ── 2. Upstream forwarding — coalesced via singleflight ───────────────
	sfClientName := ""
	if hasClientNameUpstream {
		sfClientName = clientName
	}
	sfKey       := buildSFKey(qNameTrimmed, q.Qtype, routeIdx, doBit, r.CheckingDisabled, sfClientName)
	didUpstream := false
	
	v, sfErr, shared := sfGroup.Do(sfKey, func() (any, error) {
		didUpstream = true
		IncrUpstreamCall()
		
		ctx, cancel := newUpstreamCtx()
		defer cancel()
		
		msg, addr, err := group.Exchange(ctx, r, clientID, clientName)
		if err != nil || msg == nil {
			// [FEAT] Infinite Serve-Stale Fallback
			// Intercept upstream outages and connection timeouts natively by 
			// probing the cache arrays for expired records as an absolute last resort.
			if cfg.Cache.ServeStaleInfinite {
				fallbackMsg := msgPool.Get().(*dns.Msg)
				*fallbackMsg = dns.Msg{}
				if CacheGetExpired(cacheKey, fallbackMsg) {
					return sfResult{msg: fallbackMsg, addr: "stale-fallback"}, nil
				}
				msgPool.Put(fallbackMsg)
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
		if sfErr != nil && sfErr.Error() == "silent_drop" {
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
			// If 'shared' is true, this is a coalesced SingleFlight cache-miss.
			// Only the primary worker executes CacheUpdateOrder to prevent parallel goroutines from thrashing.
			if cfg.Cache.AnswerSort != "random" && !shared {
				CacheUpdateOrder(cacheKey, finalResp)
			}
		}
	}

	// ── 5. Target Name Policy Check (Cache Miss) ──────────────────────────
	if checkTargetNames(w, r, finalResp, clientMAC, clientIP, clientAddr, clientName, clientID, protocol, sni, path, bypassPolicies, originalQName) {
		return
	}

	// ── 6. Response transforms ────────────────────────────────────────────
	finalResp = transformResponse(finalResp, q.Qtype, doBit, true)

	// ── 7. IP Filter Policy Check (Cache Miss) ────────────────────────────
	if filterResponseIPs(w, r, finalResp, clientMAC, clientIP, clientAddr, clientName, clientID, protocol, sni, path, bypassPolicies, originalQName, originalQNameTrimmed) {
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
		IncrBlockedDomain(originalQNameTrimmed, "Upstream NULL-IP ("+routeName+")")
		recordRecentBlock(clientIP, originalQNameTrimmed, "Upstream NULL-IP ("+routeName+")") 
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
		rcodeStr := dns.RcodeToString[finalResp.Rcode]
		if rcodeStr == "" {
			rcodeStr = fmt.Sprintf("RCODE:%d", finalResp.Rcode)
		}

		status := rcodeStr
		switch {
		case shared && !didUpstream:
			status = "COALESCED | " + rcodeStr
		case isNullIP:
			status = rcodeStr + " (NULL-IP)"
		case finalResp.Truncated:
			status = fmt.Sprintf("TRUNCATED (TC=1, Upstream:%dB, Client:%dB) | %s", upstreamSize, clientAdvertised, rcodeStr)
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
		
		if upstreamUsed == "stale-fallback" {
			status = "INFINITE STALE FALLBACK | " + status
		}
		
		if spoofedAlias != "" {
			status = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, status)
		}
		
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | UPSTREAM: %s (%s) | %s",
			protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
			routeName, routeOriginType, upstreamUsed, routeName, status)
	}
}

