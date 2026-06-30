/*
File:    process_routing.go
Version: 1.9.0
Updated: 30-Jun-2026 09:46 CEST

Description:
  Routing Engine for sdproxy.
  Executes the second phase of the core processing pipeline natively:
    - Domain Maps Suffix Walking (Domain Policy intercepts and Upstream Routes)
    - Full Client Identification (MAC, IP, CIDR, ASN, Country, SNI, PATH resolving)
    - Client Profile RCODE intercepts

Changes:
  1.9.0 - [FEAT] Introduced `Country` ISO 3166-1 alpha-2 network boundaries natively 
          into the client identity resolution matrix organically.
  1.8.0 - [SECURITY/FIX] Addressed a telemetry omission anomaly within the 
          Domain Policy routing engine. Injected the missing `IncrPolicyBlock()` 
          instruction natively prior to executing the Drop/Log evaluation sequence. 
          Guarantees that Domain Policy intercepts correctly register on the 
          global statistical counters natively.
  1.7.0 - [PERF] Injected explicit `clientNameLower`, `sniLower`, and `pathLower` 
          pre-computed structural parameters into the routing signature statically.
          Completely eradicates massive, recursive string allocations mapped to the 
          hot-path routing matrix, ensuring low-latency bounds under peak throughput.
  1.6.0 - [REFACTOR] Employed `RcodeStr` helper natively to construct Return Code 
          log structures securely and effortlessly.
*/

package main

import (
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

type routingContext struct {
	routeName        string
	routeIdx         uint16
	routeOriginType  string
	bypassLocal      bool
	clientName       string
}

func determineRouting(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower string, bypassPolicies bool) (routingContext, bool) {
	ctx := routingContext{
		routeIdx:        routeIdxDefault,
		routeName:       "default",
		routeOriginType: "DEFAULT",
		bypassLocal:     false,
		clientName:      clientName,
	}

	var domainRouteMatched bool
	var domainRouteUpstream string
	var domainRouteBypass bool

	// ── 1. Domain Maps Walk ───────────────────────────────────────────────
	// Walks the suffix tree utilizing the dynamically resolved query name. 
	// This correctly assesses Upstream bounds against internal alias targets (if spoofed).
	if hasDomainRoutes || hasDomainPolicy.Load() {
		policyAction, policyBlocked, policyMatched, drUpstream, drBypass, drMatched := walkDomainMaps(qNameTrimmed)
		if policyBlocked && !bypassPolicies {
			// [SECURITY/FIX] Align scalar metrics cleanly with internal pipeline structures natively
			IncrPolicyBlock() 
			// [SECURITY/FIX] Enforce pure analytics logging utilizing the original requested domain
			RecordBlockEvent(clientIP, originalQNameTrimmed, "Domain Policy ("+policyMatched+")") 
			
			if policyAction == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (Domain Policy (%s)) | %s",
						protocol, clientID, originalQName, dns.TypeToString[q.Qtype], policyMatched, getBlockActionLogStr(q.Qtype))
				}
			} else {
				dropped := writePolicyAction(w, r, policyAction)
				
				if logQueries {
					var actionLogStr string
					if policyAction == PolicyActionBlock {
						actionLogStr = getBlockActionLogStr(q.Qtype)
					} else if policyAction == PolicyActionDrop { 
						actionLogStr = "DROP"
					} else {
						actionLogStr = RcodeStr(policyAction)
					}
					
					statusMark := "POLICY BLOCK"
					if dropped { statusMark = "POLICY DROP" }
					
					log.Printf("[DNS] [%s] %s -> %s %s | %s (Domain Policy (%s)) | %s",
						protocol, clientID, originalQName, dns.TypeToString[q.Qtype], statusMark, policyMatched, actionLogStr)
				}
				return ctx, true // Intercepted
			}
		}
		domainRouteMatched  = drMatched
		domainRouteUpstream = drUpstream
		domainRouteBypass   = drBypass
	}

	// ── 2. Client Identity Resolution ─────────────────────────────────────
	var clientRouteMatched bool
	var clientRoute ParsedRoute

	var normalRoute ParsedRoute
	var normalOrigin string
	var normalMatched bool

	// Priority: MAC > MAC-Glob > IP > CIDR > ASN > Country > Client-Name > SNI > Path
	if hasMACRoutes && clientMAC != "" {
		if route, ok := macRoutes[clientMAC]; ok {
			if route.Force {
				clientRoute = route
				clientRouteMatched = true
				ctx.routeOriginType = "MAC"
				goto ApplyClientRoute
			}
			if !normalMatched {
				normalRoute = route
				normalOrigin = "MAC"
				normalMatched = true
			}
		}
	}
	if hasMACWildRoutes && clientMAC != "" {
		for _, wg := range macWildRoutes {
			if matchMACGlob(wg.pattern, clientMAC) {
				if wg.route.Force {
					clientRoute = wg.route
					clientRouteMatched = true
					ctx.routeOriginType = "MAC-GLOB"
					goto ApplyClientRoute
				}
				if !normalMatched {
					normalRoute = wg.route
					normalOrigin = "MAC-GLOB"
					normalMatched = true
				}
				break
			}
		}
	}
	if hasIPRoutes && clientIP != "" {
		if route, ok := ipRoutes[clientIP]; ok {
			if route.Force {
				clientRoute = route
				clientRouteMatched = true
				ctx.routeOriginType = "IP"
				goto ApplyClientRoute
			}
			if !normalMatched {
				normalRoute = route
				normalOrigin = "IP"
				normalMatched = true
			}
		}
	}
	if hasCIDRRoutes && clientAddr.IsValid() {
		for _, cr := range cidrRoutes {
			if cr.net.Contains(clientAddr) {
				if cr.route.Force {
					clientRoute = cr.route
					clientRouteMatched = true
					ctx.routeOriginType = "CIDR"
					goto ApplyClientRoute
				}
				if !normalMatched {
					normalRoute = cr.route
					normalOrigin = "CIDR"
					normalMatched = true
				}
				break
			}
		}
	}
	if (hasASNRoutes || hasCountryRoutes) && clientAddr.IsValid() {
		if asn, _, country := LookupASNDetails(clientAddr); asn != "" || country != "" {
			if hasASNRoutes && asn != "" {
				if route, ok := asnRoutes[asn]; ok {
					if route.Force {
						clientRoute = route
						clientRouteMatched = true
						ctx.routeOriginType = "ASN"
						goto ApplyClientRoute
					}
					if !normalMatched {
						normalRoute = route
						normalOrigin = "ASN"
						normalMatched = true
					}
				}
			}
			if hasCountryRoutes && country != "" && !clientRouteMatched {
				countryUpper := strings.ToUpper(country)
				if route, ok := countryRoutes[countryUpper]; ok {
					if route.Force {
						clientRoute = route
						clientRouteMatched = true
						ctx.routeOriginType = "COUNTRY"
						goto ApplyClientRoute
					}
					if !normalMatched {
						normalRoute = route
						normalOrigin = "COUNTRY"
						normalMatched = true
					}
				}
			}
		}
	}
	// [PERF/FIX] Consume pre-lowered `clientNameLower` structure natively.
	if hasClientNameRoutes && clientNameLower != "" {
		if route, ok := clientNameRoutes[clientNameLower]; ok {
			if route.Force {
				clientRoute = route
				clientRouteMatched = true
				ctx.routeOriginType = "CLIENT-NAME"
				goto ApplyClientRoute
			}
			if !normalMatched {
				normalRoute = route
				normalOrigin = "CLIENT-NAME"
				normalMatched = true
			}
		}
	}
	// [PERF/FIX] Consume pre-lowered `sniLower` structure natively.
	if hasSNIRoutes && sniLower != "" {
		if route, ok := sniRoutes[sniLower]; ok {
			if route.Force {
				clientRoute = route
				clientRouteMatched = true
				ctx.routeOriginType = "SNI"
				goto ApplyClientRoute
			}
			if !normalMatched {
				normalRoute = route
				normalOrigin = "SNI"
				normalMatched = true
			}
		}
	}
	// [PERF/FIX] Consume pre-lowered `pathLower` structure natively.
	if hasPathRoutes && pathLower != "" {
		p := pathLower
		if strings.HasPrefix(p, "path:") {
			p = strings.TrimPrefix(p, "path:")
		}
		p = strings.TrimSuffix(p, "/")
		if route, ok := pathRoutes[p]; ok {
			if route.Force {
				clientRoute = route
				clientRouteMatched = true
				ctx.routeOriginType = "PATH"
				goto ApplyClientRoute
			}
			if !normalMatched {
				normalRoute = route
				normalOrigin = "PATH"
				normalMatched = true
			}
		}
	}

	if normalMatched {
		clientRoute = normalRoute
		clientRouteMatched = true
		ctx.routeOriginType = normalOrigin
	}

ApplyClientRoute:
	if clientRouteMatched {
		if clientRoute.ClientName != "" {
			ctx.clientName = clientRoute.ClientName
		}

		if clientRoute.HasRcode && !bypassPolicies {
			IncrPolicyBlock()
			reason := "Client Route Policy (" + ctx.routeOriginType + ")"
			
			// [SECURITY/FIX] Enforce pure analytics logging utilizing the original requested domain
			RecordBlockEvent(clientIP, originalQNameTrimmed, reason)

			localClientID := clientID
			if ctx.clientName != clientName {
				localClientID = buildClientID(clientIP, ctx.clientName, clientAddr)
			}

			if clientRoute.Rcode == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (Client Route (%s)) | %s",
						protocol, localClientID, originalQName, dns.TypeToString[q.Qtype], ctx.routeOriginType, getBlockActionLogStr(q.Qtype))
				}
			} else {
				dropped := writePolicyAction(w, r, clientRoute.Rcode)

				if logQueries {
					var actionLogStr string
					if clientRoute.Rcode == PolicyActionBlock {
						actionLogStr = getBlockActionLogStr(q.Qtype)
					} else if clientRoute.Rcode == PolicyActionDrop {
						actionLogStr = "DROP"
					} else {
						actionLogStr = RcodeStr(clientRoute.Rcode)
					}

					statusMark := "POLICY BLOCK"
					if dropped {
						statusMark = "POLICY DROP"
					}

					log.Printf("[DNS] [%s] %s -> %s %s | %s (Client Route (%s)) | %s",
						protocol, localClientID, originalQName, dns.TypeToString[q.Qtype], statusMark, ctx.routeOriginType, actionLogStr)
				}
				return ctx, true // Intercepted
			}
		}

		if clientRoute.Upstream != "" {
			ctx.routeName = clientRoute.Upstream
			ctx.routeIdx  = getRouteIdx(clientRoute.Upstream)
		}
		ctx.bypassLocal = clientRoute.BypassLocal
	}

	// ── 3. Apply Domain Routing Properties ────────────────────────────────
	if domainRouteMatched {
		ctx.routeName       = domainRouteUpstream
		ctx.routeIdx        = getRouteIdx(domainRouteUpstream)
		ctx.routeOriginType = "DOMAIN"
		ctx.bypassLocal     = domainRouteBypass
	}

	return ctx, false
}

