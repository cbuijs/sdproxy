/*
File:    process_routing.go
Version: 1.3.0
Updated: 06-May-2026 12:21 CEST

Description:
  Routing Engine for sdproxy.
  Executes the second phase of the core processing pipeline natively:
    - Domain Maps Suffix Walking (Domain Policy intercepts and Upstream Routes)
    - Full Client Identification (MAC, IP, CIDR, ASN, SNI, PATH resolving)
    - Client Profile RCODE intercepts

Changes:
  1.3.0 - [FEAT] Integrated `force` evaluations cleanly across all client route 
          identifiers natively. Any rule flagged with `force: true` securely overrides 
          the default network priority hierarchy, allowing users to override baseline 
          subnet routing with pinpoint explicit host rules.
  1.2.0 - [FEAT] Added `bypassPolicies` parameter support to strictly skip Domain
          Policy sinkholes when explicitly allowlisted by the Custom Rules Engine.
*/

package main

import (
	"fmt"
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

func determineRouting(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, clientName, clientID, protocol, sni, path string, bypassPolicies bool) (routingContext, bool) {
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
	if hasDomainRoutes || hasDomainPolicy.Load() {
		policyAction, policyBlocked, policyMatched, drUpstream, drBypass, drMatched := walkDomainMaps(qNameTrimmed)
		if policyBlocked && !bypassPolicies {
			IncrBlockedDomain(qNameTrimmed, "Domain Policy ("+policyMatched+")")
			recordRecentBlock(clientIP, qNameTrimmed, "Domain Policy ("+policyMatched+")") 
			
			if policyAction == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (Domain Policy (%s)) | %s",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], policyMatched, getBlockActionLogStr(q.Qtype))
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
						actionLogStr = dns.RcodeToString[policyAction]
						if actionLogStr == "" {
							actionLogStr = fmt.Sprintf("RCODE:%d", policyAction)
						}
					}
					
					statusMark := "POLICY BLOCK"
					if dropped { statusMark = "POLICY DROP" }
					
					log.Printf("[DNS] [%s] %s -> %s %s | %s (Domain Policy (%s)) | %s",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], statusMark, policyMatched, actionLogStr)
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

	// Priority: MAC > MAC-Glob > IP > CIDR > ASN > Client-Name > SNI > Path
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
	if hasASNRoutes && clientIP != "" {
		if asn, _, _ := LookupASNDetails(clientAddr); asn != "" {
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
	}
	if hasClientNameRoutes && ctx.clientName != "" {
		if route, ok := clientNameRoutes[strings.ToLower(ctx.clientName)]; ok {
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
	if hasSNIRoutes && sni != "" {
		if route, ok := sniRoutes[strings.ToLower(sni)]; ok {
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
	if hasPathRoutes && path != "" {
		if route, ok := pathRoutes[path]; ok {
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
			IncrBlockedDomain(qNameTrimmed, reason)
			recordRecentBlock(clientIP, qNameTrimmed, reason)

			localClientID := clientID
			if ctx.clientName != clientName {
				localClientID = buildClientID(clientIP, ctx.clientName, clientAddr)
			}

			if clientRoute.Rcode == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (Client Route (%s)) | %s",
						protocol, localClientID, q.Name, dns.TypeToString[q.Qtype], ctx.routeOriginType, getBlockActionLogStr(q.Qtype))
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
						actionLogStr = dns.RcodeToString[clientRoute.Rcode]
						if actionLogStr == "" {
							actionLogStr = fmt.Sprintf("RCODE:%d", clientRoute.Rcode)
						}
					}

					statusMark := "POLICY BLOCK"
					if dropped {
						statusMark = "POLICY DROP"
					}

					log.Printf("[DNS] [%s] %s -> %s %s | %s (Client Route (%s)) | %s",
						protocol, localClientID, q.Name, dns.TypeToString[q.Qtype], statusMark, ctx.routeOriginType, actionLogStr)
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

