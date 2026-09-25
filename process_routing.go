/*
File:    process_routing.go
Version: 1.12.1
Last Updated: 25-Sep-2026 12:00 CEST

Description:
  Routing Engine for sdproxy.
  Executes the second phase of the core processing pipeline natively:
    - Domain Maps Suffix Walking (Domain Policy intercepts and Upstream Routes)
    - Full Client Identification (MAC, IP, CIDR, ASN, Country, SNI, PATH, PORT resolving)
    - Client Profile RCODE intercepts

Changes:
  1.12.1 - [SECURITY/FIX] Resolved an issue utilizing `sync.Map` in `webuiClientBlocks` natively
           by executing map iterations explicitly safely avoiding bounded OOM restrictions organically.
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

// resolveClientRoute explicitly resolves the target identities before executing bounds matrices natively.
func resolveClientRoute(clientMAC, clientIP string, clientAddr netip.Addr, clientNameLower, sniLower, pathLower, portStr string) (ParsedRoute, bool, string) {
	var normalRoute ParsedRoute
	var normalOrigin string
	var normalMatched bool
	
	// Dynamic Compound evaluation matrix (ForceAnd)
	for _, mapping := range compoundRouteMappings {
		allMatched := true
		var matchedOrigins []string
		
		for _, rawKey := range mapping.keys {
			keyMatched := false
			switch classifyRouteKey(rawKey) {
			case rkMAC:
				if clientMAC != "" && strings.EqualFold(clientMAC, rawKey) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "MAC")
				}
			case rkMACGlob:
				if clientMAC != "" && matchMACGlob(normaliseMACGlob(rawKey), clientMAC) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "MAC-GLOB")
				}
			case rkIP:
				if clientIP != "" && clientIP == rawKey {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "IP")
				}
			case rkCIDR:
				if clientAddr.IsValid() {
					if prefix, err := ParsePrefixUnmapped(rawKey); err == nil && prefix.Contains(clientAddr) {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "CIDR")
					}
				}
			case rkASN:
				if clientAddr.IsValid() {
					if asn, _, _ := LookupASNDetails(clientAddr); asn != "" && strings.EqualFold(asn, rawKey) {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "ASN")
					}
				}
			case rkCountry:
				if clientAddr.IsValid() {
					if _, _, country := LookupASNDetails(clientAddr); country != "" {
						cc := strings.TrimPrefix(strings.ToUpper(rawKey), "CC:")
						if strings.EqualFold(country, cc) {
							keyMatched = true
							matchedOrigins = append(matchedOrigins, "COUNTRY")
						}
					}
				}
			case rkClientName:
				if clientNameLower != "" && clientNameLower == strings.ToLower(rawKey) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "CLIENT-NAME")
				}
			case rkSNI:
				if sniLower != "" && sniLower == strings.ToLower(strings.TrimPrefix(rawKey, "sni:")) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "SNI")
				}
			case rkPath:
				if pathLower != "" {
					p := strings.ToLower(rawKey)
					if strings.HasPrefix(p, "path:") { p = strings.TrimPrefix(p, "path:") }
					if pathLower == strings.TrimSuffix(p, "/") {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "PATH")
					}
				}
			case rkPort:
				if portStr != "" {
					if p, ok := parsePort(rawKey); ok && p == portStr {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "PORT")
					}
				}
			}

			if !keyMatched {
				allMatched = false
				break
			}
		}

		if allMatched {
			originStr := strings.Join(matchedOrigins, "+")
			if mapping.route.Force { return mapping.route, true, originStr }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = mapping.route, originStr, true }
		}
	}
	
	// Fast Path standard evaluations
	if hasMACRoutes && clientMAC != "" {
		if route, ok := macRoutes[clientMAC]; ok {
			if route.Force { return route, true, "MAC" }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "MAC", true }
		}
	}
	if hasMACWildRoutes && clientMAC != "" {
		for _, wg := range macWildRoutes {
			if matchMACGlob(wg.pattern, clientMAC) {
				if wg.route.Force { return wg.route, true, "MAC-GLOB" }
				if !normalMatched { normalRoute, normalOrigin, normalMatched = wg.route, "MAC-GLOB", true }
				break
			}
		}
	}
	if hasIPRoutes && clientIP != "" {
		if route, ok := ipRoutes[clientIP]; ok {
			if route.Force { return route, true, "IP" }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "IP", true }
		}
	}
	if hasCIDRRoutes && clientAddr.IsValid() {
		for _, cr := range cidrRoutes {
			if cr.net.Contains(clientAddr) {
				if cr.route.Force { return cr.route, true, "CIDR" }
				if !normalMatched { normalRoute, normalOrigin, normalMatched = cr.route, "CIDR", true }
				break
			}
		}
	}
	if (hasASNRoutes || hasCountryRoutes) && clientAddr.IsValid() {
		if asn, _, country := LookupASNDetails(clientAddr); asn != "" || country != "" {
			if hasASNRoutes && asn != "" {
				if route, ok := asnRoutes[asn]; ok {
					if route.Force { return route, true, "ASN" }
					if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "ASN", true }
				}
			}
			if hasCountryRoutes && country != "" && !normalMatched {
				countryUpper := strings.ToUpper(country)
				if route, ok := countryRoutes[countryUpper]; ok {
					if route.Force { return route, true, "COUNTRY" }
					if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "COUNTRY", true }
				}
			}
		}
	}
	if hasClientNameRoutes && clientNameLower != "" {
		if route, ok := clientNameRoutes[clientNameLower]; ok {
			if route.Force { return route, true, "CLIENT-NAME" }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "CLIENT-NAME", true }
		}
	}
	if hasSNIRoutes && sniLower != "" {
		if route, ok := sniRoutes[sniLower]; ok {
			if route.Force { return route, true, "SNI" }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "SNI", true }
		}
	}
	if hasPathRoutes && pathLower != "" {
		p := pathLower
		if strings.HasPrefix(p, "path:") {
			p = strings.TrimPrefix(p, "path:")
		}
		p = strings.TrimSuffix(p, "/")
		if route, ok := pathRoutes[p]; ok {
			if route.Force { return route, true, "PATH" }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "PATH", true }
		}
	}
	if hasPortRoutes && portStr != "" {
		if route, ok := portRoutes[portStr]; ok {
			if route.Force { return route, true, "PORT" }
			if !normalMatched { normalRoute, normalOrigin, normalMatched = route, "PORT", true }
		}
	}

	if normalMatched {
		return normalRoute, true, normalOrigin
	}

	return ParsedRoute{}, false, ""
}

func determineRouting(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, portStr string, bypassPolicies bool, bypassGlobal bool, clientRoute ParsedRoute, clientRouteMatched bool, routeOriginType string) (routingContext, bool) {
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
		if policyBlocked && !bypassPolicies && !bypassGlobal {
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
	if clientRouteMatched {
		ctx.routeOriginType = routeOriginType
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
	if domainRouteMatched && !(clientRouteMatched && clientRoute.Force) {
		ctx.routeName       = domainRouteUpstream
		ctx.routeIdx        = getRouteIdx(domainRouteUpstream)
		ctx.routeOriginType = "DOMAIN"
		ctx.bypassLocal     = domainRouteBypass
	}

	return ctx, false
}
