/*
File:    process_routing.go
Version: 1.24.0
Last Updated: 12-Nov-2026 17:10 CET

Description:
  Routing Engine for sdproxy.
  Executes the second phase of the core processing pipeline natively:
    - Domain Maps Suffix Walking (Domain Policy intercepts and Upstream Routes)
    - Full Client Identification (MAC, EDNS0 MAC, IP, CIDR, ECS, ASN, Country, SNI, PATH, PORT resolving)
    - Client Profile RCODE intercepts

Changes:
  1.24.0 - [FIX] Allowed `macWildRoutes`, `ednsMACWildRoutes`, `cidrRoutes`, and
           `ecsCIDRRoutes` loops in `resolveClientRoute` to continue scanning for
           a `force: true` entry after recording the first non-forced match,
           matching `ResolveStateKeyAndGroup` (`parental.go` 3.51.0).
  1.23.0 - [FIX] Allowed `hasCountryRoutes` evaluation in `resolveClientRoute` even
           when a higher-precedence unforced rule matched (`normalMatched == true`)
           so a `CC:` route with `force: true` properly overrides unforced MAC/IP/ASN
           routes.
  1.22.0 - [CLEANUP] Removed unused `sni` parameter from `determineRouting` and
           `path` parameter from `determineRouting` since `sniLower` and `pathLower`
           are already pre-normalized by `ProcessDNS`.
  1.21.0 - [SECURITY/FIX] Evaluated `walkDomainMaps` against `originalQNameTrimmed`
           before `qNameTrimmed` when a query was rewritten by an `rrs:` CNAME
           alias, ensuring `domain_policy` blocks on the original queried domain
           cannot be bypassed by an `rrs:` CNAME alias.
  1.20.0 - [FEAT] Added `protoEndpoint` and Simple Logging Mode (`logSimple` /
           `logQuerySimple`) support for Domain Policy and Client Route RCODE
           interceptions in `determineRouting`.
  1.19.0 - [FEAT] Added `ednsMAC` parameter to `resolveClientRoute` and `determineRouting`
           to support EDNS0 Option 65001 (`mac:<mac>` and `mac:<mac-glob>`) matching
           in standard and `force-and` compound routes, and preserved `[MAC: <mac>]`
           log annotations on `localClientID`.
  1.18.0 - [FIX] Normalized `sni:` and `path:` compound route matching with
           `strings.TrimSpace` and leading `/` enforcement to match
           `initClientRoutes` and `ResolveStateKeyAndGroup`.
  1.17.0 - [FEAT] Preserved incoming ECS log annotation on `localClientID` when
           a client route overrides `client_name` and triggers an RCODE intercept.
  1.16.0 - [FEAT] Added `ecsIP` (`ecsAddr`) and `ecsPrefix` parameters to
           `resolveClientRoute` to support `ecs:` IP and CIDR matching in standard
           and `force-and` compound routes.
  1.15.0 - [FIX] Removed redundant `path:` prefix and trailing slash stripping on
           `cleanPath` in `resolveClientRoute` (`hasPathRoutes` branch).
*/

package main

import (
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

type routingContext struct {
	routeName       string
	routeIdx        uint16
	routeOriginType string
	bypassLocal     bool
	clientName      string
}

// resolveClientRoute explicitly resolves the target identities before executing bounds matrices natively.
func resolveClientRoute(clientMAC, ednsMAC, clientIP string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, clientNameLower, sniLower, pathLower, portStr string) (ParsedRoute, bool, string) {
	var normalRoute ParsedRoute
	var normalOrigin string
	var normalMatched bool

	cleanPath := pathLower
	if len(cleanPath) > 1 {
		cleanPath = strings.TrimSuffix(cleanPath, "/")
	}
	cleanSNI := lowerTrimDot(sniLower)

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
			case rkEDNSMAC:
				if ednsMAC != "" && strings.EqualFold(ednsMAC, parseMACKey(rawKey)) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "EDNS-MAC")
				}
			case rkEDNSMACGlob:
				if ednsMAC != "" && matchMACGlob(normaliseMACGlob(parseMACKey(rawKey)), ednsMAC) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "EDNS-MAC-GLOB")
				}
			case rkIP:
				if clientAddr.IsValid() {
					if ip, err := netip.ParseAddr(rawKey); err == nil && ip.Unmap() == clientAddr {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "IP")
					}
				}
			case rkCIDR:
				if clientAddr.IsValid() {
					if prefix, err := ParsePrefixUnmapped(rawKey); err == nil && prefix.Contains(clientAddr) {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "CIDR")
					}
				}
			case rkECSIP:
				if ecsAddr.IsValid() {
					if ip, err := netip.ParseAddr(parseECSKey(rawKey)); err == nil && ip.Unmap() == ecsAddr {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "ECS-IP")
					}
				}
			case rkECSCIDR:
				if ecsAddr.IsValid() {
					if prefix, err := ParsePrefixUnmapped(parseECSKey(rawKey)); err == nil && matchECSCIDR(prefix.Masked(), ecsPrefix, ecsAddr) {
						keyMatched = true
						matchedOrigins = append(matchedOrigins, "ECS-CIDR")
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
				if cleanSNI != "" && cleanSNI == lowerTrimDot(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(rawKey), "sni:"))) {
					keyMatched = true
					matchedOrigins = append(matchedOrigins, "SNI")
				}
			case rkPath:
				if cleanPath != "" {
					p := strings.ToLower(rawKey)
					if strings.HasPrefix(p, "path:") {
						p = strings.TrimSpace(strings.TrimPrefix(p, "path:"))
					}
					if p != "" && p[0] != '/' {
						p = "/" + p
					}
					if len(p) > 1 {
						p = strings.TrimSuffix(p, "/")
					}
					if cleanPath == p {
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
			if mapping.route.Force {
				return mapping.route, true, originStr
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = mapping.route, originStr, true
			}
		}
	}

	// Fast Path standard evaluations
	if hasMACRoutes && clientMAC != "" {
		if route, ok := macRoutes[clientMAC]; ok {
			if route.Force {
				return route, true, "MAC"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "MAC", true
			}
		}
	}
	if hasMACWildRoutes && clientMAC != "" {
		for _, wg := range macWildRoutes {
			if matchMACGlob(wg.pattern, clientMAC) {
				if wg.route.Force {
					return wg.route, true, "MAC-GLOB"
				}
				if !normalMatched {
					normalRoute, normalOrigin, normalMatched = wg.route, "MAC-GLOB", true
				}
			}
		}
	}
	if hasEDNSMACRoutes && ednsMAC != "" {
		if route, ok := ednsMACRoutes[ednsMAC]; ok {
			if route.Force {
				return route, true, "EDNS-MAC"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "EDNS-MAC", true
			}
		}
	}
	if hasEDNSMACWildRoutes && ednsMAC != "" {
		for _, wg := range ednsMACWildRoutes {
			if matchMACGlob(wg.pattern, ednsMAC) {
				if wg.route.Force {
					return wg.route, true, "EDNS-MAC-GLOB"
				}
				if !normalMatched {
					normalRoute, normalOrigin, normalMatched = wg.route, "EDNS-MAC-GLOB", true
				}
			}
		}
	}
	if hasIPRoutes && clientIP != "" {
		if route, ok := ipRoutes[clientIP]; ok {
			if route.Force {
				return route, true, "IP"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "IP", true
			}
		}
	}
	if hasCIDRRoutes && clientAddr.IsValid() {
		for _, cr := range cidrRoutes {
			if cr.net.Contains(clientAddr) {
				if cr.route.Force {
					return cr.route, true, "CIDR"
				}
				if !normalMatched {
					normalRoute, normalOrigin, normalMatched = cr.route, "CIDR", true
				}
			}
		}
	}
	if hasECSIPRoutes && ecsAddr.IsValid() {
		if route, ok := ecsIPRoutes[ecsAddr.String()]; ok {
			if route.Force {
				return route, true, "ECS-IP"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "ECS-IP", true
			}
		}
	}
	if hasECSCIDRRoutes && ecsAddr.IsValid() {
		for _, cr := range ecsCIDRRoutes {
			if matchECSCIDR(cr.net, ecsPrefix, ecsAddr) {
				if cr.route.Force {
					return cr.route, true, "ECS-CIDR"
				}
				if !normalMatched {
					normalRoute, normalOrigin, normalMatched = cr.route, "ECS-CIDR", true
				}
			}
		}
	}
	if (hasASNRoutes || hasCountryRoutes) && clientAddr.IsValid() {
		if asn, _, country := LookupASNDetails(clientAddr); asn != "" || country != "" {
			if hasASNRoutes && asn != "" {
				if route, ok := asnRoutes[asn]; ok {
					if route.Force {
						return route, true, "ASN"
					}
					if !normalMatched {
						normalRoute, normalOrigin, normalMatched = route, "ASN", true
					}
				}
			}
			if hasCountryRoutes && country != "" {
				countryUpper := strings.ToUpper(country)
				if route, ok := countryRoutes[countryUpper]; ok {
					if route.Force {
						return route, true, "COUNTRY"
					}
					if !normalMatched {
						normalRoute, normalOrigin, normalMatched = route, "COUNTRY", true
					}
				}
			}
		}
	}
	if hasClientNameRoutes && clientNameLower != "" {
		if route, ok := clientNameRoutes[clientNameLower]; ok {
			if route.Force {
				return route, true, "CLIENT-NAME"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "CLIENT-NAME", true
			}
		}
	}
	if hasSNIRoutes && cleanSNI != "" {
		if route, ok := sniRoutes[cleanSNI]; ok {
			if route.Force {
				return route, true, "SNI"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "SNI", true
			}
		}
	}
	if hasPathRoutes && cleanPath != "" {
		if route, ok := pathRoutes[cleanPath]; ok {
			if route.Force {
				return route, true, "PATH"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "PATH", true
			}
		}
	}
	if hasPortRoutes && portStr != "" {
		if route, ok := portRoutes[portStr]; ok {
			if route.Force {
				return route, true, "PORT"
			}
			if !normalMatched {
				normalRoute, normalOrigin, normalMatched = route, "PORT", true
			}
		}
	}

	if normalMatched {
		return normalRoute, true, normalOrigin
	}

	return ParsedRoute{}, false, ""
}

func determineRouting(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, originalQName, originalQNameTrimmed, clientIP string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, ednsMAC, clientName, clientID, protocol, protoEndpoint string, bypassPolicies bool, bypassGlobal bool, clientRoute ParsedRoute, clientRouteMatched bool, routeOriginType string) (routingContext, bool) {
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
		var (
			policyAction  int
			policyBlocked bool
			policyMatched string
			drUpstream    string
			drBypass      bool
			drMatched     bool
		)
		if originalQNameTrimmed != "" && originalQNameTrimmed != qNameTrimmed {
			policyAction, policyBlocked, policyMatched, drUpstream, drBypass, drMatched = walkDomainMaps(originalQNameTrimmed)
		}
		pa2, pb2, pm2, dru2, drb2, drm2 := walkDomainMaps(qNameTrimmed)
		if !policyBlocked && pb2 {
			policyAction, policyBlocked, policyMatched = pa2, pb2, pm2
		}
		if drm2 {
			drUpstream, drBypass, drMatched = dru2, drb2, drm2
		}

		if policyBlocked && !bypassPolicies && !bypassGlobal {
			IncrPolicyBlock()
			RecordBlockEvent(clientIP, originalQNameTrimmed, "Domain Policy ("+policyMatched+")")

			if policyAction == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (Domain Policy (%s)) | %s",
						protocol, clientID, originalQName, qtypeName(q.Qtype), policyMatched, getBlockActionLogStr(q.Qtype))
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

					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), actionLogStr, "Domain Policy ("+policyMatched+")", false)
					} else {
						statusMark := "POLICY BLOCK"
						if dropped {
							statusMark = "POLICY DROP"
						}

						log.Printf("[DNS] [%s] %s -> %s %s | %s (Domain Policy (%s)) | %s",
							protocol, clientID, originalQName, qtypeName(q.Qtype), statusMark, policyMatched, actionLogStr)
					}
				}
				return ctx, true // Intercepted
			}
		}
		domainRouteMatched = drMatched
		domainRouteUpstream = drUpstream
		domainRouteBypass = drBypass
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

			RecordBlockEvent(clientIP, originalQNameTrimmed, reason)

			localClientID := clientID
			if ctx.clientName != clientName {
				localClientID = appendClientEDNS(buildClientID(clientIP, ctx.clientName, clientAddr), ecsAddr, ecsPrefix, ednsMAC)
			}

			if clientRoute.Rcode == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (Client Route (%s)) | %s",
						protocol, localClientID, originalQName, qtypeName(q.Qtype), ctx.routeOriginType, getBlockActionLogStr(q.Qtype))
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

					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), actionLogStr, "Client Route ("+ctx.routeOriginType+")", false)
					} else {
						statusMark := "POLICY BLOCK"
						if dropped {
							statusMark = "POLICY DROP"
						}

						log.Printf("[DNS] [%s] %s -> %s %s | %s (Client Route (%s)) | %s",
							protocol, localClientID, originalQName, qtypeName(q.Qtype), statusMark, ctx.routeOriginType, actionLogStr)
					}
				}
				return ctx, true // Intercepted
			}
		}

		if clientRoute.Upstream != "" {
			ctx.routeName = clientRoute.Upstream
			ctx.routeIdx = getRouteIdx(clientRoute.Upstream)
		}
		ctx.bypassLocal = clientRoute.BypassLocal
	}

	// ── 3. Apply Domain Routing Properties ────────────────────────────────
	if domainRouteMatched && !(clientRouteMatched && clientRoute.Force) {
		ctx.routeName = domainRouteUpstream
		ctx.routeIdx = getRouteIdx(domainRouteUpstream)
		ctx.routeOriginType = "DOMAIN"
		ctx.bypassLocal = domainRouteBypass
	}

	return ctx, false
}
