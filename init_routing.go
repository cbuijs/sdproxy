/*
File:    init_routing.go
Version: 1.5.0
Updated: 30-Jun-2026 09:46 CEST

Description:
  Parses and maps client-based and domain-based routing rules for sdproxy.
  Translates YAML configurations (MAC, IP, CIDR, ASN, Country, SNI, Path, Name) into 
  highly optimized lookup tables used by the routing engine.

Changes:
  1.5.0 - [FEAT] Initialized parsing bindings natively for newly supported `CC:` 
          Country Code boundary constraints.
  1.4.0 - [REFACTOR] Inherited `ParsePrefixUnmapped` from `process_helpers.go`.
          Enforces uniform CIDR extraction boundaries cleanly natively.
  1.3.0 - [SECURITY/FIX] Embedded `Unmap()` normalization algorithms directly 
          into `rkCIDR` network evaluations. Neutralizes routing bypasses where 
          IPv4-mapped IPv6 identifiers failed to intercept standard IPv4 stubs natively.
*/

package main

import (
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// initClientRoutes parses the `routes:` and `routes_files:` configurations and populates
// the global mapping tables for MAC, IP, CIDR, ASN, Country, SNI, Path, and Client-Name routing.
func initClientRoutes() {
	macRoutes = make(map[string]ParsedRoute)
	ipRoutes = make(map[string]ParsedRoute)
	asnRoutes = make(map[string]ParsedRoute)
	countryRoutes = make(map[string]ParsedRoute)
	clientNameRoutes = make(map[string]ParsedRoute)
	sniRoutes = make(map[string]ParsedRoute)
	pathRoutes = make(map[string]ParsedRoute)
	macWildRoutes = nil
	cidrRoutes = nil

	processRoute := func(rawKey string, route RouteConfig) {
		pr := ParsedRoute{
			Upstream:    route.Upstream,
			ClientName:  route.ClientName,
			BypassLocal: route.BypassLocal,
			Force:       route.Force,
		}

		targetStr := route.Upstream

		// RCODE (Return Code) Validation - Absolute highest priority override
		if route.Rcode != "" {
			actionStr := strings.ToUpper(strings.TrimSpace(route.Rcode))
			targetStr = "RCODE:" + actionStr

			if actionStr == "DROP" {
				pr.HasRcode = true
				pr.Rcode = PolicyActionDrop
			} else if actionStr == "BLOCK" {
				pr.HasRcode = true
				pr.Rcode = PolicyActionBlock
			} else {
				rcode, ok := dns.StringToRcode[actionStr]
				if !ok {
					if logRouting {
						log.Printf("[WARN] routes: unknown RCODE %q for %q — ignored", route.Rcode, rawKey)
					}
					targetStr = route.Upstream
				} else {
					pr.HasRcode = true
					pr.Rcode = rcode
				}
			}
		}

		// Fallbacks mapping (RCODE -> UPSTREAM -> GROUP)
		if pr.Upstream == "" && route.Group != "" && !pr.HasRcode {
			if grp, ok := cfg.Groups[route.Group]; ok && grp.Upstream != "" {
				pr.Upstream = grp.Upstream
				if !pr.HasRcode {
					targetStr = pr.Upstream
				}
			}
			if !pr.BypassLocal && route.Group != "" {
				if grp, ok := cfg.Groups[route.Group]; ok {
					pr.BypassLocal = grp.BypassLocal
				}
			}
		}

		// Purely cosmetic resolution for the initialization logs if nothing was explicitly set
		if targetStr == "" && !pr.HasRcode {
			targetStr = "default"
		}

		var props []string
		if pr.BypassLocal {
			props = append(props, "bypass_local=true")
		}
		if pr.Force {
			props = append(props, "force=true")
		}
		propStr := ""
		if len(props) > 0 {
			propStr = " (" + strings.Join(props, ", ") + ")"
		}

		// Support grouping multiple identifiers via comma-separated syntax.
		for _, key := range strings.Split(rawKey, ",") {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}

			switch classifyRouteKey(key) {
			case rkMAC:
				if mac, err := net.ParseMAC(key); err == nil {
					macRoutes[mac.String()] = pr
					if logRouting {
						log.Printf("[INIT] MAC Route: %s -> %s%s", mac, targetStr, propStr)
					}
				}
			case rkMACGlob:
				macWildRoutes = append(macWildRoutes, macWildRoute{pattern: normaliseMACGlob(key), route: pr})
				if logRouting {
					log.Printf("[INIT] MAC Glob Route: %s -> %s%s", key, targetStr, propStr)
				}
			case rkIP:
				if ip, err := netip.ParseAddr(key); err == nil {
					ipRoutes[ip.Unmap().String()] = pr
					if logRouting {
						log.Printf("[INIT] IP Route: %s -> %s%s", ip.Unmap().String(), targetStr, propStr)
					}
				}
			case rkCIDR:
				if prefix, err := ParsePrefixUnmapped(key); err == nil {
					cidrRoutes = append(cidrRoutes, cidrRouteEntry{net: prefix, route: pr})
					if logRouting {
						log.Printf("[INIT] CIDR Route: %s -> %s%s", prefix.String(), targetStr, propStr)
					}
				}
			case rkASN:
				asn := strings.ToUpper(key)
				asnRoutes[asn] = pr
				if logRouting {
					log.Printf("[INIT] ASN Route: %s -> %s%s", asn, targetStr, propStr)
				}
			case rkCountry:
				cc := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(key), "CC:"))
				countryRoutes[cc] = pr
				if logRouting {
					log.Printf("[INIT] Country Route: %s -> %s%s", cc, targetStr, propStr)
				}
			case rkSNI:
				sni := strings.ToLower(strings.TrimPrefix(key, "sni:"))
				sniRoutes[sni] = pr
				if logRouting {
					log.Printf("[INIT] SNI Route: %s -> %s%s", sni, targetStr, propStr)
				}
			case rkPath:
				p := key
				if strings.HasPrefix(p, "path:") {
					p = strings.TrimPrefix(p, "path:")
				}
				p = strings.ToLower(strings.TrimSuffix(p, "/"))
				pathRoutes[p] = pr
				if logRouting {
					log.Printf("[INIT] Path Route: %s -> %s%s", p, targetStr, propStr)
				}
			case rkClientName:
				clientNameRoutes[strings.ToLower(key)] = pr
				if logRouting {
					log.Printf("[INIT] Client Name Route: %s -> %s%s", key, targetStr, propStr)
				}
			}
		}
	}

	// 1. Process inline routes map
	for rawKey, route := range cfg.Routes {
		processRoute(rawKey, route)
	}

	// 2. Process file-backed routes maps
	for filePath, route := range cfg.RoutesFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			if logRouting {
				log.Printf("[WARN] routes_files: cannot read %q: %v", filePath, err)
			}
			continue
		}
		if logRouting {
			log.Printf("[INIT] Loaded %d route(s) from file: %s", len(lines), filePath)
		}
		for _, line := range lines {
			processRoute(line, route)
		}
	}

	hasMACRoutes = len(macRoutes) > 0
	hasMACWildRoutes = len(macWildRoutes) > 0
	hasIPRoutes = len(ipRoutes) > 0
	hasCIDRRoutes = len(cidrRoutes) > 0
	hasASNRoutes = len(asnRoutes) > 0
	hasCountryRoutes = len(countryRoutes) > 0
	hasClientNameRoutes = len(clientNameRoutes) > 0
	hasSNIRoutes = len(sniRoutes) > 0
	hasPathRoutes = len(pathRoutes) > 0

	// [SECURITY/FIX] Sort CIDR Routes natively by prefix length descending (most specific wins)
	if len(cidrRoutes) > 0 {
		sort.SliceStable(cidrRoutes, func(i, j int) bool {
			return cidrRoutes[i].net.Bits() > cidrRoutes[j].net.Bits()
		})
	}
}

// initDomainRoutes parses `domain_routes:` and `domain_routes_files:` mapping suffix routes to targets.
func initDomainRoutes() {
	domainRoutes = make(map[string]domainRouteEntry, len(cfg.DomainRoutes))

	processDomainRoute := func(rawDomain string, dr DomainRouteConfig) {
		if dr.Upstream == "" {
			if logRouting {
				log.Printf("[WARN] domain_routes: entry %q has no upstream — skipped", rawDomain)
			}
			return
		}

		for _, domain := range strings.Split(rawDomain, ",") {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}

			clean := strings.ToLower(strings.TrimSuffix(domain, "."))
			domainRoutes[clean] = domainRouteEntry{
				upstream:    dr.Upstream,
				bypassLocal: dr.BypassLocal,
			}
			if logRouting {
				if dr.BypassLocal {
					log.Printf("[INIT] Domain Route: *.%s -> %s (bypass_local=true)", clean, dr.Upstream)
				} else {
					log.Printf("[INIT] Domain Route: *.%s -> %s", clean, dr.Upstream)
				}
			}
		}
	}

	for rawDomain, dr := range cfg.DomainRoutes {
		processDomainRoute(rawDomain, dr)
	}

	for filePath, dr := range cfg.DomainRoutesFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			if logRouting {
				log.Printf("[WARN] domain_routes_files: cannot read %q: %v", filePath, err)
			}
			continue
		}
		if logRouting {
			log.Printf("[INIT] Loaded %d domain route(s) from file: %s", len(lines), filePath)
		}
		for _, line := range lines {
			processDomainRoute(line, dr)
		}
	}

	hasDomainRoutes = len(domainRoutes) > 0
}

