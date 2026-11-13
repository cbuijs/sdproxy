/*
File:    init_routing.go
Version: 1.12.0
Last Updated: 04-Nov-2026 19:38 CET

Description:
  Parses and maps client-based and domain-based routing rules for sdproxy.
  Translates YAML configurations (MAC, EDNS0 MAC, IP, CIDR, ECS, ASN, Country, SNI, Path, Port, Name) into 
  highly optimized lookup tables used by the routing engine.

Changes:
  1.12.0 - [FIX] Enabled `[WARN]` logs in `initClientRoutes` and `initDomainRoutes`
           when `logSystem` or `logRouting` is active so Simple Logging Mode
           (`logSimple: true`) retains all configuration and file-read warnings.
  1.11.0 - [FEAT] Added `rkEDNSMAC` and `rkEDNSMACGlob` initialization bindings in
           `initClientRoutes` to populate `ednsMACRoutes` and `ednsMACWildRoutes`
           for EDNS0 Option 65001 (`mac:`) matching.
  1.10.0 - [FIX] Handled `rkInvalid` in `initClientRoutes` to log a warning and
           skip malformed `ecs:`, `port:`, `sni:`, and `path:` route keys.
         - [FIX] Normalized `path:` keys with `strings.TrimSpace` and leading `/`
           enforcement.
  1.9.0  - [FEAT] Added `rkECSIP` and `rkECSCIDR` initialization bindings in
           `initClientRoutes`.
  1.8.0  - [FIX] Normalized `sni:` and `path:` prefix stripping to be case-insensitive
           and preserved root path `"/"`.
  1.7.1  - [FIX] Removed duplicate `compoundRouteMap`, `compoundRouteMappings`, and `portRoutes`
           definitions.
  1.7.0  - [FEAT] Added initialization bindings for the newly supported `port:` identifier natively.
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

func initClientRoutes() {
	macRoutes = make(map[string]ParsedRoute)
	ednsMACRoutes = make(map[string]ParsedRoute)
	ipRoutes = make(map[string]ParsedRoute)
	ecsIPRoutes = make(map[string]ParsedRoute)
	asnRoutes = make(map[string]ParsedRoute)
	countryRoutes = make(map[string]ParsedRoute)
	clientNameRoutes = make(map[string]ParsedRoute)
	sniRoutes = make(map[string]ParsedRoute)
	pathRoutes = make(map[string]ParsedRoute)
	portRoutes = make(map[string]ParsedRoute)
	macWildRoutes = nil
	ednsMACWildRoutes = nil
	cidrRoutes = nil
	ecsCIDRRoutes = nil
	compoundRouteMappings = nil

	processRoute := func(rawKey string, route RouteConfig) {
		pr := ParsedRoute{
			Upstream:     route.Upstream,
			ClientName:   route.ClientName,
			BypassLocal:  route.BypassLocal,
			BypassGlobal: route.BypassGlobal,
			Force:        route.Force,
			ForceAnd:     route.ForceAnd,
		}

		targetStr := route.Upstream

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
					if logRouting || logSystem {
						log.Printf("[WARN] routes: unknown RCODE %q for %q — ignored", route.Rcode, rawKey)
					}
					targetStr = route.Upstream
				} else {
					pr.HasRcode = true
					pr.Rcode = rcode
				}
			}
		}

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

		if targetStr == "" && !pr.HasRcode {
			targetStr = "default"
		}

		var props []string
		if pr.BypassLocal {
			props = append(props, "bypass_local=true")
		}
		if pr.BypassGlobal {
			props = append(props, "bypass_global=true")
		}
		if pr.Force {
			props = append(props, "force=true")
		}
		if pr.ForceAnd {
			props = append(props, "force-and=true")
		}
		propStr := ""
		if len(props) > 0 {
			propStr = " (" + strings.Join(props, ", ") + ")"
		}

		keys := strings.Split(rawKey, ",")
		var validKeys []string
		for _, key := range keys {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if classifyRouteKey(key) == rkInvalid {
				if logRouting || logSystem {
					log.Printf("[WARN] routes: invalid route key %q — skipped", key)
				}
				if pr.ForceAnd {
					return
				}
				continue
			}
			validKeys = append(validKeys, key)
		}

		if len(validKeys) == 0 {
			return
		}

		if pr.ForceAnd && len(validKeys) > 1 {
			compoundRouteMappings = append(compoundRouteMappings, compoundRouteMap{keys: validKeys, route: pr})
			if logRouting {
				log.Printf("[INIT] Compound Route (AND): %s -> %s%s", strings.Join(validKeys, " + "), targetStr, propStr)
			}
			return
		}

		for _, key := range validKeys {
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
			case rkEDNSMAC:
				if mac, err := net.ParseMAC(parseMACKey(key)); err == nil {
					ednsMACRoutes[mac.String()] = pr
					if logRouting {
						log.Printf("[INIT] EDNS0 MAC Route: %s -> %s%s", mac, targetStr, propStr)
					}
				}
			case rkEDNSMACGlob:
				pat := normaliseMACGlob(parseMACKey(key))
				ednsMACWildRoutes = append(ednsMACWildRoutes, macWildRoute{pattern: pat, route: pr})
				if logRouting {
					log.Printf("[INIT] EDNS0 MAC Glob Route: %s -> %s%s", pat, targetStr, propStr)
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
					cidrRoutes = append(cidrRoutes, cidrRouteEntry{net: prefix.Masked(), route: pr})
					if logRouting {
						log.Printf("[INIT] CIDR Route: %s -> %s%s", prefix.Masked().String(), targetStr, propStr)
					}
				}
			case rkECSIP:
				if ip, err := netip.ParseAddr(parseECSKey(key)); err == nil {
					ecsIPRoutes[ip.Unmap().String()] = pr
					if logRouting {
						log.Printf("[INIT] ECS IP Route: %s -> %s%s", ip.Unmap().String(), targetStr, propStr)
					}
				}
			case rkECSCIDR:
				if prefix, err := ParsePrefixUnmapped(parseECSKey(key)); err == nil {
					ecsCIDRRoutes = append(ecsCIDRRoutes, cidrRouteEntry{net: prefix.Masked(), route: pr})
					if logRouting {
						log.Printf("[INIT] ECS CIDR Route: %s -> %s%s", prefix.Masked().String(), targetStr, propStr)
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
				sni := lowerTrimDot(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(key), "sni:")))
				sniRoutes[sni] = pr
				if logRouting {
					log.Printf("[INIT] SNI Route: %s -> %s%s", sni, targetStr, propStr)
				}
			case rkPath:
				p := strings.ToLower(key)
				if strings.HasPrefix(p, "path:") {
					p = strings.TrimSpace(strings.TrimPrefix(p, "path:"))
				}
				if p != "" && p[0] != '/' {
					p = "/" + p
				}
				if len(p) > 1 {
					p = strings.TrimSuffix(p, "/")
				}
				pathRoutes[p] = pr
				if logRouting {
					log.Printf("[INIT] Path Route: %s -> %s%s", p, targetStr, propStr)
				}
			case rkPort:
				if p, ok := parsePort(key); ok {
					portRoutes[p] = pr
					if logRouting {
						log.Printf("[INIT] Port Route: %s -> %s%s", p, targetStr, propStr)
					}
				}
			case rkClientName:
				clientNameRoutes[strings.ToLower(key)] = pr
				if logRouting {
					log.Printf("[INIT] Client Name Route: %s -> %s%s", key, targetStr, propStr)
				}
			}
		}
	}

	for rawKey, route := range cfg.Routes {
		processRoute(rawKey, route)
	}

	for filePath, route := range cfg.RoutesFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			if logRouting || logSystem {
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
	hasEDNSMACRoutes = len(ednsMACRoutes) > 0
	hasEDNSMACWildRoutes = len(ednsMACWildRoutes) > 0
	hasIPRoutes = len(ipRoutes) > 0
	hasCIDRRoutes = len(cidrRoutes) > 0
	hasECSIPRoutes = len(ecsIPRoutes) > 0
	hasECSCIDRRoutes = len(ecsCIDRRoutes) > 0
	hasASNRoutes = len(asnRoutes) > 0
	hasCountryRoutes = len(countryRoutes) > 0
	hasClientNameRoutes = len(clientNameRoutes) > 0
	hasSNIRoutes = len(sniRoutes) > 0
	hasPathRoutes = len(pathRoutes) > 0
	hasPortRoutes = len(portRoutes) > 0

	if len(cidrRoutes) > 0 {
		sort.SliceStable(cidrRoutes, func(i, j int) bool {
			return cidrRoutes[i].net.Bits() > cidrRoutes[j].net.Bits()
		})
	}
	if len(ecsCIDRRoutes) > 0 {
		sort.SliceStable(ecsCIDRRoutes, func(i, j int) bool {
			return ecsCIDRRoutes[i].net.Bits() > ecsCIDRRoutes[j].net.Bits()
		})
	}
}

func initDomainRoutes() {
	domainRoutes = make(map[string]domainRouteEntry, len(cfg.DomainRoutes))

	processDomainRoute := func(rawDomain string, dr DomainRouteConfig) {
		if dr.Upstream == "" {
			if logRouting || logSystem {
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
			if logRouting || logSystem {
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
