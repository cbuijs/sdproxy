/*
File:    init_core.go
Version: 1.118.0
Last Updated: 23-Oct-2026 17:15 CEST

Description:
  High-level initialization orchestrator and general IO helpers for sdproxy.
  Dispatches specific tasks to init_routing, init_policy, and init_upstreams.

Changes:
  1.118.0 - [FEAT] Supported comma-separated domain and regex tokens in `initRRs`
            via `splitDomainPolicyKeys` for parity with `domain_policy:`.
  1.117.0 - [FEAT] Added regex domain key support (`/pattern/`) in `initRRs` for
            global `rrs:` and per-group `groups.<group>.rrs:`, with deterministic
            ordering and startup compilation validation.
  1.116.0 - [FEAT/FIX] Registered `ednsMACRoutes` and `ednsMACWildRoutes` in
            `initRouteIndex` so upstream groups referenced exclusively via `mac:`
            EDNS0 Option 65001 routes receive a dedicated cache partition index.
  1.115.0 - [FEAT/FIX] Registered `ecsIPRoutes` and `ecsCIDRRoutes` in `initRouteIndex`
            so upstream groups referenced exclusively via `ecs:` routes receive a
            dedicated cache partition index.
  1.114.0 - [SECURITY/FIX] Eradicated a critical Cache Persistence Corruption vulnerability natively.
  1.113.0 - [SECURITY/FIX] initRouteIndex() didn't register upstream group
            names referenced ONLY via a `port:` route (portRoutes) or a
            `force-and` compound route (compoundRouteMappings).
  1.112.0 - [DEAD-CODE/CLEANUP] Removed the orphaned readConfigListURL fetcher.
  1.111.0 - [TIER 2] syncDirForFile moved to helpers_io.go; readConfigListURL now
            shares the 10MB truncation-detection idiom with the policy loader.
  1.110.0 - [SECURITY/RELIABILITY] syncDirForFile deployed so atomic renames
            survive power loss on embedded routers.
*/

package main

import (
	"bufio"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const maxRemoteListBytes = 10 * 1024 * 1024

// readConfigListFile reads a file line by line, stripping whitespace and inline comments.
func readConfigListFile(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// initBlockAction parses the global 'BLOCK' definition.
func initBlockAction() {
	action := strings.ToUpper(strings.TrimSpace(cfg.Server.BlockAction))
	if action == "" || action == "NULL" {
		globalBlockAction = BlockActionNull
	} else if action == "DROP" {
		globalBlockAction = BlockActionDrop
	} else if action == "LOG" {
		globalBlockAction = BlockActionLog
	} else if action == "IP" {
		globalBlockAction = BlockActionIP
		for _, ipStr := range cfg.Server.BlockIPs {
			if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
				if ip.To4() != nil {
					globalBlockIPv4 = append(globalBlockIPv4, ip.To4())
				} else {
					globalBlockIPv6 = append(globalBlockIPv6, ip.To16())
				}
			}
		}
		if len(globalBlockIPv4) == 0 && len(globalBlockIPv6) == 0 {
			globalBlockAction = BlockActionNull
		}
	} else if rcode, ok := dns.StringToRcode[action]; ok {
		globalBlockAction = BlockActionRcode
		globalBlockRcode = rcode
	} else {
		globalBlockAction = BlockActionNull
	}
	if logSystem {
		log.Printf("[INIT] Global Block Action: %s", action)
	}
}

// initDGA parses the ML classification definitions for Domain Generation Algorithms.
func initDGA() {
	if cfg.Server.DGA.Enabled {
		hasDGA = true
		if cfg.Server.DGA.Threshold <= 0 {
			cfg.Server.DGA.Threshold = 80.0
		}
		if cfg.Server.DGA.Action == "" {
			cfg.Server.DGA.Action = "BLOCK"
		}
		if logSystem {
			log.Printf("[INIT] DGA ML Detection enabled (Threshold: %.1f, Action: %s)", cfg.Server.DGA.Threshold, cfg.Server.DGA.Action)
		}
	}
}

// initRouteIndex constructs the numerical lookup map required by the cache architecture.
func initRouteIndex() {
	routeIdxByName = make(map[string]uint16, len(cfg.Upstreams)+4)
	routeIdxByName["local"] = routeIdxLocal
	nextIdx := uint16(1)

	var names []string
	addName := func(name string) {
		if name != "" {
			names = append(names, name)
		}
	}

	for groupName := range routeUpstreams {
		addName(groupName)
	}
	for _, dr := range domainRoutes {
		addName(dr.upstream)
	}
	for _, route := range macRoutes {
		addName(route.Upstream)
	}
	for _, route := range macWildRoutes {
		addName(route.route.Upstream)
	}
	for _, route := range ednsMACRoutes {
		addName(route.Upstream)
	}
	for _, route := range ednsMACWildRoutes {
		addName(route.route.Upstream)
	}
	for _, route := range ipRoutes {
		addName(route.Upstream)
	}
	for _, cr := range cidrRoutes {
		addName(cr.route.Upstream)
	}
	for _, route := range ecsIPRoutes {
		addName(route.Upstream)
	}
	for _, cr := range ecsCIDRRoutes {
		addName(cr.route.Upstream)
	}
	for _, route := range asnRoutes {
		addName(route.Upstream)
	}
	for _, route := range countryRoutes {
		addName(route.Upstream)
	}
	for _, route := range clientNameRoutes {
		addName(route.Upstream)
	}
	for _, route := range sniRoutes {
		addName(route.Upstream)
	}
	for _, route := range pathRoutes {
		addName(route.Upstream)
	}
	for _, route := range portRoutes {
		addName(route.Upstream)
	}
	for _, cm := range compoundRouteMappings {
		addName(cm.route.Upstream)
	}

	// [SECURITY/FIX] Execute deterministic assignment ordering securely.
	sort.Strings(names)

	for _, name := range names {
		if _, exists := routeIdxByName[name]; !exists {
			if nextIdx == 65535 {
				log.Fatalf("[FATAL] Maximum number of isolated routing groups (65535) exceeded.")
			}
			routeIdxByName[name] = nextIdx
			nextIdx++
		}
	}

	routeIdxDefault = routeIdxByName["default"]
}

// initRRs parses global and per-group spoofed records (including regex domain keys).
func initRRs() {
	globalRRs = make(map[string]spoofRecord)
	globalRRRegexes = nil
	groupRRs = make(map[string]map[string]spoofRecord)
	groupRRRegexes = make(map[string][]spoofRegexRecord)

	parseRRMap := func(source map[string]interface{}, dest map[string]spoofRecord) []spoofRegexRecord {
		keys := make([]string, 0, len(source))
		for k := range source {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var regexes []spoofRegexRecord
		seenRegex := make(map[string]int)
		for _, k := range keys {
			v := source[k]
			var rec spoofRecord
			switch val := v.(type) {
			case string:
				if ip, err := netip.ParseAddr(strings.TrimSpace(val)); err == nil {
					rec.IPs = append(rec.IPs, ip.Unmap())
				} else {
					rec.CNAME = lowerTrimDot(val)
				}
			case []interface{}:
				for _, item := range val {
					if str, ok := item.(string); ok {
						if ip, err := netip.ParseAddr(strings.TrimSpace(str)); err == nil {
							rec.IPs = append(rec.IPs, ip.Unmap())
						}
					}
				}
			}

			for _, tok := range splitDomainPolicyKeys(k) {
				if isRegexKey(tok) {
					re, err := compileDomainRegex(tok)
					if err != nil {
						log.Fatalf("[FATAL] rrs: %v", err)
					}
					if idx, exists := seenRegex[tok]; exists {
						regexes[idx].rec = rec
					} else {
						seenRegex[tok] = len(regexes)
						regexes = append(regexes, spoofRegexRecord{
							raw: tok,
							re:  re,
							rec: rec,
						})
					}
					continue
				}

				domain := lowerTrimDot(tok)
				if domain != "" {
					dest[domain] = rec
				}
			}
		}
		return regexes
	}

	globalRRRegexes = parseRRMap(cfg.RRs, globalRRs)
	hasGroupRRs := false
	for grpName, grpCfg := range cfg.Groups {
		if len(grpCfg.RRs) > 0 {
			gm := make(map[string]spoofRecord)
			gr := parseRRMap(grpCfg.RRs, gm)
			if len(gm) > 0 {
				groupRRs[grpName] = gm
				hasGroupRRs = true
			}
			if len(gr) > 0 {
				groupRRRegexes[grpName] = gr
				hasGroupRRs = true
			}
		}
	}
	hasRRs = len(globalRRs) > 0 || len(globalRRRegexes) > 0 || hasGroupRRs
}

// initDDR maps RFC 9462 Discovery of Designated Resolvers endpoints.
func initDDR() {
	if cfg.Server.ECHConfigList != "" {
		if b, err := os.ReadFile(cfg.Server.ECHConfigList); err == nil {
			ddrECHConfig = b
		}
	}
	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		source := cfg.Server.DDR.HostnameSource
		if source == "" {
			source = "strict"
		}
		var raw []string
		if source == "strict" || source == "both" {
			raw = append(raw, cfg.Server.DDR.Hostnames...)
		}
		if source == "tls" || source == "both" {
			raw = append(raw, tlsAuthorizedNames...)
		}
		for _, h := range raw {
			clean := strings.ToLower(strings.TrimSuffix(h, "."))
			if clean != "" && !strings.Contains(clean, "*") && net.ParseIP(clean) == nil {
				if !ddrHostnames[clean] {
					ddrHostnames[clean] = true
					ddrHostnamesList = append(ddrHostnamesList, clean)
				}
			}
		}
		for _, s := range cfg.Server.DDR.IPv4 {
			if ip := net.ParseIP(s); ip != nil {
				ddrIPv4 = append(ddrIPv4, ip)
			}
		}
		for _, s := range cfg.Server.DDR.IPv6 {
			if ip := net.ParseIP(s); ip != nil {
				ddrIPv6 = append(ddrIPv6, ip)
			}
		}
		ddrDoHPort, ddrDoTPort, ddrDoQPort = 0, 0, 0
		for _, addr := range cfg.Server.ListenDoH {
			ddrDoHPort = extractPort(addr, 443)
		}
		for _, addr := range cfg.Server.ListenDoT {
			ddrDoTPort = extractPort(addr, 853)
		}
		for _, addr := range cfg.Server.ListenDoQ {
			ddrDoQPort = extractPort(addr, 853)
		}
	}
}

