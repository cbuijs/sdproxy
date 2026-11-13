/*
File:    init_core.go
Version: 1.120.0
Last Updated: 05-Nov-2026 14:15 CET

Description:
  High-level initialization orchestrator and general IO helpers for sdproxy.
  Dispatches specific tasks to init_routing, init_policy, and init_upstreams.

Changes:
  1.120.0 - [FEAT] Added `initProximityAddrs` to harvest explicit listener IPs,
            DDR IPs, local outbound source IPs toward configured upstreams, and
            active network interface unicast IPs to populate `proximityRefV4` and
            `proximityRefV6` for `answer_sort: "proximity"`.
  1.119.0 - [SECURITY/FIX] Validated non-empty `spoofRecord` values (`rec.CNAME != ""`
            or `len(rec.IPs) > 0`) in `initRRs` before registering exact or regex
            entries so empty or malformed `rrs:` targets are skipped with a warning
            rather than blackholing matching domains.
  1.118.0 - [FEAT] Supported comma-separated domain and regex tokens in `initRRs`
            via `splitDomainPolicyKeys` for parity with `domain_policy:`.
  1.117.0 - [FEAT] Added regex domain key support (`/pattern/`) in `initRRs` for
            global `rrs:` and per-group `groups.<group>.rrs:`, with deterministic
            ordering and startup compilation validation.
  1.116.0 - [FEAT/FIX] Registered `ednsMACRoutes` and `ednsMACWildRoutes` in
            `initRouteIndex`.
  1.115.0 - [FEAT/FIX] Registered `ecsIPRoutes` and `ecsCIDRRoutes` in `initRouteIndex`.
  1.114.0 - [SECURITY/FIX] Eradicated a critical Cache Persistence Corruption vulnerability natively.
  1.113.0 - [SECURITY/FIX] initRouteIndex() didn't register upstream group
            names referenced ONLY via a `port:` route (portRoutes) or a
            `force-and` compound route (compoundRouteMappings).
  1.112.0 - [DEAD-CODE/CLEANUP] Removed the orphaned readConfigListURL fetcher.
  1.111.0 - [TIER 2] syncDirForFile moved to helpers_io.go.
*/

package main

import (
	"bufio"
	"encoding/binary"
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
					rec.CNAME = lowerTrimDot(strings.TrimSpace(val))
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

			if rec.CNAME == "" && len(rec.IPs) == 0 {
				if logSystem || logRouting {
					log.Printf("[WARN] rrs: entry %q has no valid IP or CNAME target — skipped", k)
				}
				continue
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

// initProximityAddrs harvests all local listener IP addresses, local interface
// addresses (when listening on 0.0.0.0 / ::), and local source IP addresses
// used for outbound upstream queries to populate proximityRefV4 and proximityRefV6.
func initProximityAddrs() {
	seen := make(map[netip.Addr]struct{})
	var v4s []uint32
	var v6s [][2]uint64
	var logList []string

	addAddr := func(addr netip.Addr) {
		if !addr.IsValid() {
			return
		}
		addr = addr.Unmap().WithZone("")
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			return
		}
		if ipVersionSupport == "ipv4" && !addr.Is4() {
			return
		}
		if ipVersionSupport == "ipv6" && !addr.Is6() {
			return
		}
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		logList = append(logList, addr.String())

		if addr.Is4() {
			b := addr.As4()
			v4s = append(v4s, binary.BigEndian.Uint32(b[:]))
		} else if addr.Is6() {
			b := addr.As16()
			v6s = append(v6s, [2]uint64{
				binary.BigEndian.Uint64(b[0:8]),
				binary.BigEndian.Uint64(b[8:16]),
			})
		}
	}

	addAddrStr := func(s string) (wasUnspecified bool) {
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if host == "" {
			return true
		}
		if a, err := netip.ParseAddr(host); err == nil {
			a = a.Unmap().WithZone("")
			if a.IsUnspecified() {
				return true
			}
			addAddr(a)
		}
		return false
	}

	hasWildcardListener := false
	for _, list := range [][]string{
		cfg.Server.ListenUDP,
		cfg.Server.ListenTCP,
		cfg.Server.ListenDoT,
		cfg.Server.ListenDoH,
		cfg.Server.ListenDoQ,
	} {
		for _, raw := range list {
			if addAddrStr(raw) {
				hasWildcardListener = true
			}
		}
	}

	for _, s := range cfg.Server.DDR.IPv4 {
		addAddrStr(s)
	}
	for _, s := range cfg.Server.DDR.IPv6 {
		addAddrStr(s)
	}

	probeTargets := make(map[string]struct{})
	addProbeTarget := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		host, port, err := net.SplitHostPort(raw)
		if err != nil {
			host = raw
			port = "53"
		}
		if a, err := netip.ParseAddr(host); err == nil {
			a = a.Unmap().WithZone("")
			if a.IsValid() && !a.IsUnspecified() {
				probeTargets[net.JoinHostPort(a.String(), port)] = struct{}{}
			}
		}
	}

	for _, grp := range routeUpstreams {
		if grp == nil {
			continue
		}
		for _, u := range grp.Servers {
			if u == nil {
				continue
			}
			for _, dAddr := range u.dialAddrs {
				addProbeTarget(dAddr)
			}
			for _, bIP := range u.BootstrapIPs {
				addProbeTarget(bIP)
			}
		}
	}
	for _, u := range globalBootstrapServers {
		if u == nil {
			continue
		}
		for _, dAddr := range u.dialAddrs {
			addProbeTarget(dAddr)
		}
		for _, bIP := range u.BootstrapIPs {
			addProbeTarget(bIP)
		}
	}

	// Probe OS routing table via zero-packet UDP socket binds to discover exact
	// local source IP addresses used for associated outgoing upstream queries.
	for target := range probeTargets {
		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
			if a, ok := netip.AddrFromSlice(ua.IP); ok {
				addAddr(a)
			}
		} else {
			addAddrStr(conn.LocalAddr().String())
		}
		conn.Close()
	}

	if hasWildcardListener || len(seen) == 0 {
		if ifAddrs, err := net.InterfaceAddrs(); err == nil {
			for _, ifa := range ifAddrs {
				var ip net.IP
				switch v := ifa.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil {
					continue
				}
				if a, ok := netip.AddrFromSlice(ip); ok {
					a = a.Unmap().WithZone("")
					if a.IsLoopback() && len(seen) > 0 {
						continue
					}
					addAddr(a)
				}
			}
		}
	}

	proximityRefV4 = v4s
	proximityRefV6 = v6s

	if cfg.Cache.AnswerSort == "proximity" && (logCaching || logSystem) {
		log.Printf("[CACHE] Proximity answer sorting reference IPs (%d IPv4, %d IPv6): %s",
			len(v4s), len(v6s), strings.Join(logList, ", "))
	}
}
