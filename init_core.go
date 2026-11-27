/*
File:    init_core.go
Version: 1.123.0
Last Updated: 27-Nov-2026 13:30 CET

Description:
  High-level initialization orchestrator and general IO helpers for sdproxy.
  Dispatches specific tasks to init_routing, init_policy, and init_upstreams.

Changes:
  1.123.0 - [CLEANUP] Removed dead `"local": 0` reservation from `initRouteIndex`
            since local-identity cache items are distinguished by `routeLocalTag`.
  1.122.0 - [FIX] Filtered DDR listener port discovery (`pickDDRPort`) through
            `filterListeners`, preferred non-loopback listener ports, and
            canonicalized `ddrIPv4` / `ddrIPv6` slices.
  1.121.0 - [PERF] Pre-initialized static `net.IP` block-IP templates
            (`globalBlockIPv4` and `globalBlockIPv6`) in `initBlockAction`.
  1.120.0 - [FEAT] Added `initProximityAddrs` to populate `proximityRefV4` and
            `proximityRefV6` for `answer_sort: "proximity"`.
  1.119.0 - [SECURITY/FIX] Validated non-empty `spoofRecord` values in `initRRs`.
  1.118.0 - [FEAT] Supported comma-separated domain and regex tokens in `initRRs`.
  1.117.0 - [FEAT] Added regex domain key support (`/pattern/`) in `initRRs`.
  1.116.0 - [FEAT/FIX] Registered `ednsMACRoutes` and `ednsMACWildRoutes` in
            `initRouteIndex`.
  1.115.0 - [FEAT/FIX] Registered `ecsIPRoutes` and `ecsCIDRRoutes` in
            `initRouteIndex`.
  1.114.0 - [SECURITY/FIX] Fixed Cache Persistence route index consistency.
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

func initBlockAction() {
	globalBlockIPv4 = nil
	globalBlockIPv6 = nil

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
			if addr, err := netip.ParseAddr(strings.TrimSpace(ipStr)); err == nil {
				addr = addr.Unmap()
				if addr.Is4() {
					b4 := addr.As4()
					ip4 := make(net.IP, net.IPv4len)
					copy(ip4, b4[:])
					globalBlockIPv4 = append(globalBlockIPv4, ip4)
				} else if addr.Is6() {
					b16 := addr.As16()
					ip6 := make(net.IP, net.IPv6len)
					copy(ip6, b16[:])
					globalBlockIPv6 = append(globalBlockIPv6, ip6)
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

func initRouteIndex() {
	routeIdxByName = make(map[string]uint16, len(cfg.Upstreams)+4)
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

func pickDDRPort(addrs []string, defaultPort uint16) uint16 {
	active := filterListeners(addrs)
	if len(active) == 0 {
		return 0
	}
	var fallback uint16
	for _, addr := range active {
		p := extractPort(addr, defaultPort)
		if fallback == 0 {
			fallback = p
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return p
		}
		if a, pErr := netip.ParseAddr(host); pErr == nil && a.Unmap().IsLoopback() {
			continue
		}
		return p
	}
	return fallback
}

func initDDR() {
	ddrECHConfig = nil
	if cfg.Server.ECHConfigList != "" {
		if b, err := os.ReadFile(cfg.Server.ECHConfigList); err == nil {
			ddrECHConfig = b
		}
	}
	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		ddrHostnamesList = nil
		ddrIPv4 = nil
		ddrIPv6 = nil

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
			clean := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
			if clean != "" && !strings.Contains(clean, "*") && net.ParseIP(clean) == nil {
				if !ddrHostnames[clean] {
					ddrHostnames[clean] = true
					ddrHostnamesList = append(ddrHostnamesList, clean)
				}
			}
		}
		if ipVersionSupport != "ipv6" {
			for _, s := range cfg.Server.DDR.IPv4 {
				if addr, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && addr.Unmap().Is4() {
					b4 := addr.Unmap().As4()
					ip4 := make(net.IP, net.IPv4len)
					copy(ip4, b4[:])
					ddrIPv4 = append(ddrIPv4, ip4)
				}
			}
		}
		if ipVersionSupport != "ipv4" {
			for _, s := range cfg.Server.DDR.IPv6 {
				if addr, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && addr.Is6() && !addr.Is4In6() {
					b16 := addr.As16()
					ip6 := make(net.IP, net.IPv6len)
					copy(ip6, b16[:])
					ddrIPv6 = append(ddrIPv6, ip6)
				}
			}
		}
		ddrDoHPort = pickDDRPort(cfg.Server.ListenDoH, 443)
		ddrDoTPort = pickDDRPort(cfg.Server.ListenDoT, 853)
		ddrDoQPort = pickDDRPort(cfg.Server.ListenDoQ, 853)
	}
}

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
		for _, raw := range filterListeners(list) {
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
