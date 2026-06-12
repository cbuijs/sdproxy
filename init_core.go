/*
File:    init_core.go
Version: 1.108.0
Updated: 06-Jun-2026 14:47 CEST

Description:
  High-level initialization orchestrator and general IO helpers for sdproxy.
  Dispatches specific tasks to init_routing, init_policy, and init_upstreams.

Changes:
  1.108.0 - [SECURITY/FIX] Eradicated a Silent Truncation vulnerability natively 
            within `readConfigListURL`. The `LimitReader` now correctly evaluates 
            over-capacity byte exhaustion, completely rejecting the payload rather 
            than parsing incomplete lists and deploying fractured security constraints.
  1.107.0 - [SECURITY/FIX] Enforced strict `uint16` overflow boundaries natively within 
            the `assignIdx` loop. Prevents malicious or misconfigured arrays possessing 
            over 65,535 external endpoints from wrapping the dynamic index allocator 
            back to 0, which would fatally conflate external Upstream Groups with 
            the protected internal LAN identity resolver (`routeIdxLocal`).
  1.106.0 - [FIX] Remedied a silent routing mapping regression within `initRouteIndex`. 
            The index engine now strictly iterates across actively parsed memory maps 
            (`macRoutes`, `domainRoutes`, `cidrRoutes`) rather than structural 
            YAML representations. Definitively ensures file-loaded external routes 
            dynamically acquire isolated cache index partitions correctly natively.
*/

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

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

// readConfigListURL fetches a list of strings from a remote HTTP/HTTPS endpoint securely.
func readConfigListURL(urlStr string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.Server.UserAgent)

	resp, err := catHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad HTTP status code: %d", resp.StatusCode)
	}

	var lines []string
	
	// [SECURITY/FIX] CWE-400 Uncontrolled Resource Consumption Protection
	// Read precisely 1 byte beyond the maximum capacity limit to actively detect 
	// upstream truncation and reject the transaction natively.
	lr := io.LimitReader(resp.Body, 10*1024*1024+1)
	scanner := bufio.NewScanner(lr)
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
	
	// Evaluate Limit exhaustion natively to flag silent truncations.
	// Prevents parsing and deploying an incomplete security/routing list organically.
	if scanner.Err() == nil && lr.(*io.LimitedReader).N == 0 {
		return nil, fmt.Errorf("security constraint: remote list exceeded 10MB maximum buffer capacity")
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
				if ip.To4() != nil { globalBlockIPv4 = append(globalBlockIPv4, ip.To4()) } else { globalBlockIPv6 = append(globalBlockIPv6, ip.To16()) }
			}
		}
		if len(globalBlockIPv4) == 0 && len(globalBlockIPv6) == 0 { globalBlockAction = BlockActionNull }
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
		if cfg.Server.DGA.Threshold <= 0 { cfg.Server.DGA.Threshold = 80.0 }
		if cfg.Server.DGA.Action == "" { cfg.Server.DGA.Action = "BLOCK" }
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
	
	assignIdx := func(name string) {
		if name == "" {
			return 
		}
		if _, exists := routeIdxByName[name]; !exists {
			// [SECURITY/FIX] Enforce strict uint16 overflow boundaries natively.
			// Prevents the dynamic index allocator from wrapping back to 0 (routeIdxLocal),
			// which would catastrophically conflate external Upstream Groups with 
			// the protected internal LAN identity resolver.
			if nextIdx == 65535 {
				log.Fatalf("[FATAL] Maximum number of isolated routing groups (65535) exceeded natively.")
			}
			routeIdxByName[name] = nextIdx
			nextIdx++
		}
	}
	
	// Dynamically register boundaries leveraging fully parsed internal maps
	for groupName := range routeUpstreams { assignIdx(groupName) }
	
	for _, dr := range domainRoutes { assignIdx(dr.upstream) }
	
	for _, route := range macRoutes { assignIdx(route.Upstream) }
	for _, route := range macWildRoutes { assignIdx(route.route.Upstream) }
	for _, route := range ipRoutes { assignIdx(route.Upstream) }
	for _, cr := range cidrRoutes { assignIdx(cr.route.Upstream) }
	for _, route := range asnRoutes { assignIdx(route.Upstream) }
	for _, route := range clientNameRoutes { assignIdx(route.Upstream) }
	for _, route := range sniRoutes { assignIdx(route.Upstream) }
	for _, route := range pathRoutes { assignIdx(route.Upstream) }

	routeIdxDefault = routeIdxByName["default"]
}

// initRRs parses global and per-group spoofed records natively
func initRRs() {
	globalRRs = make(map[string]spoofRecord)
	groupRRs = make(map[string]map[string]spoofRecord)

	parseRRMap := func(source map[string]interface{}, dest map[string]spoofRecord) {
		for k, v := range source {
			domain := lowerTrimDot(k)
			var rec spoofRecord
			switch val := v.(type) {
			case string:
				if ip, err := netip.ParseAddr(strings.TrimSpace(val)); err == nil { rec.IPs = append(rec.IPs, ip.Unmap()) } else { rec.CNAME = lowerTrimDot(val) }
			case []interface{}:
				for _, item := range val {
					if str, ok := item.(string); ok {
						if ip, err := netip.ParseAddr(strings.TrimSpace(str)); err == nil { rec.IPs = append(rec.IPs, ip.Unmap()) }
					}
				}
			}
			dest[domain] = rec
		}
	}
	parseRRMap(cfg.RRs, globalRRs)
	for grpName, grpCfg := range cfg.Groups {
		if len(grpCfg.RRs) > 0 {
			gm := make(map[string]spoofRecord)
			parseRRMap(grpCfg.RRs, gm)
			groupRRs[grpName] = gm
		}
	}
	hasRRs = len(globalRRs) > 0 || len(groupRRs) > 0
}

// initDDR maps RFC 9462 Discovery of Designated Resolvers endpoints.
func initDDR() {
	if cfg.Server.ECHConfigList != "" {
		if b, err := os.ReadFile(cfg.Server.ECHConfigList); err == nil { ddrECHConfig = b }
	}
	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		source := cfg.Server.DDR.HostnameSource
		if source == "" { source = "strict" }
		var raw []string
		if source == "strict" || source == "both" { raw = append(raw, cfg.Server.DDR.Hostnames...) }
		if source == "tls" || source == "both" { raw = append(raw, tlsAuthorizedNames...) }
		for _, h := range raw {
			clean := strings.ToLower(strings.TrimSuffix(h, "."))
			if clean != "" && !strings.Contains(clean, "*") && net.ParseIP(clean) == nil {
				if !ddrHostnames[clean] { ddrHostnames[clean] = true; ddrHostnamesList = append(ddrHostnamesList, clean) }
			}
		}
		for _, s := range cfg.Server.DDR.IPv4 { if ip := net.ParseIP(s); ip != nil { ddrIPv4 = append(ddrIPv4, ip) } }
		for _, s := range cfg.Server.DDR.IPv6 { if ip := net.ParseIP(s); ip != nil { ddrIPv6 = append(ddrIPv6, ip) } }
		ddrDoHPort, ddrDoTPort, ddrDoQPort = 0, 0, 0
		for _, addr := range cfg.Server.ListenDoH { ddrDoHPort = extractPort(addr, 443) }
		for _, addr := range cfg.Server.ListenDoT { ddrDoTPort = extractPort(addr, 853) }
		for _, addr := range cfg.Server.ListenDoQ { ddrDoQPort = extractPort(addr, 853) }
	}
}

