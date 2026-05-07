/*
File:    init_core.go
Version: 1.101.0 (Split)
Updated: 07-May-2026 09:20 CEST

Description:
  Configuration translation and global state mapping for sdproxy.
  Extracts raw YAML configurations and supplementary list-files into highly-optimized,
  memory-resident routing tables, policy maps, and upstream connection targets.

Changes:
  1.101.0 - [FEAT] Integrated `initRRs()` natively to parse and securely bound the 
           explicit A/AAAA/CNAME structural requirements of the `rrs:` (Spoofed Records)
           configuration payloads.
  1.100.0 - [SECURITY/PERF] Normalized raw IP addresses within Domain Policy lists 
           into strict /32 and /128 CIDR boundaries natively. Eradicates severe 
           CPU penalties caused by routing raw IP strings into the domain suffix-walking engine.
*/

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
	
	// Expand capacity to prevent buffer-too-long errors natively
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Strip inline comments if present
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		if len(lines) == 0 {
			return nil, err
		}
		log.Printf("[INIT] WARNING: Partial scanner error reading %s: %v", filePath, err)
	}
	return lines, nil
}

// readConfigListURL fetches a list of strings from a remote HTTP/HTTPS endpoint securely.
// It enforces a 10MB payload limit to prevent memory exhaustion attacks and strips
// whitespace and inline comments natively.
func readConfigListURL(urlStr string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	// Identify ourselves gracefully utilizing the configured agent string
	req.Header.Set("User-Agent", cfg.Server.UserAgent)

	// Leverage the globally available, hardened internal HTTP client 
	// defined in parental_loader.go
	resp, err := catHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad HTTP status code: %d", resp.StatusCode)
	}

	var lines []string
	// Hardened limit: Cap the readable payload to 10MB to prevent malicious 
	// infinite-stream or memory exhaustion attacks from compromised endpoints.
	lr := io.LimitReader(resp.Body, 10*1024*1024)
	scanner := bufio.NewScanner(lr)
	
	// Expand capacity to prevent buffer-too-long errors natively
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Strip inline comments if present
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		if len(lines) == 0 {
			return nil, err
		}
		log.Printf("[INIT] WARNING: Partial scanner error fetching %s: %v", urlStr, err)
	}
	return lines, nil
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
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}
			if ip := net.ParseIP(ipStr); ip != nil {
				if ip.To4() != nil {
					globalBlockIPv4 = append(globalBlockIPv4, ip.To4())
				} else {
					globalBlockIPv6 = append(globalBlockIPv6, ip.To16())
				}
			} else {
				log.Printf("[WARN] Invalid IP in server.block_ips: %s", ipStr)
			}
		}
		if len(globalBlockIPv4) == 0 && len(globalBlockIPv6) == 0 {
			log.Printf("[WARN] Block action is 'IP' but no valid block_ips provided. Falling back to 'NULL'.")
			globalBlockAction = BlockActionNull
		}
	} else {
		rcode, ok := dns.StringToRcode[action]
		if !ok {
			log.Printf("[WARN] Unknown block_action %q. Falling back to 'NULL'.", action)
			globalBlockAction = BlockActionNull
		} else {
			globalBlockAction = BlockActionRcode
			globalBlockRcode = rcode
		}
	}
	log.Printf("[INIT] Global Block Action: %s", action)
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
		log.Printf("[INIT] DGA ML Detection enabled (Threshold: %.1f, Action: %s)", cfg.Server.DGA.Threshold, cfg.Server.DGA.Action)
	} else {
		log.Println("[INIT] DGA ML Detection disabled.")
	}
}

// initClientRoutes parses the `routes:` and `routes_files:` configurations and populates
// the global mapping tables for MAC, IP, CIDR, ASN, SNI, Path, and Client-Name routing.
func initClientRoutes() {
	macRoutes = make(map[string]ParsedRoute)
	ipRoutes = make(map[string]ParsedRoute)
	asnRoutes = make(map[string]ParsedRoute)
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
					log.Printf("[WARN] routes: unknown RCODE %q for %q — ignored", route.Rcode, rawKey)
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
					log.Printf("[INIT] MAC Route: %s -> %s%s", mac, targetStr, propStr)
				}
			case rkMACGlob:
				macWildRoutes = append(macWildRoutes, macWildRoute{pattern: normaliseMACGlob(key), route: pr})
				log.Printf("[INIT] MAC Glob Route: %s -> %s%s", key, targetStr, propStr)
			case rkIP:
				if ip, err := netip.ParseAddr(key); err == nil {
					ipRoutes[ip.Unmap().String()] = pr
					log.Printf("[INIT] IP Route: %s -> %s%s", ip.Unmap().String(), targetStr, propStr)
				}
			case rkCIDR:
				if prefix, err := netip.ParsePrefix(key); err == nil {
					cidrRoutes = append(cidrRoutes, cidrRouteEntry{net: prefix, route: pr})
					log.Printf("[INIT] CIDR Route: %s -> %s%s", prefix.String(), targetStr, propStr)
				}
			case rkASN:
				asn := strings.ToUpper(key)
				asnRoutes[asn] = pr
				log.Printf("[INIT] ASN Route: %s -> %s%s", asn, targetStr, propStr)
			case rkSNI:
				sni := strings.ToLower(strings.TrimPrefix(key, "sni:"))
				sniRoutes[sni] = pr
				log.Printf("[INIT] SNI Route: %s -> %s%s", sni, targetStr, propStr)
			case rkPath:
				p := key
				if strings.HasPrefix(p, "path:") {
					p = strings.TrimPrefix(p, "path:")
				}
				p = strings.ToLower(strings.TrimSuffix(p, "/"))
				pathRoutes[p] = pr
				log.Printf("[INIT] Path Route: %s -> %s%s", p, targetStr, propStr)
			case rkClientName:
				clientNameRoutes[strings.ToLower(key)] = pr
				log.Printf("[INIT] Client Name Route: %s -> %s%s", key, targetStr, propStr)
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
			log.Printf("[WARN] routes_files: cannot read %q: %v", filePath, err)
			continue
		}
		log.Printf("[INIT] Loaded %d route(s) from file: %s", len(lines), filePath)
		for _, line := range lines {
			processRoute(line, route)
		}
	}

	hasMACRoutes = len(macRoutes) > 0
	hasMACWildRoutes = len(macWildRoutes) > 0
	hasIPRoutes = len(ipRoutes) > 0
	hasCIDRRoutes = len(cidrRoutes) > 0
	hasASNRoutes = len(asnRoutes) > 0
	hasClientNameRoutes = len(clientNameRoutes) > 0
	hasSNIRoutes = len(sniRoutes) > 0
	hasPathRoutes = len(pathRoutes) > 0

	// [SECURITY/FIX] Sort CIDR Routes natively by prefix length descending (most specific wins)
	// Eliminates non-deterministic routing behaviors caused by randomized YAML map iterations.
	if len(cidrRoutes) > 0 {
		sort.SliceStable(cidrRoutes, func(i, j int) bool {
			return cidrRoutes[i].net.Bits() > cidrRoutes[j].net.Bits()
		})
	}

	hasClientRoutes = hasMACRoutes || hasMACWildRoutes || hasIPRoutes || hasCIDRRoutes || hasASNRoutes || hasClientNameRoutes || hasSNIRoutes || hasPathRoutes
}

// initDomainRoutes parses `domain_routes:` and `domain_routes_files:` mapping suffix routes to targets.
func initDomainRoutes() {
	// Initialize with capacity based on inline routes map (files may dynamically expand this further)
	domainRoutes = make(map[string]domainRouteEntry, len(cfg.DomainRoutes))

	processDomainRoute := func(rawDomain string, dr DomainRouteConfig) {
		if dr.Upstream == "" {
			log.Printf("[WARN] domain_routes: entry %q has no upstream — skipped", rawDomain)
			return
		}

		// Support grouping multiple domains via comma-separated syntax.
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
			if dr.BypassLocal {
				log.Printf("[INIT] Domain Route: *.%s -> %s (bypass_local=true)", clean, dr.Upstream)
			} else {
				log.Printf("[INIT] Domain Route: *.%s -> %s", clean, dr.Upstream)
			}
		}
	}

	// 1. Process inline domain routes map
	for rawDomain, dr := range cfg.DomainRoutes {
		processDomainRoute(rawDomain, dr)
	}

	// 2. Process file-backed domain routes maps
	for filePath, dr := range cfg.DomainRoutesFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			log.Printf("[WARN] domain_routes_files: cannot read %q: %v", filePath, err)
			continue
		}
		log.Printf("[INIT] Loaded %d domain route(s) from file: %s", len(lines), filePath)
		for _, line := range lines {
			processDomainRoute(line, dr)
		}
	}

	hasDomainRoutes = len(domainRoutes) > 0
}

// initUpstreams constructs connection pools, resolves bootstrap IPs, counts unique endpoints,
// and assigns routing strategies for outbound DNS.
func initUpstreams() {
	routeUpstreams = make(map[string]*UpstreamGroup, len(cfg.Upstreams))
	hasClientNameUpstream = false

	globalStrategy := cfg.Server.UpstreamSelection
	if globalStrategy == "" {
		globalStrategy = "stagger"
	}

	for groupName, ugc := range cfg.Upstreams {
		ups := make([]*Upstream, 0, len(ugc.Servers))
		uniqueEndpoints := make(map[string]struct{})

		for _, rawURL := range ugc.Servers {
			u, err := ParseUpstream(rawURL)
			if err != nil {
				log.Printf("[WARN] Upstream %q in group %q: %v — skipped", rawURL, groupName, err)
				continue
			}
			ups = append(ups, u)
			if strings.Contains(rawURL, "{client-name}") {
				hasClientNameUpstream = true
			}

			// Tally up all unique destinations configured or resolved for this upstream
			hasExplicitTarget := false
			if len(u.BootstrapIPs) > 0 {
				for _, ip := range u.BootstrapIPs {
					uniqueEndpoints[ip] = struct{}{}
					hasExplicitTarget = true
				}
			} 
			if len(u.dialAddrs) > 0 {
				for _, dialAddr := range u.dialAddrs {
					if host, _, err := net.SplitHostPort(dialAddr); err == nil {
						uniqueEndpoints[host] = struct{}{}
					} else {
						uniqueEndpoints[dialAddr] = struct{}{}
					}
					hasExplicitTarget = true
				}
			}
			
			if !hasExplicitTarget {
				// Fallback for DoH/DoH3 endpoints without explicit IPs/bootstraps
				uniqueEndpoints[u.RawURL] = struct{}{}
			}
		}

		strategy := ugc.Strategy
		if strategy == "" {
			strategy = globalStrategy
		}
		strategy = strings.ToLower(strategy)

		// Sanity check algorithm types.
		switch strategy {
		case "stagger", "round-robin", "random", "fastest", "secure":
			// Valid
		default:
			log.Printf("[WARN] Upstream group %q has unknown strategy %q, falling back to %q", groupName, strategy, globalStrategy)
			strategy = globalStrategy
		}

		pref := strings.ToLower(ugc.Preference)
		if pref == "" {
			pref = "fastest"
		}
		if pref != "fastest" && pref != "ordered" {
			log.Printf("[WARN] Upstream group %q has unknown preference %q, falling back to 'fastest'", groupName, pref)
			pref = "fastest"
		}

		mode := strings.ToLower(ugc.Mode)
		if mode == "" {
			mode = "loose"
		}
		if mode != "loose" && mode != "strict" {
			log.Printf("[WARN] Upstream group %q has unknown mode %q, falling back to 'loose'", groupName, mode)
			mode = "loose"
		}

		// Fallback: the new routing algorithms should ONLY be used when there are multiple 
		// unique endpoints within the pool. Otherwise, parallel execution mechanics apply natively.
		if len(uniqueEndpoints) <= 1 && strategy != "stagger" {
			log.Printf("[INIT] Upstream group %q strategy %q overridden to 'stagger' (only %d unique endpoint(s) found)", groupName, strategy, len(uniqueEndpoints))
			strategy = "stagger"
		}

		routeUpstreams[groupName] = &UpstreamGroup{
			Name:       groupName,
			Strategy:   strategy,
			Preference: pref,
			Mode:       mode,
			Servers:    ups,
		}

		log.Printf("[INIT] Upstream group %q: %d server(s), %d unique endpoint(s) | strategy: %s (pref: %s, mode: %s)", groupName, len(ups), len(uniqueEndpoints), strategy, pref, mode)
	}

	if _, ok := routeUpstreams["default"]; !ok {
		log.Fatal("[FATAL] No 'default' upstream group defined in config")
	}
}

// ---------------------------------------------------------------------------
// Domain Policy Loading & Polling
// ---------------------------------------------------------------------------

var (
	policyHTTPMeta = make(map[string]catListHeaders)
	policyFileMeta = make(map[string]int64)
	policyMu       sync.Mutex
)

func loadPolicyMeta() map[string]catListHeaders {
	meta := make(map[string]catListHeaders)
	if cfg.Server.PolicyCacheDir == "" {
		return meta
	}
	b, err := os.ReadFile(filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json"))
	if err == nil {
		json.Unmarshal(b, &meta)
	}
	return meta
}

func savePolicyMeta(meta map[string]catListHeaders) {
	if cfg.Server.PolicyCacheDir == "" {
		return
	}
	os.MkdirAll(cfg.Server.PolicyCacheDir, 0755)
	b, err := json.Marshal(meta)
	if err == nil {
		path := filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json")
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0644) == nil {
			os.Rename(tmp, path)
		}
	}
}

// pollDomainPolicies iterates over all domain policy arrays natively, dynamically
// reconstructing the global fast-path routing hashmap asynchronously to prevent
// locking up the active DNS query resolution pipeline.
func pollDomainPolicies(force bool) {
	policyMu.Lock()
	defer policyMu.Unlock()

	changed := false
	activeFiles := make(map[string]bool)
	activeURLs := make(map[string]bool)

	if force {
		policyHTTPMeta = make(map[string]catListHeaders)
	} else if len(policyHTTPMeta) == 0 && cfg.Server.PolicyCacheDir != "" {
		policyHTTPMeta = loadPolicyMeta()
	}

	// 1. Check local file modifications
	for filePath := range cfg.DomainPolicyFiles {
		activeFiles[filePath] = true
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}
		mtime := info.ModTime().UnixNano()
		if lastMtime, ok := policyFileMeta[filePath]; !ok || lastMtime != mtime {
			policyFileMeta[filePath] = mtime
			changed = true
		}
	}

	urlData := make(map[string][]string)
	fetchFailed := make(map[string]bool)

	// 2. Check remote URL modifications securely (ETag/Last-Modified caching)
	for urlStr := range cfg.DomainPolicyURLs {
		activeURLs[urlStr] = true
		req, err := http.NewRequest(http.MethodGet, urlStr, nil)
		if err != nil {
			fetchFailed[urlStr] = true
			continue
		}
		req.Header.Set("User-Agent", cfg.Server.UserAgent)

		var cachePath string
		hasCacheFile := false
		if cfg.Server.PolicyCacheDir != "" {
			os.MkdirAll(cfg.Server.PolicyCacheDir, 0755)
			h := sha256.Sum256([]byte(urlStr))
			cachePath = filepath.Join(cfg.Server.PolicyCacheDir, "policy-"+hex.EncodeToString(h[:8])+".raw")
			if _, errStat := os.Stat(cachePath); errStat == nil {
				hasCacheFile = true
			}
		}

		if !force {
			if m, ok := policyHTTPMeta[urlStr]; ok && hasCacheFile {
				if m.LastModified != "" {
					req.Header.Set("If-Modified-Since", m.LastModified)
				}
				if m.ETag != "" {
					req.Header.Set("If-None-Match", m.ETag)
				}
			}
		}

		// Leverage the globally available, hardened internal HTTP client
		resp, err := catHTTPClient.Do(req)
		if err != nil {
			fetchFailed[urlStr] = true
			if !hasCacheFile {
				log.Printf("[POLICY] Fetch failed for %s: %v", urlStr, err)
			} else {
				log.Printf("[POLICY] Fetch failed for %s: %v — falling back to local cache", urlStr, err)
			}
			continue
		}

		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			if hasCacheFile {
				log.Printf("[POLICY] Not modified (304) for %s — queued local cache", urlStr)
			}
			continue
		} else if resp.StatusCode == http.StatusOK {
			policyHTTPMeta[urlStr] = catListHeaders{
				LastModified: resp.Header.Get("Last-Modified"),
				ETag:         resp.Header.Get("ETag"),
			}
			
			// Process response body directly into memory structures to avoid double IO drain later
			var lines []string
			lr := io.LimitReader(resp.Body, 10*1024*1024)
			scanner := bufio.NewScanner(lr)
			
			// Expand capacity to prevent buffer-too-long errors natively
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
			
			if err := scanner.Err(); err != nil {
				log.Printf("[POLICY] WARNING: Partial scanner error fetching %s: %v", urlStr, err)
			}
			resp.Body.Close()
			
			urlData[urlStr] = lines
			
			if cachePath != "" {
				tmp := cachePath + ".tmp"
				f, err := os.Create(tmp)
				if err == nil {
					w := bufio.NewWriter(f)
					for _, l := range lines {
						w.WriteString(l)
						w.WriteByte('\n')
					}
					w.Flush()
					f.Close()
					os.Rename(tmp, cachePath)
				}
				log.Printf("[POLICY] Fetched %d entries from %s — saved to cache", len(lines), urlStr)
			} else {
				log.Printf("[POLICY] Fetched %d entries from %s", len(lines), urlStr)
			}
			changed = true
		} else {
			fetchFailed[urlStr] = true
			resp.Body.Close()
			if hasCacheFile {
				log.Printf("[POLICY] HTTP %d for %s — falling back to local cache", resp.StatusCode, urlStr)
			} else {
				log.Printf("[POLICY] Failed to fetch HTTP %d for %s", resp.StatusCode, urlStr)
			}
		}
	}

	// 3. Garbage Collection: Prune removed tracking targets from the cache
	for f := range policyFileMeta {
		if !activeFiles[f] {
			delete(policyFileMeta, f)
			changed = true
			log.Printf("[POLICY] Garbage collected removed file source: %s", f)
		}
	}
	for u := range policyHTTPMeta {
		if !activeURLs[u] {
			delete(policyHTTPMeta, u)
			changed = true
			log.Printf("[POLICY] Garbage collected removed URL source: %s", u)
		}
	}

	if domainPolicySnap.Load() == nil {
		changed = true
	}

	if !changed {
		return
	}

	savePolicyMeta(policyHTTPMeta)

	// 4. Rebuild the master map natively
	newMap := make(map[string]int)
	var newCIDRs []dpCidrEntry // [SECURITY/FIX] Explicit CIDR Array for payload IP Filtering

	processDomainPolicy := func(rawKey string, actionName string) int {
		discarded := 0
		for _, domainStr := range strings.Split(rawKey, ",") {
			domainStr = strings.TrimSpace(domainStr)
			if domainStr == "" {
				continue
			}

			actionStr := strings.ToUpper(actionName)
			var rcode int
			if actionStr == "DROP" {
				rcode = PolicyActionDrop
			} else if actionStr == "BLOCK" {
				rcode = PolicyActionBlock
			} else {
				rc, ok := dns.StringToRcode[actionStr]
				if !ok {
					continue
				}
				rcode = rc
			}

			// Pre-emptively discard IP/CIDR configurations if they are disabled globally.
			if !cfg.Server.FilterIPs {
				if _, err := netip.ParseAddr(domainStr); err == nil {
					discarded++
					continue
				}
				if _, err := netip.ParsePrefix(domainStr); err == nil {
					discarded++
					continue
				}
			} else {
				// [SECURITY/PERF] Normalize bare IPs into strict CIDR blocks natively.
				// Prevents raw IPs from polluting the domain suffix-walking trie, 
				// guaranteeing high-performance prefix isolation.
				if addr, err := netip.ParseAddr(domainStr); err == nil {
					var prefix netip.Prefix
					if addr.Is4() {
						prefix = netip.PrefixFrom(addr, 32)
					} else {
						prefix = netip.PrefixFrom(addr, 128)
					}
					newCIDRs = append(newCIDRs, dpCidrEntry{prefix: prefix, action: rcode})
					continue
				}
				if prefix, err := netip.ParsePrefix(domainStr); err == nil {
					newCIDRs = append(newCIDRs, dpCidrEntry{prefix: prefix, action: rcode})
					continue
				}
			}

			clean := strings.ToLower(strings.TrimSuffix(domainStr, "."))
			if clean == "" {
				continue
			}

			newMap[clean] = rcode
		}
		return discarded
	}

	discardedInline := 0
	for rawKey, actionName := range cfg.DomainPolicy {
		discardedInline += processDomainPolicy(rawKey, actionName)
	}
	if discardedInline > 0 {
		log.Printf("[POLICY] Discarded %d IP/CIDR rule(s) from inline domain_policy (server.filter_ips is false)", discardedInline)
	}

	for filePath, actionName := range cfg.DomainPolicyFiles {
		lines, err := readConfigListFile(filePath)
		if err == nil {
			log.Printf("[POLICY] Loaded %d domain policy rule(s) from local file: %s", len(lines), filePath)
			discarded := 0
			for _, line := range lines {
				discarded += processDomainPolicy(line, actionName)
			}
			if discarded > 0 {
				log.Printf("[POLICY] Discarded %d IP/CIDR rule(s) from file %s (server.filter_ips is false)", discarded, filePath)
			}
		} else {
			log.Printf("[POLICY] Failed to load domain policy file %s: %v", filePath, err)
		}
	}

	for urlStr, actionName := range cfg.DomainPolicyURLs {
		var lines []string
		var err error
		var loadSource string

		// Retrieve lines sequentially: Memory Map -> Local Cache -> Explicit Fetch
		if data, ok := urlData[urlStr]; ok {
			lines = data
			loadSource = "network fetch"
		} else if cfg.Server.PolicyCacheDir != "" {
			h := sha256.Sum256([]byte(urlStr))
			cachePath := filepath.Join(cfg.Server.PolicyCacheDir, "policy-"+hex.EncodeToString(h[:8])+".raw")
			if _, errStat := os.Stat(cachePath); errStat == nil {
				lines, err = readConfigListFile(cachePath)
				if err == nil {
					loadSource = "local cache"
				} else {
					loadSource = "failed cache load"
				}
			} else if !fetchFailed[urlStr] {
				lines, err = readConfigListURL(urlStr)
				loadSource = "fallback network fetch"
			} else {
				err = fmt.Errorf("fetch failed and no cache fallback exists")
			}
		} else if !fetchFailed[urlStr] {
			lines, err = readConfigListURL(urlStr)
			loadSource = "fallback network fetch"
		} else {
			err = fmt.Errorf("fetch failed")
		}

		if err == nil {
			log.Printf("[POLICY] Loaded %d domain policy rule(s) from %s for URL: %s", len(lines), loadSource, urlStr)
			discarded := 0
			for _, line := range lines {
				discarded += processDomainPolicy(line, actionName)
			}
			if discarded > 0 {
				log.Printf("[POLICY] Discarded %d IP/CIDR rule(s) from URL %s (server.filter_ips is false)", discarded, urlStr)
			}
		} else {
			log.Printf("[POLICY] Failed to load domain policy URL %s: %v", urlStr, err)
		}
	}

	// Atomically swap the memory arrays into the live pipeline securely
	domainPolicySnap.Store(&newMap)
	domainPolicyCIDRSnap.Store(&newCIDRs)
	hasDomainPolicy.Store(len(newMap) > 0 || len(newCIDRs) > 0)
	computeDomainLabelBounds(&newMap)
	
	log.Printf("[POLICY] Rebuilt domain policy map. Loaded %d rule(s) globally.", len(newMap)+len(newCIDRs))
}

// initPolicies prepares the fast-path blocking structures for QTypes and Domains.
func initPolicies() {
	// --- RType policy ---
	rtypePolicy = make(map[uint16]int, len(cfg.RtypePolicy))

	processRtype := func(rawKey string, actionName string) {
		for _, typeName := range strings.Split(rawKey, ",") {
			typeName = strings.TrimSpace(typeName)
			if typeName == "" {
				continue
			}

			qtype, ok := dns.StringToType[strings.ToUpper(typeName)]
			if !ok {
				log.Printf("[WARN] rtype_policy: unknown query type %q — skipped", typeName)
				continue
			}

			actionStr := strings.ToUpper(actionName)
			if actionStr == "DROP" {
				rtypePolicy[qtype] = PolicyActionDrop
				log.Printf("[INIT] RType Policy: %s -> DROP", typeName)
				continue
			} else if actionStr == "BLOCK" {
				rtypePolicy[qtype] = PolicyActionBlock
				log.Printf("[INIT] RType Policy: %s -> BLOCK", typeName)
				continue
			}

			rcode, ok := dns.StringToRcode[actionStr]
			if !ok {
				log.Printf("[WARN] rtype_policy: unknown action or RCODE %q for type %q — skipped", actionName, typeName)
				continue
			}
			rtypePolicy[qtype] = rcode
			log.Printf("[INIT] RType Policy: %s -> %s", typeName, dns.RcodeToString[rcode])
		}
	}

	// 1. Process inline RType policies
	for rawKey, actionName := range cfg.RtypePolicy {
		processRtype(rawKey, actionName)
	}

	// 2. Process file-backed RType policies
	for filePath, actionName := range cfg.RtypePolicyFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			log.Printf("[WARN] rtype_policy_files: cannot read %q: %v", filePath, err)
			continue
		}
		log.Printf("[INIT] Loaded %d RType policy rule(s) from file: %s", len(lines), filePath)
		for _, line := range lines {
			processRtype(line, actionName)
		}
	}

	// --- Domain policy (Initial Fetch) ---
	pollDomainPolicies(forceRefreshStartup)

	pollStr := cfg.Server.PolicyPollInterval
	if pollStr == "" {
		pollStr = "6h"
	}
	if pollStr != "0s" && pollStr != "0" {
		if interval, err := time.ParseDuration(pollStr); err == nil && interval > 0 {
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for range ticker.C {
					pollDomainPolicies(false)
				}
			}()
		} else {
			log.Printf("[INIT] Invalid policy_poll_interval %q: %v", pollStr, err)
		}
	}

	// --- Obsolete qtype blocking ---
	if cfg.Server.BlockObsoleteQtypes {
		added := 0
		for qtype := range obsoleteQtypes {
			if _, userSet := rtypePolicy[qtype]; !userSet {
				rtypePolicy[qtype] = dns.RcodeNotImplemented
				added++
			}
		}
		blockUnknownQtypes = true
		log.Printf("[INIT] Obsolete qtype blocking: %d types injected (NOTIMP); unassigned types also blocked at query time", added)
	} else {
		log.Println("[INIT] Obsolete qtype blocking: disabled")
	}
	hasRtypePolicy = len(rtypePolicy) > 0
}

// computeDomainLabelBounds determines the min/max dot separation required to process
// suffix lookups natively and securely.
func computeDomainLabelBounds(dpMap *map[string]int) {
	countLabels := func(k string) int { return strings.Count(k, ".") + 1 }

	if len(*dpMap) > 0 {
		minP, maxP := 128, 1
		for k := range *dpMap {
			n := countLabels(k)
			if n < minP {
				minP = n
			}
			if n > maxP {
				maxP = n
			}
		}
		domainPolicyMinLabels.Store(int32(minP))
		domainPolicyMaxLabels.Store(int32(maxP))
	} else {
		domainPolicyMinLabels.Store(1)
		domainPolicyMaxLabels.Store(128)
	}

	if len(domainRoutes) > 0 {
		minR, maxR := 128, 1
		for k := range domainRoutes {
			n := countLabels(k)
			if n < minR {
				minR = n
			}
			if n > maxR {
				maxR = n
			}
		}
		domainRoutesMinLabels.Store(int32(minR))
		domainRoutesMaxLabels.Store(int32(maxR))
	} else {
		domainRoutesMinLabels.Store(1)
		domainRoutesMaxLabels.Store(128)
	}

	log.Printf("[INIT] Domain label bounds: policy [%d..%d], routes [%d..%d]",
		domainPolicyMinLabels.Load(), domainPolicyMaxLabels.Load(),
		domainRoutesMinLabels.Load(), domainRoutesMaxLabels.Load())
}

// initRouteIndex constructs the numerical lookup map required by the cache architecture.
func initRouteIndex() {
	routeIdxByName = make(map[string]uint16, len(cfg.Upstreams)+4)
	routeIdxByName["local"] = routeIdxLocal
	nextIdx := uint16(1)
	assignIdx := func(name string) {
		if _, exists := routeIdxByName[name]; !exists {
			routeIdxByName[name] = nextIdx
			nextIdx++
		}
	}
	for groupName := range cfg.Upstreams {
		assignIdx(groupName)
	}
	for _, dr := range cfg.DomainRoutes {
		assignIdx(dr.Upstream)
	}
	for _, route := range cfg.Routes {
		upstream := route.Upstream
		if upstream == "" && route.Group != "" {
			if grp, ok := cfg.Groups[route.Group]; ok && grp.Upstream != "" {
				upstream = grp.Upstream
			}
		}
		if upstream != "" {
			assignIdx(upstream)
		}
	}
	routeIdxDefault = routeIdxByName["default"]
	log.Printf("[INIT] Route index table: %d entries", len(routeIdxByName))
}

// initRRs parses global and per-group spoofed records natively
func initRRs() {
	globalRRs = make(map[string]spoofRecord)
	groupRRs = make(map[string]map[string]spoofRecord)

	parseRRMap := func(source map[string]interface{}, dest map[string]spoofRecord, context string) {
		for k, v := range source {
			domain := lowerTrimDot(k)
			var rec spoofRecord

			switch val := v.(type) {
			case string:
				val = strings.TrimSpace(val)
				if ip, err := netip.ParseAddr(val); err == nil {
					rec.IPs = append(rec.IPs, ip.Unmap())
				} else {
					rec.CNAME = lowerTrimDot(val)
				}
			case []interface{}:
				for _, item := range val {
					if str, ok := item.(string); ok {
						str = strings.TrimSpace(str)
						if ip, err := netip.ParseAddr(str); err == nil {
							rec.IPs = append(rec.IPs, ip.Unmap())
						} else {
							log.Fatalf("[FATAL] Invalid IP %q in %s spoofed records for %s. CNAMEs cannot be mixed in arrays.", str, context, domain)
						}
					}
				}
			default:
				log.Fatalf("[FATAL] Invalid format in %s spoofed records for %s. Must be string or array of strings.", context, domain)
			}

			if len(rec.IPs) > 0 && rec.CNAME != "" {
				log.Fatalf("[FATAL] Cannot mix IPs and CNAME for spoofed record %s in %s", domain, context)
			}

			dest[domain] = rec
		}
	}

	if len(cfg.RRs) > 0 {
		parseRRMap(cfg.RRs, globalRRs, "global")
	}

	for grpName, grpCfg := range cfg.Groups {
		if len(grpCfg.RRs) > 0 {
			gm := make(map[string]spoofRecord)
			parseRRMap(grpCfg.RRs, gm, "group '"+grpName+"'")
			groupRRs[grpName] = gm
		}
	}

	hasRRs = len(globalRRs) > 0 || len(groupRRs) > 0
	if hasRRs {
		log.Printf("[INIT] Spoofed RRs loaded: %d global, %d group-specific", len(globalRRs), len(groupRRs))
	}
}

// initDDR maps RFC 9462 Discovery of Designated Resolvers endpoints.
func initDDR() {
	if cfg.Server.ECHConfigList != "" {
		var err error
		ddrECHConfig, err = os.ReadFile(cfg.Server.ECHConfigList)
		if err != nil {
			log.Printf("[WARN] DDR ECH payload file read failed: %v", err)
		} else {
			log.Printf("[INIT] DDR ECH payload successfully loaded from %s and ready for spoofing.", cfg.Server.ECHConfigList)
		}
	}

	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		ddrHostnamesList = nil

		source := cfg.Server.DDR.HostnameSource
		if source == "" {
			source = "strict"
		}

		// Seamlessly construct discovery targets via array bounds or live cert structures natively
		var raw []string
		if source == "strict" || source == "both" {
			raw = append(raw, cfg.Server.DDR.Hostnames...)
		}
		if source == "tls" || source == "both" {
			raw = append(raw, tlsAuthorizedNames...)
		}

		for _, h := range raw {
			clean := strings.ToLower(strings.TrimSuffix(h, "."))
			// Skip explicit empty nodes, IP formats masquerading as hosts, and broad certificate wildcards
			if clean == "" || strings.Contains(clean, "*") || net.ParseIP(clean) != nil {
				continue
			}
			if !ddrHostnames[clean] {
				ddrHostnames[clean] = true
				ddrHostnamesList = append(ddrHostnamesList, clean)
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
		
		// [FIX] Zero-out default global ports to prevent DDR from advertising inactive listeners natively.
		ddrDoHPort = 0
		ddrDoTPort = 0
		ddrDoQPort = 0
		
		for _, addr := range cfg.Server.ListenDoH {
			ddrDoHPort = extractPort(addr, 443)
		}
		for _, addr := range cfg.Server.ListenDoT {
			ddrDoTPort = extractPort(addr, 853)
		}
		for _, addr := range cfg.Server.ListenDoQ {
			ddrDoQPort = extractPort(addr, 853)
		}
		
		log.Printf("[INIT] DDR enabled (source: %s): %d hostname(s), %d IPv4, %d IPv6, DoH=%d DoT=%d DoQ=%d",
			source, len(ddrHostnames), len(ddrIPv4), len(ddrIPv6), ddrDoHPort, ddrDoTPort, ddrDoQPort)
	} else {
		log.Println("[INIT] DDR disabled.")
	}
}

