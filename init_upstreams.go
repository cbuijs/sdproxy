/*
File:    init_upstreams.go
Version: 1.6.0
Updated: 08-Jul-2026 09:15 CEST

Description:
  Parses upstream definitions and builds group strategies for sdproxy.
  Handles bootstrap resolution and ECH/ALPN discovery for outbound encrypted DNS.

Changes:
  1.6.0 - [FEAT] Propagated `cfg.Server.MaxSecureUpstreams` into each constructed 
          `UpstreamGroup`, enabling the "secure" strategy fan-out cap to be 
          configured instead of hardcoded.
  1.5.0 - [CLEANUP] Pruned obsolete `hasClientNameUpstream` variable assignment securely.
          Replaces stagnant assignments generated natively elsewhere.
  1.4.0 - [PERF] Parallelized upstream parsing and DDR (Discovery of Designated Resolvers) 
          execution natively using `sync.WaitGroup`. Eliminates cascading network 
          timeouts and drastically reduces startup latency when configuring multiple 
          encrypted endpoints.
  1.3.0 - [SECURITY/FIX] Dynamically asserted `HasClientName` bounds natively 
          during Upstream Group instantiation. Enables immediate detection of 
          `{client-name}` templates organically to enforce localized cache 
          isolation structures dynamically down the pipeline.
*/

package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

// initUpstreams constructs connection pools and selection strategies for outbound DNS.
func initUpstreams() {
	routeUpstreams = make(map[string]*UpstreamGroup, len(cfg.Upstreams))

	globalStrategy := cfg.Server.UpstreamSelection
	if globalStrategy == "" { globalStrategy = "stagger" }

	// [FEAT] Resolve the "secure" strategy consensus fan-out cap once, from config.
	// validateConfig() already defaults this to 5 when unset/invalid.
	maxSecureUpstreams := cfg.Server.MaxSecureUpstreams
	if maxSecureUpstreams <= 0 {
		maxSecureUpstreams = 5
	}

	var wg sync.WaitGroup
	var mu sync.Mutex // Protects routeUpstreams and active boundaries

	for groupName, ugc := range cfg.Upstreams {
		wg.Add(1)
		go func(gName string, gConf UpstreamGroupConfig) {
			defer wg.Done()

			// Concurrently parse all servers within the group to parallelize DDR network requests
			var serverWg sync.WaitGroup
			parsedServers := make([]*Upstream, len(gConf.Servers))

			grpECSAction := strings.ToLower(gConf.ECS.Action)
			grpECSV4 := gConf.ECS.IPv4Mask
			grpECSV6 := gConf.ECS.IPv6Mask

			if grpECSAction == "" { grpECSAction = cfg.Server.ECS.Action }
			if grpECSV4 <= 0 || grpECSV4 > 32 { grpECSV4 = cfg.Server.ECS.IPv4Mask }
			if grpECSV6 <= 0 || grpECSV6 > 128 { grpECSV6 = cfg.Server.ECS.IPv6Mask }

			for i, rawURL := range gConf.Servers {
				serverWg.Add(1)
				// Execute parsing natively leveraging indexed slice writes to prevent mutex contention
				go func(idx int, url string) {
					defer serverWg.Done()
					
					// [SECURITY/FIX] Pass the fully resolved globalBootstrapServers array dynamically 
					// to prevent standard upstreams from encountering data races natively.
					u, err := ParseUpstream(url, globalBootstrapServers)
					if err != nil {
						if logSystem {
							log.Printf("[WARN] Failed to parse upstream %q in group %q: %v", url, gName, err)
						}
						return
					}
					u.ECSAction, u.ECSV4Mask, u.ECSV6Mask = grpECSAction, grpECSV4, grpECSV6
					parsedServers[idx] = u
				}(i, rawURL)
			}
			serverWg.Wait()

			// Aggregate successfully parsed servers
			var ups []*Upstream
			uniqueEndpoints := make(map[string]struct{})
			hasGrpClientName := false

			for i, u := range parsedServers {
				if u == nil {
					continue
				}
				ups = append(ups, u)
				
				rawURL := gConf.Servers[i]
				// Assess presence of individualized routing payloads organically
				if strings.Contains(rawURL, "{client-name}") { 
					hasGrpClientName = true
				}
				
				for _, ip := range u.BootstrapIPs { uniqueEndpoints[ip] = struct{}{} }
				for _, dialAddr := range u.dialAddrs {
					if host, _, err := net.SplitHostPort(dialAddr); err == nil { uniqueEndpoints[host] = struct{}{} } else { uniqueEndpoints[dialAddr] = struct{}{} }
				}
			}

			strategy := strings.ToLower(gConf.Strategy)
			if strategy == "" { strategy = globalStrategy }
			if len(uniqueEndpoints) <= 1 && strategy != "stagger" { strategy = "stagger" }

			pref := strings.ToLower(gConf.Preference)
			if pref == "" { pref = "fastest" }
			mode := strings.ToLower(gConf.Mode)
			if mode == "" { mode = "loose" }

			mu.Lock()
			routeUpstreams[gName] = &UpstreamGroup{
				Name: gName, Strategy: strategy, Preference: pref, Mode: mode,
				IgnoreQnameLabels: gConf.IgnoreQnameLabels,
				ECSAction: grpECSAction, ECSV4Mask: grpECSV4, ECSV6Mask: grpECSV6,
				HasClientName: hasGrpClientName,
				MaxSecureUpstreams: maxSecureUpstreams,
				Servers: ups,
			}
			if logSystem {
				log.Printf("[INIT] Upstream group %q: %d server(s), strategy: %s (pref: %s, mode: %s, ignore_labels: %v, ecs: %s, isolated_cache: %v, max_secure_upstreams: %d)", 
					gName, len(ups), strategy, pref, mode, gConf.IgnoreQnameLabels, grpECSAction, hasGrpClientName, maxSecureUpstreams)
			}
			mu.Unlock()
		}(groupName, ugc)
	}
	
	wg.Wait()
}

