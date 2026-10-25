/*
File:    init_upstreams.go
Version: 1.7.0
Last Updated: 25-Oct-2026 16:05 CET

Description:
  Parses upstream definitions and builds group strategies for sdproxy.
  Handles bootstrap resolution and ECH/ALPN discovery for outbound encrypted DNS.

Changes:
  1.7.0 - [PERF/SECURITY] Bounded concurrent upstream bootstrap and DDR/ECH discovery
          goroutines in `initUpstreams` with a 16-slot semaphore (`upstreamInitSem`)
          to prevent socket/goroutine exhaustion on configurations with large numbers
          of upstream endpoints.
  1.6.0 - [FEAT] Propagated `cfg.Server.MaxSecureUpstreams` into each constructed 
          `UpstreamGroup`.
  1.5.0 - [CLEANUP] Pruned obsolete `hasClientNameUpstream` variable assignment securely.
  1.4.0 - [PERF] Parallelized upstream parsing and DDR execution natively using `sync.WaitGroup`.
  1.3.0 - [SECURITY/FIX] Dynamically asserted `HasClientName` bounds natively 
          during Upstream Group instantiation.
*/

package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

const maxConcurrentUpstreamInit = 16

// initUpstreams constructs connection pools and selection strategies for outbound DNS.
func initUpstreams() {
	routeUpstreams = make(map[string]*UpstreamGroup, len(cfg.Upstreams))

	globalStrategy := cfg.Server.UpstreamSelection
	if globalStrategy == "" {
		globalStrategy = "stagger"
	}

	maxSecureUpstreams := cfg.Server.MaxSecureUpstreams
	if maxSecureUpstreams <= 0 {
		maxSecureUpstreams = 5
	}

	upstreamInitSem := make(chan struct{}, maxConcurrentUpstreamInit)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for groupName, ugc := range cfg.Upstreams {
		wg.Add(1)
		go func(gName string, gConf UpstreamGroupConfig) {
			defer wg.Done()

			var serverWg sync.WaitGroup
			parsedServers := make([]*Upstream, len(gConf.Servers))

			grpECSAction := strings.ToLower(gConf.ECS.Action)
			grpECSV4 := gConf.ECS.IPv4Mask
			grpECSV6 := gConf.ECS.IPv6Mask

			if grpECSAction == "" {
				grpECSAction = cfg.Server.ECS.Action
			}
			if grpECSV4 <= 0 || grpECSV4 > 32 {
				grpECSV4 = cfg.Server.ECS.IPv4Mask
			}
			if grpECSV6 <= 0 || grpECSV6 > 128 {
				grpECSV6 = cfg.Server.ECS.IPv6Mask
			}

			for i, rawURL := range gConf.Servers {
				serverWg.Add(1)
				go func(idx int, url string) {
					defer serverWg.Done()

					upstreamInitSem <- struct{}{}
					defer func() { <-upstreamInitSem }()

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

			var ups []*Upstream
			uniqueEndpoints := make(map[string]struct{})
			hasGrpClientName := false

			for i, u := range parsedServers {
				if u == nil {
					continue
				}
				ups = append(ups, u)

				rawURL := gConf.Servers[i]
				if strings.Contains(rawURL, "{client-name}") {
					hasGrpClientName = true
				}

				for _, ip := range u.BootstrapIPs {
					uniqueEndpoints[ip] = struct{}{}
				}
				for _, dialAddr := range u.dialAddrs {
					if host, _, err := net.SplitHostPort(dialAddr); err == nil {
						uniqueEndpoints[host] = struct{}{}
					} else {
						uniqueEndpoints[dialAddr] = struct{}{}
					}
				}
			}

			strategy := strings.ToLower(gConf.Strategy)
			if strategy == "" {
				strategy = globalStrategy
			}
			if len(uniqueEndpoints) <= 1 && strategy != "stagger" {
				strategy = "stagger"
			}

			pref := strings.ToLower(gConf.Preference)
			if pref == "" {
				pref = "fastest"
			}
			mode := strings.ToLower(gConf.Mode)
			if mode == "" {
				mode = "loose"
			}

			mu.Lock()
			routeUpstreams[gName] = &UpstreamGroup{
				Name:               gName,
				Strategy:           strategy,
				Preference:         pref,
				Mode:               mode,
				IgnoreQnameLabels:  gConf.IgnoreQnameLabels,
				ECSAction:          grpECSAction,
				ECSV4Mask:          grpECSV4,
				ECSV6Mask:          grpECSV6,
				HasClientName:      hasGrpClientName,
				MaxSecureUpstreams: maxSecureUpstreams,
				Servers:            ups,
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
