/*
File:    main.go
Version: 1.250.0
Last Updated: 25-Oct-2026 16:45 CET

Description:
  Application entry point and core orchestrator for sdproxy.
  Reads config.yaml, wires all subsystems sequentially, and blocks on signals.

Changes:
  1.250.0 - [FEAT] Added `-U` / `--update-config` command-line flag to complement
            the current configuration file with all documentation comments and
            missing/new options while keeping existing options intact.
  1.249.0 - [FEAT] Added `-C` / `--clean-config` (outputs a stripped, minimal YAML
            configuration with all comments and default values removed) and
            `-E` / `--example-config` (outputs the complete, documented reference
            configuration and exits).
  1.248.0 - [SECURITY] Initialized `trustedProxies` from `cfg.Server.TrustedProxies`
            at startup so EDNS0 Option 65001 (`mac:`) and EDNS0 Client Subnet (`ecs:`)
            assertions are restricted to trusted forwarder proxies (or loopback by default).
  1.247.0 - [FEAT/FIX] Applied `sanitizeYAMLRegexEscapes` before `yaml.Unmarshal`
            so double-quoted `/.../` regexes in `config.yaml` support standard
            single-backslash escapes (`\.`, `\d`, `\b`, etc.) natively.
  1.246.0 - [FIX] Started `InitARP()` when `cfg.WebUI.Enabled` is true even if no
            MAC routes are configured, ensuring the WebUI "Known Clients & Blocking"
            table populates hardware ARP entries.
*/

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	debug.SetGCPercent(100)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -c, --config <file>    Path to YAML configuration file (default: config.yaml)\n")
		fmt.Fprintf(os.Stderr, "  -t, --test             Test the configuration file for syntax/logic errors and exit\n")
		fmt.Fprintf(os.Stderr, "  -C, --clean-config     Clean the configuration file (strip comments and default values) to stdout and exit\n")
		fmt.Fprintf(os.Stderr, "  -U, --update-config    Update/complement the configuration file with all comments and missing options to stdout and exit\n")
		fmt.Fprintf(os.Stderr, "  -E, --example-config   Print the full documented default/reference configuration to stdout and exit\n")
		fmt.Fprintf(os.Stderr, "  -f, --force-refresh    Force fetching/loading fresh copies of all external lists and databases on startup\n")
		fmt.Fprintf(os.Stderr, "  -4, --ipv4             Limit resource loading and listeners to IPv4 only\n")
		fmt.Fprintf(os.Stderr, "  -6, --ipv6             Limit resource loading and listeners to IPv6 only\n")
		fmt.Fprintf(os.Stderr, "  -v, --version          Show current sdproxy version and exit\n")
		fmt.Fprintf(os.Stderr, "  -h, --help             Show this help message\n")
	}

	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			continue
		}

		name := arg
		if idx := strings.Index(arg, "="); idx >= 0 {
			name = arg[:idx]
		}

		if strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--") {
			if len(name) > 2 {
				fmt.Fprintf(os.Stderr, "Error: Long parameters must use a double dash (e.g., --%s)\n\n", name[1:])
				flag.Usage()
				os.Exit(1)
			}
		}

		if strings.HasPrefix(name, "--") {
			if len(name) == 3 {
				fmt.Fprintf(os.Stderr, "Error: Short parameters must use a single dash (e.g., -%s)\n\n", name[2:])
				flag.Usage()
				os.Exit(1)
			}
		}
	}

	var (
		configFile       string
		testConfig       bool
		cleanConfig      bool
		updateConfig     bool
		exampleConfig    bool
		forceRefreshFlag bool
		ipv4Only         bool
		ipv6Only         bool
		showVersion      bool
		showHelp         bool
	)

	flag.StringVar(&configFile, "c", "config.yaml", "Path to YAML configuration file (Short)")
	flag.StringVar(&configFile, "config", "config.yaml", "Path to YAML configuration file (Long)")

	flag.BoolVar(&testConfig, "t", false, "Test the configuration file for syntax/logic errors and exit (Short)")
	flag.BoolVar(&testConfig, "test", false, "Test the configuration file for syntax/logic errors and exit (Long)")

	flag.BoolVar(&cleanConfig, "C", false, "Clean the configuration file (strip comments and default values) to stdout and exit (Short)")
	flag.BoolVar(&cleanConfig, "clean-config", false, "Clean the configuration file (strip comments and default values) to stdout and exit (Long)")

	flag.BoolVar(&updateConfig, "U", false, "Update/complement the configuration file with all comments and missing options to stdout and exit (Short)")
	flag.BoolVar(&updateConfig, "update-config", false, "Update/complement the configuration file with all comments and missing options to stdout and exit (Long)")

	flag.BoolVar(&exampleConfig, "E", false, "Print the full documented default/reference configuration to stdout and exit (Short)")
	flag.BoolVar(&exampleConfig, "example-config", false, "Print the full documented default/reference configuration to stdout and exit (Long)")

	flag.BoolVar(&forceRefreshFlag, "f", false, "Force fetching/loading fresh copies of all external lists and databases on startup (Short)")
	flag.BoolVar(&forceRefreshFlag, "force-refresh", false, "Force fetching/loading fresh copies of all external lists and databases on startup (Long)")

	flag.BoolVar(&ipv4Only, "4", false, "Limit resource loading and listeners to IPv4 only (Short)")
	flag.BoolVar(&ipv4Only, "ipv4", false, "Limit resource loading and listeners to IPv4 only (Long)")

	flag.BoolVar(&ipv6Only, "6", false, "Limit resource loading and listeners to IPv6 only (Short)")
	flag.BoolVar(&ipv6Only, "ipv6", false, "Limit resource loading and listeners to IPv6 only (Long)")

	flag.BoolVar(&showVersion, "v", false, "Show current sdproxy version and exit (Short)")
	flag.BoolVar(&showVersion, "version", false, "Show current sdproxy version and exit (Long)")

	flag.BoolVar(&showHelp, "h", false, "Show this help message (Short)")
	flag.BoolVar(&showHelp, "help", false, "Show this help message (Long)")

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if showVersion {
		fmt.Printf("sdproxy %s (Built: %s, Build: %s)\n", BuildVersion, BuildTime, BuildNumber)
		os.Exit(0)
	}

	if exampleConfig {
		fmt.Print(FullReferenceConfigYAML)
		if !strings.HasSuffix(FullReferenceConfigYAML, "\n") {
			fmt.Println()
		}
		os.Exit(0)
	}

	forceRefreshStartup = forceRefreshFlag

	data, err := os.ReadFile(configFile)
	if err != nil {
		if testConfig || cleanConfig || updateConfig {
			fmt.Fprintf(os.Stderr, "[ERROR] FATAL: Cannot read config file %s: %v\n", configFile, err)
			os.Exit(1)
		}
		log.Fatalf("[FATAL] Cannot read config %s: %v", configFile, err)
	}

	data = sanitizeYAMLRegexEscapes(data)

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		if testConfig || cleanConfig || updateConfig {
			fmt.Fprintf(os.Stderr, "[ERROR] FATAL: Cannot parse YAML in %s: %v\n", configFile, err)
			os.Exit(1)
		}
		log.Fatalf("[FATAL] Cannot parse config %s: %v", configFile, err)
	}

	rawCfg := cfg
	valErr := validateConfig()

	if updateConfig {
		if valErr != nil {
			fmt.Fprintf(os.Stderr, "[UPDATE] FAILED: Configuration constraint error in %s: %v\n", configFile, valErr)
			os.Exit(1)
		}
		updated, err := UpdateConfigYAML(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[UPDATE] FAILED: Could not update configuration: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(updated)
		os.Exit(0)
	}

	if cleanConfig {
		if valErr != nil {
			fmt.Fprintf(os.Stderr, "[CLEAN] FAILED: Configuration constraint error in %s: %v\n", configFile, valErr)
			os.Exit(1)
		}
		cleaned, err := CleanConfigYAML(rawCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[CLEAN] FAILED: Could not serialize cleaned configuration: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(cleaned)
		os.Exit(0)
	}

	if testConfig {
		if valErr != nil {
			fmt.Fprintf(os.Stderr, "[TEST] FAILED: Configuration constraint error in %s: %v\n", configFile, valErr)
			os.Exit(1)
		}
		fmt.Printf("[TEST] OK: Configuration %s is valid and structurally sound.\n", configFile)
		os.Exit(0)
	}
	if valErr != nil {
		log.Fatalf("[FATAL] Configuration validation failed: %v", valErr)
	}

	if cfg.Logging.LogQueries != nil {
		logQueries = *cfg.Logging.LogQueries
	} else {
		logQueries = true
	}
	logASNDetails = cfg.Logging.LogASNDetails
	logStrategy = cfg.Logging.LogStrategy

	if cfg.Logging.LogParental != nil {
		logParental = *cfg.Logging.LogParental
	} else {
		logParental = false
	}
	if cfg.Logging.LogIdentity != nil {
		logIdentity = *cfg.Logging.LogIdentity
	} else {
		logIdentity = false
	}
	if cfg.Logging.LogCaching != nil {
		logCaching = *cfg.Logging.LogCaching
	} else {
		logCaching = false
	}
	if cfg.Logging.LogDDR != nil {
		logDDR = *cfg.Logging.LogDDR
	} else {
		logDDR = false
	}
	if cfg.Logging.LogTLS != nil {
		logTLS = *cfg.Logging.LogTLS
	} else {
		logTLS = false
	}
	if cfg.Logging.LogSystem != nil {
		logSystem = *cfg.Logging.LogSystem
	} else {
		logSystem = true
	}
	if cfg.Logging.LogWebUI != nil {
		logWebUI = *cfg.Logging.LogWebUI
	} else {
		logWebUI = true
	}
	if cfg.Logging.LogRouting != nil {
		logRouting = *cfg.Logging.LogRouting
	} else {
		logRouting = false
	}

	if logSystem {
		log.Printf("[BOOT] Starting sdproxy (Simple DNS Proxy) - %s", BuildVersion)
		if autoEnabledFlattenCNAME {
			log.Println("[BOOT] [INFO] Upstream group with 'consolidate' preference detected. Automatically forced 'server.flatten_cname: true' to ensure RFC-compliant, single-CNAME flattened client payloads.")
		}
	}

	if cfg.Logging.StripTime {
		log.SetFlags(0)
	} else {
		log.SetFlags(log.Ldate | log.Ltime)
	}

	if cfg.WebUI.Enabled {
		log.SetOutput(io.MultiWriter(os.Stderr, WebUILogStreamer))
		if logSystem {
			log.Println("[BOOT] Web UI and background statistics trackers are ENABLED")
		}
	} else {
		log.SetOutput(os.Stderr)
		if logSystem {
			log.Println("[BOOT] Web UI and background statistics trackers are DISABLED")
		}
	}

	if forceRefreshStartup {
		if logSystem {
			log.Println("[BOOT] CLI Override: Force-refresh enabled. Ignoring persistent cache metadata.")
		}
	}

	if logSystem {
		if logQueries {
			log.Println("[BOOT] Per-query logging enabled (logging.log_queries: true)")
			if logASNDetails {
				log.Println("[BOOT] ASN details in logs enabled (logging.log_asn_details: true)")
			}
		} else {
			log.Println("[BOOT] Per-query logging disabled (logging.log_queries: false)")
		}

		if logStrategy {
			log.Println("[BOOT] Strategy logging enabled (logging.log_strategy: true)")
		}
	}

	if ipv4Only && ipv6Only {
		ipVersionSupport = "both"
		if logSystem {
			log.Println("[BOOT] CLI Override: Both IPv4 and IPv6 requested via flags.")
		}
	} else if ipv4Only {
		ipVersionSupport = "ipv4"
		if logSystem {
			log.Println("[BOOT] CLI Override: IPv4 only requested via flags.")
		}
	} else if ipv6Only {
		ipVersionSupport = "ipv6"
		if logSystem {
			log.Println("[BOOT] CLI Override: IPv6 only requested via flags.")
		}
	} else {
		ipVersionSupport = cfg.Server.SupportIPVersion
		if ipVersionSupport == "" {
			ipVersionSupport = "both"
		}
	}

	if logSystem {
		log.Printf("[BOOT] IP version support: %s", ipVersionSupport)
	}

	// -----------------------------------------------------------------------
	// 1. CPU-bound & Core configurations & Bootstrapping
	// -----------------------------------------------------------------------
	initBlockAction()

	if cfg.Server.UDPWorkers <= 0 {
		cfg.Server.UDPWorkers = 10
	}
	InitThrottle()

	if len(cfg.Server.BootstrapServers) > 0 {
		globalBootstrapServers = make([]*Upstream, len(cfg.Server.BootstrapServers))
		var bsWg sync.WaitGroup
		for i, s := range cfg.Server.BootstrapServers {
			rawURL := strings.TrimSpace(s)
			if rawURL == "" {
				continue
			}

			if !strings.Contains(rawURL, "://") {
				host, port, err := net.SplitHostPort(rawURL)
				if err != nil {
					host = rawURL
					port = "53"
				}
				rawURL = "udp://" + net.JoinHostPort(host, port)
			}

			bsWg.Add(1)
			go func(index int, url string, originalString string) {
				defer bsWg.Done()

				u, err := ParseUpstream(url, nil)
				if err != nil {
					log.Fatalf("[FATAL] Bootstrap server %q is invalid: %v", originalString, err)
				}

				hasExplicitIP := false
				if len(u.BootstrapIPs) > 0 {
					hasExplicitIP = true
				} else {
					for _, dialAddr := range u.dialAddrs {
						host, _, _ := net.SplitHostPort(dialAddr)
						if host == "" {
							host = dialAddr
						}
						if net.ParseIP(host) != nil {
							hasExplicitIP = true
							break
						}
					}
					if !hasExplicitIP && (u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
						rest := strings.TrimPrefix(u.RawURL, "https://")
						if idx := strings.IndexByte(rest, '/'); idx >= 0 {
							rest = rest[:idx]
						}
						if h, _, err := net.SplitHostPort(rest); err == nil {
							rest = h
						}
						if net.ParseIP(rest) != nil {
							hasExplicitIP = true
						}
					}
				}

				if !hasExplicitIP {
					log.Fatalf("[FATAL] Bootstrap server %q MUST contain a mandatory IP address (e.g., #1.1.1.1) to avoid resolution deadlocks.", originalString)
				}

				globalBootstrapServers[index] = u
			}(i, rawURL, s)
		}
		bsWg.Wait()

		var cleaned []*Upstream
		var names []string
		for _, u := range globalBootstrapServers {
			if u != nil {
				cleaned = append(cleaned, u)
				names = append(names, u.RawURL)
			}
		}
		globalBootstrapServers = cleaned

		if logSystem && len(names) > 0 {
			log.Printf("[BOOT] Bootstrap servers mapped: %s", strings.Join(names, ", "))
		}
	}

	initUpstreams()
	InitUpstreamSweeper()
	initDGA()
	initRRs()
	InitStats()

	// -----------------------------------------------------------------------
	// 2. High-Performance Parallel Boot Engine
	// -----------------------------------------------------------------------
	var bootWg sync.WaitGroup

	runBootTask := func(name string, task func()) {
		bootWg.Add(1)
		go func() {
			defer bootWg.Done()
			task()
		}()
	}

	runBootTask("LoadStats", LoadStats)
	runBootTask("LoadLogs", LoadLogs)
	runBootTask("LoadGroupOverrides", LoadGroupOverrides)
	runBootTask("InitRules", InitRules)
	runBootTask("InitClientRoutes", initClientRoutes)
	runBootTask("InitDomainRoutes", initDomainRoutes)
	runBootTask("InitPolicies", initPolicies)
	runBootTask("InitIdentity", InitIdentity)
	runBootTask("InitParental", InitParental)

	bootWg.Wait()

	// -----------------------------------------------------------------------
	// 3. Dependent Indexes & Hardware Interrogations
	// -----------------------------------------------------------------------
	initRouteIndex()

	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	if cfg.Cache.Enabled {
		if logSystem {
			if cfg.Cache.MaxTTL > 0 {
				log.Printf("[INIT] Cache TTL bounds: min=%ds, max=%ds", cfg.Cache.MinTTL, cfg.Cache.MaxTTL)
			} else {
				log.Printf("[INIT] Cache TTL bounds: min=%ds, max=unlimited", cfg.Cache.MinTTL)
			}
			if cfg.Cache.NegativeTTL > 0 {
				log.Printf("[INIT] Cache negative TTL: %ds", cfg.Cache.NegativeTTL)
			}
			if cfg.Cache.StaleTTL > 0 {
				log.Printf("[INIT] Cache serve-stale window: %ds (RFC 8767)", cfg.Cache.StaleTTL)
			}
			if cfg.Cache.PrefetchBefore > 0 && cfg.Cache.PrefetchMinHits > 0 {
				log.Printf("[INIT] Cache prefetch: trigger %ds before expiry, min %d hits",
					cfg.Cache.PrefetchBefore, cfg.Cache.PrefetchMinHits)
			}
			if cfg.Cache.SweepIntervalS > 0 {
				log.Printf("[INIT] Cache sweep interval: %ds", cfg.Cache.SweepIntervalS)
			}
		}
	}

	if hasMACRoutes || hasMACWildRoutes || hasParental || len(cfg.Identity.DnsmasqLeases) > 0 || len(cfg.Identity.IscLeases) > 0 || len(cfg.Identity.KeaLeases) > 0 || len(cfg.Identity.OdhcpdLeases) > 0 || cfg.WebUI.Enabled {
		InitARP()
	} else {
		if logSystem {
			log.Println("[ARP] No MAC routes, DHCP leases, or WebUI configured — ARP polling disabled.")
		}
	}

	InitRateLimiter()
	InitExfiltration()
	InitSubdomainLimit()

	var tlsConfig *tls.Config
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0 || len(cfg.WebUI.ListenHTTPS) > 0
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		if logTLS {
			log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
		}
	}

	initDDR()

	if cfg.Server.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.Server.MemoryLimitMB) * 1024 * 1024)
		if logSystem {
			log.Printf("[BOOT] Runtime memory limit: %d MB", cfg.Server.MemoryLimitMB)
		}
	}

	globalSelection := cfg.Server.UpstreamSelection
	if globalSelection == "" {
		globalSelection = "stagger"
	}
	if logSystem {
		log.Printf("[BOOT] Upstream global selection strategy: %s", globalSelection)
	}

	upstreamStagger = time.Duration(cfg.Server.UpstreamStaggerMs) * time.Millisecond
	if logSystem {
		if upstreamStagger > 0 {
			log.Printf("[BOOT] Upstream stagger: %s (parallel racing enabled)", upstreamStagger)
		} else {
			log.Println("[BOOT] Upstream stagger: 0 (sequential mode)")
		}
	}

	upstreamTimeout = time.Duration(cfg.Server.UpstreamTimeoutMs) * time.Millisecond
	if logSystem {
		if upstreamTimeout > 0 {
			log.Printf("[BOOT] Upstream timeout: %s per exchange", upstreamTimeout)
		} else {
			log.Println("[BOOT] Upstream timeout: disabled (transport default governs)")
		}
	}

	if cfg.Server.SyntheticTTL > 0 {
		syntheticTTL = uint32(cfg.Server.SyntheticTTL)
	} else {
		syntheticTTL = 60
	}
	if logSystem {
		log.Printf("[BOOT] Synthetic TTL: %d s (DDR, local identity, NXDOMAIN SOA)", syntheticTTL)
	}

	dnsACLAllow = parseACL(cfg.Server.ACL.Allow)
	dnsACLDeny = parseACL(cfg.Server.ACL.Deny)
	hasDNSACL = len(dnsACLAllow) > 0 || len(dnsACLDeny) > 0
	if hasDNSACL {
		if logSystem {
			log.Printf("[BOOT] DNS ACL enabled: %d allow rules, %d deny rules", len(dnsACLAllow), len(dnsACLDeny))
		}
	}

	trustedProxies = parseACL(cfg.Server.TrustedProxies)
	if len(trustedProxies) > 0 && logSystem {
		log.Printf("[BOOT] Trusted EDNS proxies configured: %d rule(s)", len(trustedProxies))
	}

	webUIACLAllow = parseACL(cfg.WebUI.ACL.Allow)
	webUIACLDeny = parseACL(cfg.WebUI.ACL.Deny)
	hasWebUIACL = len(webUIACLAllow) > 0 || len(webUIACLDeny) > 0
	if hasWebUIACL {
		if logSystem {
			log.Printf("[BOOT] Web UI ACL enabled: %d allow rules, %d deny rules", len(webUIACLAllow), len(webUIACLDeny))
		}
	}

	hasRateLimit = cfg.Server.RateLimit.Enabled
	hasRebindingProtection = cfg.Server.RebindingProtection

	if cfg.Server.SearchDomainLeakPrevention != nil {
		searchDomainLeakPrevention = *cfg.Server.SearchDomainLeakPrevention
	} else {
		searchDomainLeakPrevention = true
	}

	InitRecentBlocks()

	isPublic := false
	for _, addr := range append(cfg.Server.ListenUDP, cfg.Server.ListenTCP...) {
		if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "[::]:") || strings.HasPrefix(addr, ":") {
			isPublic = true
			break
		}
	}
	if isPublic && !hasDNSACL && !hasRateLimit {
		if logSystem {
			log.Printf("[SECURITY WARNING] Listening on all interfaces (0.0.0.0 / [::]) without DNS ACLs or Rate Limiting enabled. Your server is highly vulnerable to being abused in DNS Amplification attacks!")
		}
	}

	StartServers(tlsConfig)
	StartWebUI(tlsConfig)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	if logSystem {
		log.Printf("[BOOT] Received signal %v — shutting down", s)
	}

	Shutdown()

	SaveStats()
	SaveLogs()
	SaveGroupOverrides()
	SaveRules()
	SaveCache()
}

func parseACL(entries []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, s := range entries {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		if !strings.Contains(s, "/") {
			if addr, err := netip.ParseAddr(s); err == nil {
				addr = addr.Unmap()
				if addr.Is4() {
					s = addr.String() + "/32"
				} else {
					s = addr.String() + "/128"
				}
			}
		}

		if prefix, err := ParsePrefixUnmapped(s); err == nil {
			prefixes = append(prefixes, prefix)
		} else {
			log.Printf("[WARN] Invalid ACL entry %q: %v", s, err)
		}
	}
	return prefixes
}

