/*
File:    main.go
Version: 1.231.0
Updated: 07-May-2026 09:20 CEST

Description:
  Application entry point and core orchestrator for sdproxy.
  Reads config.yaml, wires all subsystems sequentially, and blocks on signals.

Changes:
  1.231.0 - [FEAT] Integrated `initRRs()` sequentially into the boot process to 
            evaluate and bind A/AAAA/CNAME Spoofed Records natively.
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

	forceRefreshStartup = forceRefreshFlag

	data, err := os.ReadFile(configFile)
	if err != nil {
		if testConfig {
			fmt.Fprintf(os.Stderr, "[TEST] FATAL: Cannot read config file %s: %v\n", configFile, err)
			os.Exit(1)
		}
		log.Fatalf("[FATAL] Cannot read config %s: %v", configFile, err)
	}
	
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		if testConfig {
			fmt.Fprintf(os.Stderr, "[TEST] FATAL: Cannot parse YAML in %s: %v\n", configFile, err)
			os.Exit(1)
		}
		log.Fatalf("[FATAL] Cannot parse config %s: %v", configFile, err)
	}

	valErr := validateConfig()
	
	if testConfig {
		if valErr != nil {
			fmt.Fprintf(os.Stderr, "[TEST] FAILED: Configuration constraint error in %s: %v\n", configFile, valErr)
			os.Exit(1)
		}
		fmt.Printf("[TEST] OK: Configuration %s is valid and structurally sound.\n", configFile)
		os.Exit(0)
	}

	log.Printf("[BOOT] Starting sdproxy (Simple DNS Proxy) - %s", BuildVersion)

	if cfg.Logging.StripTime {
		log.SetFlags(0)
	} else {
		log.SetFlags(log.Ldate | log.Ltime)
	}
	
	if cfg.WebUI.Enabled {
		log.SetOutput(io.MultiWriter(os.Stderr, WebUILogStreamer))
		log.Println("[BOOT] Web UI and background statistics trackers are ENABLED")
	} else {
		log.SetOutput(os.Stderr)
		log.Println("[BOOT] Web UI and background statistics trackers are DISABLED")
	}

	if forceRefreshStartup {
		log.Println("[BOOT] CLI Override: Force-refresh enabled. Ignoring persistent cache metadata.")
	}

	if cfg.Logging.LogQueries != nil {
		logQueries = *cfg.Logging.LogQueries
	} else {
		logQueries = true
	}
	
	logASNDetails = cfg.Logging.LogASNDetails
	logStrategy = cfg.Logging.LogStrategy
	
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

	if ipv4Only && ipv6Only {
		ipVersionSupport = "both"
		log.Println("[BOOT] CLI Override: Both IPv4 and IPv6 requested via flags.")
	} else if ipv4Only {
		ipVersionSupport = "ipv4"
		log.Println("[BOOT] CLI Override: IPv4 only requested via flags.")
	} else if ipv6Only {
		ipVersionSupport = "ipv6"
		log.Println("[BOOT] CLI Override: IPv6 only requested via flags.")
	} else {
		ipVersionSupport = cfg.Server.SupportIPVersion
		if ipVersionSupport == "" {
			ipVersionSupport = "both"
		}
	}
	log.Printf("[BOOT] IP version support: %s", ipVersionSupport)

	if valErr != nil {
		log.Printf("[WARN] %v", valErr)
	}

	LoadStats()
	LoadLogs()
	LoadGroupOverrides()
	InitRules() 
	InitStats()

	if cfg.Server.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.Server.MemoryLimitMB) * 1024 * 1024)
		log.Printf("[BOOT] Runtime memory limit: %d MB", cfg.Server.MemoryLimitMB)
	}

	if cfg.Server.UDPWorkers <= 0 {
		cfg.Server.UDPWorkers = 10
	}

	InitThrottle()      

	globalSelection := cfg.Server.UpstreamSelection
	if globalSelection == "" {
		globalSelection = "stagger"
	}
	log.Printf("[BOOT] Upstream global selection strategy: %s", globalSelection)

	upstreamStagger = time.Duration(cfg.Server.UpstreamStaggerMs) * time.Millisecond
	if upstreamStagger > 0 {
		log.Printf("[BOOT] Upstream stagger: %s (parallel racing enabled)", upstreamStagger)
	} else {
		log.Println("[BOOT] Upstream stagger: 0 (sequential mode)")
	}
	upstreamTimeout = time.Duration(cfg.Server.UpstreamTimeoutMs) * time.Millisecond
	if upstreamTimeout > 0 {
		log.Printf("[BOOT] Upstream timeout: %s per exchange", upstreamTimeout)
	} else {
		log.Println("[BOOT] Upstream timeout: disabled (transport default governs)")
	}

	if cfg.Server.SyntheticTTL > 0 {
		syntheticTTL = uint32(cfg.Server.SyntheticTTL)
	} else {
		syntheticTTL = 60
	}
	log.Printf("[BOOT] Synthetic TTL: %d s (DDR, local identity, NXDOMAIN SOA)", syntheticTTL)

	for _, s := range cfg.Server.BootstrapServers {
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

		u, err := ParseUpstream(rawURL)
		if err != nil {
			log.Fatalf("[FATAL] Bootstrap server %q is invalid: %v", s, err)
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
			if !hasExplicitIP && (u.Proto == "doh" || u.Proto == "doh3") {
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
			log.Fatalf("[FATAL] Bootstrap server %q MUST contain a mandatory IP address (e.g., #1.1.1.1) to avoid resolution deadlocks.", s)
		}

		globalBootstrapServers = append(globalBootstrapServers, u)
	}
	
	if len(globalBootstrapServers) > 0 {
		var names []string
		for _, u := range globalBootstrapServers {
			names = append(names, u.RawURL)
		}
		log.Printf("[BOOT] Bootstrap servers: %s", strings.Join(names, ", "))
	}

	dnsACLAllow = parseACL(cfg.Server.ACL.Allow)
	dnsACLDeny  = parseACL(cfg.Server.ACL.Deny)
	hasDNSACL   = len(dnsACLAllow) > 0 || len(dnsACLDeny) > 0
	if hasDNSACL {
		log.Printf("[BOOT] DNS ACL enabled: %d allow rules, %d deny rules", len(dnsACLAllow), len(dnsACLDeny))
	}

	webUIACLAllow = parseACL(cfg.WebUI.ACL.Allow)
	webUIACLDeny  = parseACL(cfg.WebUI.ACL.Deny)
	hasWebUIACL   = len(webUIACLAllow) > 0 || len(webUIACLDeny) > 0
	if hasWebUIACL {
		log.Printf("[BOOT] Web UI ACL enabled: %d allow rules, %d deny rules", len(webUIACLAllow), len(webUIACLDeny))
	}

	hasRateLimit = cfg.Server.RateLimit.Enabled
	hasRebindingProtection = cfg.Server.RebindingProtection

	isPublic := false
	for _, addr := range append(cfg.Server.ListenUDP, cfg.Server.ListenTCP...) {
		if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "[::]:") || strings.HasPrefix(addr, ":") {
			isPublic = true
			break
		}
	}
	if isPublic && !hasDNSACL && !hasRateLimit {
		log.Printf("[SECURITY WARNING] Listening on all interfaces (0.0.0.0 / [::]) without DNS ACLs or Rate Limiting enabled. Your server is highly vulnerable to being abused in DNS Amplification attacks!")
	}

	initClientRoutes()
	initDomainRoutes()
	initUpstreams()
	initPolicies()
	initBlockAction()
	initRouteIndex()
	initDGA() 
	initRRs()

	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	if cfg.Cache.Enabled {
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

	if hasMACRoutes || hasMACWildRoutes {
		InitARP()
	} else {
		log.Println("[ARP] No MAC routes configured — ARP polling disabled.")
	}

	InitIdentity()      
	InitRateLimiter()   
	InitExfiltration() 
	InitParental()      

	var tlsConfig *tls.Config
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0 || len(cfg.WebUI.ListenHTTPS) > 0
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
	}

	initDDR() 

	StartServers(tlsConfig)
	StartWebUI(tlsConfig)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("[BOOT] Received signal %v — shutting down", s)

	Shutdown()
	
	SaveStats()
	SaveLogs()
	SaveGroupOverrides()
	SaveRules()
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
				if addr.Is4() {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		
		if prefix, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, prefix)
		} else {
			log.Printf("[WARN] Invalid ACL entry %q: %v", s, err)
		}
	}
	return prefixes
}

