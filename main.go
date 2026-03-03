/*
File: main.go
Version: 1.22.0
Last Updated: 2026-03-03 23:00 CET
Description: Application entry point, configuration loading, TLS setup, and
             subsystem initialisation. Defines tiered buffer pools shared across
             server.go and upstream.go.

Changes:
  1.22.0 - [FEAT] DDR.IPv4 and DDR.IPv6 config fields changed from string to
           []string to support multiple resolver addresses per address family.
           ddrIPv4 and ddrIPv6 globals changed from net.IP to []net.IP.
           Parsing validates address family: IPv4 entries rejected in ipv6 list
           and vice versa, with a [WARN] log and skip rather than a fatal error.
           Empty lists are valid — process.go v1.36.0 falls back to the
           incoming query's interface address at query time via ddrAddrs().
           Startup now logs the resolved address lists (or a "will use interface
           address" notice when a list is empty) for easy diagnostics.
  1.21.0 - [PERF] Four feature-presence flags set at startup and used by process.go
           to skip hot-path work when features are unconfigured:
             hasMACRoutes:          true when cfg.Routes has valid MAC entries.
             hasDomainRoutes:       true when cfg.DomainRoutes is non-empty.
             hasRtypePolicy:        true when cfg.RtypePolicy is non-empty.
             hasClientNameUpstream: true when any upstream URL contains {client-name}.
  1.20.0 - [PERF] Route index table: upstream group names mapped to uint8 indices
           (routeIdxByName). DNSCacheKey.RouteIdx replaces Route string field.
           [PERF] SetGCPercent changed from 20 to 100.
  1.19.0 - [FEAT] RType Policy config section.
  1.18.0 - [PERF] logging.log_queries config option.
  1.17.0 - [FEAT] identity.poll_interval config field.
  1.16.0 - [FIX]  DDR SVCB port numbers derived from first configured listener.
  1.15.0 - [PERF] Tiered buffer pools (smallBufPool 4KB, largeBufPool 64KB).
           Added memory_limit_mb config option.
  1.14.0 - Added DomainRoutes initialisation, DDR spoofing, TLS auto-generation.
*/

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// RouteConfig maps a MAC address to a specific upstream group and client identity.
type RouteConfig struct {
	Upstream   string `yaml:"upstream"`
	ClientName string `yaml:"client_name"`
}

// Config is the structured representation of config.yaml.
type Config struct {
	Server struct {
		ListenUDP  []string `yaml:"listen_udp"`
		ListenTCP  []string `yaml:"listen_tcp"`
		ListenDoT  []string `yaml:"listen_dot"`
		ListenDoH  []string `yaml:"listen_doh"`
		ListenDoQ  []string `yaml:"listen_doq"`
		UDPWorkers int      `yaml:"udp_workers"`
		TLSCert    string   `yaml:"tls_cert"`
		TLSKey     string   `yaml:"tls_key"`

		MemoryLimitMB int `yaml:"memory_limit_mb"`

		FilterAAAA     bool `yaml:"filter_aaaa"`
		StrictPTR      bool `yaml:"strict_ptr"`
		FlattenCNAME   bool `yaml:"flatten_cname"`
		MinimizeAnswer bool `yaml:"minimize_answer"`

		DDR struct {
			Enabled   bool     `yaml:"enabled"`
			Hostnames []string `yaml:"hostnames"`
			// IPv4 and IPv6 are lists of resolver addresses to advertise in DDR
			// spoofed responses. Multiple addresses are supported — all are included
			// in SVCB/HTTPS hints and generate individual A/AAAA records.
			// Empty list: process.go falls back to the local interface address of
			// each incoming query at query time. Useful for single-homed setups
			// where the resolver address is always the same as the listener.
			IPv4 []string `yaml:"ipv4"`
			IPv6 []string `yaml:"ipv6"`
		} `yaml:"ddr"`

		UpstreamStaggerMs int `yaml:"upstream_stagger_ms"`
	} `yaml:"server"`

	Logging struct {
		StripTime  bool  `yaml:"strip_time"`
		LogQueries *bool `yaml:"log_queries"`
	} `yaml:"logging"`

	Cache struct {
		Enabled bool `yaml:"enabled"`
		Size    int  `yaml:"size"`
		MinTTL  int  `yaml:"min_ttl"`
	} `yaml:"cache"`

	Identity struct {
		HostsFiles    []string `yaml:"hosts_files"`
		DnsmasqLeases []string `yaml:"dnsmasq_leases"`
		PollInterval  int      `yaml:"poll_interval"`
	} `yaml:"identity"`

	Upstreams    map[string][]string    `yaml:"upstreams"`
	Routes       map[string]RouteConfig `yaml:"routes"`
	DomainRoutes map[string]string      `yaml:"domain_routes"`

	// RtypePolicy maps DNS RR type names to RCODE names (both case-insensitive).
	// Resolved to uint16/int at startup and stored in rtypePolicy for O(1) hot-path use.
	RtypePolicy map[string]string `yaml:"rtype_policy"`
}

var cfg Config

type ParsedRoute struct {
	Upstream   string
	ClientName string
}

// Global read-only state — set during init, never written after (inherently thread-safe).
var (
	macRoutes      map[string]ParsedRoute
	domainRoutes   map[string]string
	routeUpstreams map[string][]*Upstream
	ddrHostnames   map[string]bool

	// ddrIPv4 and ddrIPv6 hold the configured resolver addresses for DDR spoofing.
	// Both are []net.IP so multiple addresses per family are supported.
	// When a slice is empty, process.go falls back to the incoming query's interface
	// address at query time via ddrAddrs() — no static config needed for simple setups.
	ddrIPv4 []net.IP
	ddrIPv6 []net.IP

	ddrDoHPort uint16 = 443
	ddrDoTPort uint16 = 853

	rtypePolicy map[uint16]int

	routeIdxByName  map[string]uint8
	routeIdxLocal   uint8 = 0
	routeIdxDefault uint8

	// Feature-presence flags — set once at startup, read-only after.
	// Allow process.go to skip entire hot-path blocks when features are not in use.
	hasMACRoutes          bool
	hasDomainRoutes       bool
	hasRtypePolicy        bool
	hasClientNameUpstream bool
)

// Tiered buffer pools — shared by server.go and upstream.go.
//
// smallBufPool (4KB): packing outgoing DNS messages. DNS responses are always
// small (< 512B plain, < 4KB with EDNS0). 94% smaller than a 64KB pool per buffer.
//
// largeBufPool (64KB): reading incoming HTTP bodies and DoQ streams where payload
// size is unknown. Matches the DNS wire format maximum for large DNSSEC responses.
var (
	smallBufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}
	largeBufPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

func main() {
	// GOGC=100 (Go default): GC when live heap doubles from its post-GC size.
	// SetMemoryLimit caps the absolute ceiling so memory safety is unaffected.
	debug.SetGCPercent(100)

	configFile := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.22.0")

	data, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[FATAL] Cannot read config %s: %v", *configFile, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("[FATAL] Cannot parse config %s: %v", *configFile, err)
	}

	if cfg.Logging.StripTime {
		log.SetFlags(0)
	} else {
		log.SetFlags(log.Ldate | log.Ltime)
	}

	if cfg.Logging.LogQueries != nil {
		logQueries = *cfg.Logging.LogQueries
	} else {
		logQueries = true
	}
	if logQueries {
		log.Println("[BOOT] Per-query logging enabled (logging.log_queries: true)")
	} else {
		log.Println("[BOOT] Per-query logging disabled (logging.log_queries: false)")
	}

	if cfg.Server.MemoryLimitMB > 0 {
		limit := int64(cfg.Server.MemoryLimitMB) * 1024 * 1024
		debug.SetMemoryLimit(limit)
		log.Printf("[BOOT] Runtime memory limit: %d MB", cfg.Server.MemoryLimitMB)
	}

	if cfg.Server.UDPWorkers <= 0 {
		cfg.Server.UDPWorkers = 10
	}

	upstreamStagger = time.Duration(cfg.Server.UpstreamStaggerMs) * time.Millisecond
	if upstreamStagger > 0 {
		log.Printf("[BOOT] Upstream stagger: %s (parallel racing enabled)", upstreamStagger)
	} else {
		log.Println("[BOOT] Upstream stagger: 0 (sequential mode)")
	}

	// 1. MAC-based routes
	macRoutes = make(map[string]ParsedRoute)
	for macStr, route := range cfg.Routes {
		if parsedMAC, err := net.ParseMAC(macStr); err == nil {
			macRoutes[parsedMAC.String()] = ParsedRoute{
				Upstream:   route.Upstream,
				ClientName: route.ClientName,
			}
		} else {
			log.Printf("[WARN] Invalid MAC in routes: %s", macStr)
		}
	}
	hasMACRoutes = len(macRoutes) > 0
	log.Printf("[INIT] MAC routes: %d entries (ARP polling enabled: %v)", len(macRoutes), hasMACRoutes)

	// 2. Domain-based routes
	domainRoutes = make(map[string]string)
	for domain, upstream := range cfg.DomainRoutes {
		clean := strings.ToLower(strings.TrimSuffix(domain, "."))
		domainRoutes[clean] = upstream
		log.Printf("[INIT] Domain Route: *.%s -> %s", clean, upstream)
	}
	hasDomainRoutes = len(domainRoutes) > 0

	// 3. DDR spoofing
	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		for _, h := range cfg.Server.DDR.Hostnames {
			ddrHostnames[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}

		// Parse IPv4 list — reject entries that are not valid IPv4 addresses.
		for _, s := range cfg.Server.DDR.IPv4 {
			ip := net.ParseIP(s)
			if ip == nil {
				log.Printf("[WARN] DDR ipv4: %q is not a valid IP address — skipped", s)
				continue
			}
			v4 := ip.To4()
			if v4 == nil {
				log.Printf("[WARN] DDR ipv4: %q is an IPv6 address, put it in ipv6 — skipped", s)
				continue
			}
			ddrIPv4 = append(ddrIPv4, v4)
		}

		// Parse IPv6 list — reject entries that are IPv4 addresses.
		for _, s := range cfg.Server.DDR.IPv6 {
			ip := net.ParseIP(s)
			if ip == nil {
				log.Printf("[WARN] DDR ipv6: %q is not a valid IP address — skipped", s)
				continue
			}
			if ip.To4() != nil {
				log.Printf("[WARN] DDR ipv6: %q is an IPv4 address, put it in ipv4 — skipped", s)
				continue
			}
			ddrIPv6 = append(ddrIPv6, ip)
		}

		if len(cfg.Server.ListenDoH) > 0 {
			ddrDoHPort = extractPort(cfg.Server.ListenDoH[0], 443)
		}
		if len(cfg.Server.ListenDoT) > 0 {
			ddrDoTPort = extractPort(cfg.Server.ListenDoT[0], 853)
		} else if len(cfg.Server.ListenDoQ) > 0 {
			ddrDoTPort = extractPort(cfg.Server.ListenDoQ[0], 853)
		}

		log.Printf("[INIT] DDR enabled for %d hostname(s), DoH port: %d, DoT/DoQ port: %d",
			len(ddrHostnames), ddrDoHPort, ddrDoTPort)

		// Log the effective address configuration. Empty slices are valid —
		// process.go falls back to the incoming query's interface address at runtime.
		if len(ddrIPv4) == 0 {
			log.Println("[INIT] DDR IPv4: none configured — will use incoming query interface address")
		} else {
			log.Printf("[INIT] DDR IPv4: %v", ddrIPv4)
		}
		if len(ddrIPv6) == 0 {
			log.Println("[INIT] DDR IPv6: none configured — will use incoming query interface address")
		} else {
			log.Printf("[INIT] DDR IPv6: %v", ddrIPv6)
		}
	}

	// 4. Upstream connections
	routeUpstreams = make(map[string][]*Upstream)
	for groupName, urls := range cfg.Upstreams {
		var group []*Upstream
		for _, rawURL := range urls {
			up, err := ParseUpstream(rawURL)
			if err != nil {
				log.Printf("[WARN] Failed to parse upstream %s: %v", rawURL, err)
				continue
			}
			group = append(group, up)
		}
		routeUpstreams[groupName] = group
		log.Printf("[INIT] Upstream group '%s': %d targets", groupName, len(group))
	}

	if len(routeUpstreams["default"]) == 0 {
		log.Fatal("[FATAL] 'default' upstream group is required but missing or empty.")
	}

	// Scan all upstream groups for {client-name} template usage.
	// Done after routeUpstreams is fully built — single two-level range with early
	// break, so no measurable overhead at startup. Avoids re-parsing raw URLs.
outer:
	for _, group := range routeUpstreams {
		for _, up := range group {
			if up.hasClientNameTemplate {
				hasClientNameUpstream = true
				break outer
			}
		}
	}
	log.Printf("[INIT] {client-name} upstream substitution: %v", hasClientNameUpstream)

	// 5. RType policy
	rtypePolicy = make(map[uint16]int, len(cfg.RtypePolicy))
	for typeName, rcodeName := range cfg.RtypePolicy {
		qtype, ok := dns.StringToType[strings.ToUpper(typeName)]
		if !ok {
			log.Printf("[WARN] rtype_policy: unknown RR type %q — skipped", typeName)
			continue
		}
		rcode, ok := dns.StringToRcode[strings.ToUpper(rcodeName)]
		if !ok {
			log.Printf("[WARN] rtype_policy: unknown RCODE %q for type %s — skipped", rcodeName, typeName)
			continue
		}
		rtypePolicy[qtype] = rcode
		log.Printf("[INIT] RType Policy: %s -> %s", dns.TypeToString[qtype], dns.RcodeToString[rcode])
	}
	hasRtypePolicy = len(rtypePolicy) > 0

	// 6. Route index table
	routeIdxByName = make(map[string]uint8, len(cfg.Upstreams)+4)
	routeIdxByName["local"] = routeIdxLocal
	nextIdx := uint8(1)
	assignIdx := func(name string) {
		if _, exists := routeIdxByName[name]; !exists {
			routeIdxByName[name] = nextIdx
			nextIdx++
		}
	}
	for groupName := range cfg.Upstreams {
		assignIdx(groupName)
	}
	for _, upstream := range cfg.DomainRoutes {
		assignIdx(upstream)
	}
	for _, route := range cfg.Routes {
		if route.Upstream != "" {
			assignIdx(route.Upstream)
		}
	}
	routeIdxDefault = routeIdxByName["default"]
	log.Printf("[INIT] Route index table: %d entries", len(routeIdxByName))

	// 7. Supporting subsystems
	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)

	// ARP polling is Linux-only and only useful when MAC-based routes are configured.
	// Skipping it saves a goroutine + a /proc/net/arp read every 30s + per-query
	// atomic loads in process.go on purely IP-routed or non-Linux deployments.
	if hasMACRoutes {
		InitARP()
	} else {
		log.Println("[ARP] No MAC routes configured — ARP polling disabled.")
	}

	InitIdentity()

	// 8. TLS
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0
	var tlsConfig *tls.Config
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
	}

	// 9. Network listeners
	StartServers(tlsConfig)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[BOOT] Shutting down sdproxy...")
	Shutdown()
}

// extractPort parses the port number from a "host:port" listener address string.
func extractPort(addr string, fallback uint16) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fallback
	}
	return uint16(p)
}

func getHardenedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}
}

func setupTLS() *tls.Config {
	var (
		cert tls.Certificate
		err  error
	)
	if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
		cert, err = tls.LoadX509KeyPair(cfg.Server.TLSCert, cfg.Server.TLSKey)
		if err != nil {
			log.Fatalf("[FATAL] Failed to load TLS certs: %v", err)
		}
		log.Println("[TLS] Loaded provided certificates.")
	} else {
		log.Println("[TLS] No certificates provided — generating ephemeral self-signed cert...")
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("[FATAL] Failed to generate self-signed cert: %v", err)
		}
	}
	conf             := getHardenedTLSConfig()
	conf.Certificates = []tls.Certificate{cert}
	conf.NextProtos   = []string{"h3", "h2", "doq", "dot", "http/1.1"}
	return conf
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"sdproxy"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM   := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM    := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

