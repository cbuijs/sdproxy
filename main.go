/*
File: main.go
Version: 1.20.0
Last Updated: 2026-03-03 16:00 CET
Description: Application entry point, configuration loading, TLS setup, and
             subsystem initialisation. Defines tiered buffer pools shared across
             server.go and upstream.go.

Changes:
  1.20.0 - [PERF] Route index table: upstream group names are mapped to uint8
           indices at startup (routeIdxByName). ProcessDNS uses the index in
           DNSCacheKey.RouteIdx instead of a Route string, eliminating per-lookup
           string pointer chasing in getShard (cache.go v1.14.0).
           routeIdxLocal (0) is reserved for local hosts/leases cache entries and
           never appears in cfg.Upstreams. routeIdxDefault points to "default".
           getRouteIdx() provides a safe lookup with a "default" fallback.
           [PERF] Changed SetGCPercent from 20 to 100. GOGC=20 triggered GC every
           time the live heap grew by 20% — on a 4 MB live heap that's a collection
           every 0.8 MB of allocation, causing more STW pauses than necessary.
           GOGC=100 (Go's default) lets the heap breathe between collections.
           SetMemoryLimit already caps the ceiling, so memory safety is unchanged.
  1.19.0 - [FEAT] RType Policy config section.
  1.18.0 - [PERF] Added logging.log_queries config option. Controls whether
           per-query log lines are emitted in ProcessDNS. log.Printf acquires a
           global mutex and runs fmt.Sprintf with reflection — with 10 UDP workers
           all logging on every query this was the single biggest serialisation
           point under load. When log_queries is false, per-query log lines are
           suppressed entirely — no mutex, no formatting, no I/O. Error messages
           and startup/shutdown lines always log regardless. The logQueries global
           bool is set once at startup and read without locking (immutable after init).
  1.17.0 - [FEAT] Added identity.poll_interval config field. Controls how often
           hosts and lease files are checked for changes. Defaults to 30 seconds
           when omitted or 0; enforced floor of 5 seconds (identity.go).
  1.16.0 - [FIX]  DDR SVCB port numbers were hardcoded to 443 (DoH) and 853
           (DoT/DoQ). Ports are now derived from the first configured listener
           address for each protocol at startup and stored as ddrDoHPort and
           ddrDoTPort globals.
  1.15.0 - [PERF] Replaced single 64KB bufPool with tiered smallBufPool (4KB) and
           largeBufPool (64KB). Added memory_limit_mb config option.
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
			IPv4      string   `yaml:"ipv4"`
			IPv6      string   `yaml:"ipv6"`
		} `yaml:"ddr"`

		UpstreamStaggerMs int `yaml:"upstream_stagger_ms"`
	} `yaml:"server"`

	Logging struct {
		StripTime bool `yaml:"strip_time"`

		// LogQueries controls per-query log output in ProcessDNS.
		// true  = every query is logged with client IP, route, upstream, etc.
		//         (good for debugging, bad for throughput under high load)
		// false = per-query lines suppressed; errors and startup lines still log.
		// Default: true (set explicitly in config or defaults to true below).
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
	// At startup these strings are resolved to uint16/int via dns.StringToType and
	// dns.StringToRcode and stored in the rtypePolicy global for O(1) hot-path use.
	// Example: {"ANY": "REFUSED", "HINFO": "NOTIMP", "AXFR": "REFUSED"}
	RtypePolicy map[string]string `yaml:"rtype_policy"`
}

var cfg Config

type ParsedRoute struct {
	Upstream   string
	ClientName string
}

// Global read-only state (set during init, never written after — inherently thread-safe)
var (
	macRoutes      map[string]ParsedRoute
	domainRoutes   map[string]string
	routeUpstreams map[string][]*Upstream
	ddrHostnames   map[string]bool
	ddrIPv4        net.IP
	ddrIPv6        net.IP

	ddrDoHPort uint16 = 443
	ddrDoTPort uint16 = 853

	// rtypePolicy: parsed from cfg.RtypePolicy at startup. Key: DNS qtype (uint16),
	// value: RCODE (int). O(1) lookup in ProcessDNS step 0.
	rtypePolicy map[uint16]int

	// routeIdxByName maps upstream group names to uint8 indices for use in
	// DNSCacheKey.RouteIdx. Assigned once at startup, never written after.
	//   routeIdxLocal (0)   — reserved for local hosts/leases cache entries
	//   routeIdxDefault     — index of the "default" upstream group
	// All other groups are assigned indices starting at 1.
	routeIdxByName map[string]uint8

	// routeIdxLocal is the fixed index for local-only cache entries.
	// It is const 0 and never appears in cfg.Upstreams.
	routeIdxLocal uint8 = 0

	// routeIdxDefault is the index of the "default" upstream group.
	// Set at startup once routeIdxByName is built.
	routeIdxDefault uint8
)

// Tiered buffer pools — shared by server.go and upstream.go.
//
// smallBufPool (4KB): for packing outgoing DNS messages. DNS responses are always
// small (< 512B plain, < 4KB with EDNS0). Using a 4KB pool here vs 64KB cuts
// per-buffer memory by 94% on the hot packing path.
//
// largeBufPool (64KB): for reading incoming HTTP bodies and DoQ streams where the
// payload size is unknown ahead of time. 64KB matches the DNS wire format maximum
// and ensures correctness for large DNSSEC responses.
var (
	smallBufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}
	largeBufPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

func main() {
	// GOGC=100 (Go default): GC when live heap doubles from its post-GC size.
	// The previous value of 20 triggered GC every time the heap grew 20% —
	// on a small heap (4-8 MB) that means a collection every ~0.8 MB of allocation,
	// with measurable STW pauses. GOGC=100 gives the heap room to breathe.
	// SetMemoryLimit (configured below) already caps the absolute ceiling, so
	// memory safety is maintained regardless of GOGC.
	debug.SetGCPercent(100)

	configFile := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.20.0")

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

	// Wire up conditional per-query logging. When false, all per-query log lines
	// in ProcessDNS are suppressed entirely — no mutex, no fmt.Sprintf, no I/O.
	// Errors and startup messages always log regardless.
	// Default: true (when omitted from config) — safe for small networks and debugging.
	if cfg.Logging.LogQueries != nil {
		logQueries = *cfg.Logging.LogQueries
	} else {
		logQueries = true // Default: log everything — user must opt out
	}
	if logQueries {
		log.Println("[BOOT] Per-query logging enabled (logging.log_queries: true)")
	} else {
		log.Println("[BOOT] Per-query logging disabled (logging.log_queries: false)")
	}

	// Hard memory ceiling — critical on routers with 32-128 MB RAM.
	if cfg.Server.MemoryLimitMB > 0 {
		limit := int64(cfg.Server.MemoryLimitMB) * 1024 * 1024
		debug.SetMemoryLimit(limit)
		log.Printf("[BOOT] Runtime memory limit: %d MB", cfg.Server.MemoryLimitMB)
	}

	if cfg.Server.UDPWorkers <= 0 {
		cfg.Server.UDPWorkers = 10
	}

	// Staggered parallel upstream racing (upstream.go raceExchange).
	// 0 = sequential (no parallelism). >0 = stagger delay between parallel launches.
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

	// 2. Domain-based routes (O(1) suffix lookup map)
	domainRoutes = make(map[string]string)
	for domain, upstream := range cfg.DomainRoutes {
		clean := strings.ToLower(strings.TrimSuffix(domain, "."))
		domainRoutes[clean] = upstream
		log.Printf("[INIT] Domain Route: *.%s -> %s", clean, upstream)
	}

	// 3. DDR spoofing
	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		for _, h := range cfg.Server.DDR.Hostnames {
			ddrHostnames[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}
		if cfg.Server.DDR.IPv4 != "" {
			ddrIPv4 = net.ParseIP(cfg.Server.DDR.IPv4)
		}
		if cfg.Server.DDR.IPv6 != "" {
			ddrIPv6 = net.ParseIP(cfg.Server.DDR.IPv6)
		}

		if len(cfg.Server.ListenDoH) > 0 {
			ddrDoHPort = extractPort(cfg.Server.ListenDoH[0], 443)
		}
		if len(cfg.Server.ListenDoT) > 0 {
			ddrDoTPort = extractPort(cfg.Server.ListenDoT[0], 853)
		} else if len(cfg.Server.ListenDoQ) > 0 {
			ddrDoTPort = extractPort(cfg.Server.ListenDoQ[0], 853)
		}

		log.Printf("[INIT] DDR enabled for %d hostnames (DoH port: %d, DoT/DoQ port: %d)",
			len(ddrHostnames), ddrDoHPort, ddrDoTPort)
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

	// 6. Route index table — assigns a uint8 index to every upstream group name.
	// Index 0 (routeIdxLocal) is reserved for local hosts/leases cache entries and
	// must not clash with any user-defined group. Indices start at 1 for all groups.
	// Also indexes any group name referenced in domain_routes or MAC routes that
	// isn't a key in cfg.Upstreams (config error, but we handle it gracefully).
	routeIdxByName = make(map[string]uint8, len(cfg.Upstreams)+4)
	routeIdxByName["local"] = routeIdxLocal // index 0 reserved
	nextIdx := uint8(1)
	assignIdx := func(name string) {
		if _, exists := routeIdxByName[name]; !exists {
			routeIdxByName[name] = nextIdx
			nextIdx++ // wraps at 255; ≥254 upstream groups is not a real concern
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
	routeIdxDefault = routeIdxByName["default"] // "default" is guaranteed to exist (fatal check above)
	log.Printf("[INIT] Route index table: %d entries", len(routeIdxByName))

	// 7. Supporting subsystems
	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	InitARP()
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

	// Wait for termination signal
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

