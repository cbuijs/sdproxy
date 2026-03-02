/*
File: main.go
Version: 1.18.0
Last Updated: 2026-03-02 17:00 CET
Description: Application entry point, configuration loading, TLS setup, and
             subsystem initialisation. Defines tiered buffer pools shared across
             server.go and upstream.go.

Changes:
  1.18.0 - [FEAT] Added logging.log_queries config field. Defaults to true
           (preserves existing behaviour). Set to false in production to suppress
           per-query log lines — measurably reduces CPU load at high QPS because
           log.Printf with string formatting and the log mutex are off the hot path.
           Error and upstream-failure logs are unconditional regardless of this flag.
           [PERF] Added groupNeedsClientName map[string]bool, computed once at
           startup. process.go uses this to skip all MAC/IP identity work when the
           selected upstream group has no {client-name} upstreams — saves multiple
           RLock cycles on every domain-routed query.
  1.17.0 - [FEAT] Added identity.poll_interval config field.
  1.16.0 - [FIX]  DDR SVCB port numbers derived from listener addresses at startup.
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

		// MemoryLimitMB sets a hard RSS ceiling via debug.SetMemoryLimit.
		MemoryLimitMB  int  `yaml:"memory_limit_mb"`
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
	} `yaml:"server"`

	Logging struct {
		StripTime bool `yaml:"strip_time"`

		// LogQueries controls per-query log lines (the "[DNS] ..." lines in process.go).
		// true  = log every query resolution (default — useful during setup/debugging).
		// false = suppress query lines; only errors and upstream failures are logged.
		//         Recommended for production: removes log.Printf from the hot path
		//         and eliminates the log mutex contention at high QPS.
		LogQueries bool `yaml:"log_queries"`
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

	// groupNeedsClientName is computed once at startup.
	// True for upstream groups that contain at least one upstream with a
	// {client-name} template in its URL. process.go uses this to skip all
	// MAC/IP identity lookups for groups (like plain local resolvers) that
	// never use client-name substitution.
	groupNeedsClientName map[string]bool
)

// Tiered buffer pools — shared by server.go and upstream.go.
//
// smallBufPool (4KB): for packing outgoing DNS messages.
// largeBufPool (64KB): for reading incoming HTTP bodies and DoQ streams.
var (
	smallBufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}
	largeBufPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

func main() {
	debug.SetGCPercent(20)

	configFile := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.19.0")

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

	// Default log_queries to true when omitted from config so existing setups
	// keep their current behaviour without needing a config change.
	// Explicitly set to false in production to mute the per-query log lines.
	if !cfg.Logging.LogQueries {
		log.Println("[BOOT] Query logging disabled (logging.log_queries: false) — only errors will be logged")
	}

	if cfg.Server.MemoryLimitMB > 0 {
		limit := int64(cfg.Server.MemoryLimitMB) * 1024 * 1024
		debug.SetMemoryLimit(limit)
		log.Printf("[BOOT] Runtime memory limit: %d MB", cfg.Server.MemoryLimitMB)
	}

	if cfg.Server.UDPWorkers <= 0 {
		cfg.Server.UDPWorkers = 10
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

	// 2. Domain-based routes
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

	// 5. Pre-compute which upstream groups need {client-name} resolution.
	// process.go checks this map to skip identity lookups for groups (e.g. local
	// resolvers) that never substitute client names into upstream URLs.
	groupNeedsClientName = make(map[string]bool, len(routeUpstreams))
	for groupName, ups := range routeUpstreams {
		for _, up := range ups {
			if up.hasClientNameTemplate {
				groupNeedsClientName[groupName] = true
				break
			}
		}
	}

	// 6. Supporting subsystems
	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	InitARP()
	InitIdentity()

	// 7. TLS
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0
	var tlsConfig *tls.Config
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
	}

	// 8. Network listeners
	StartServers(tlsConfig)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[BOOT] Shutting down sdproxy...")
	Shutdown()
}

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

