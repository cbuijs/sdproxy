/*
File: main.go
Version: 1.15.0
Last Updated: 2026-03-01 14:00 CET
Description: Application entry point, configuration loading, TLS setup, and
             subsystem initialisation. Defines tiered buffer pools shared across
             server.go and upstream.go.

Changes:
  1.15.0 - [PERF] Replaced single 64KB bufPool with two tiered pools:
             smallBufPool (4KB) for DNS message packing/writing — the hot path.
             largeBufPool (64KB) for HTTP/stream body reads where size is unknown.
           On a router with 10 UDP workers + DoH/DoQ connections, the old pool
           could hold 1.2MB just in idle buffers. The tiered approach cuts typical
           idle buffer memory by ~75% while keeping correctness for large reads.
           [FEAT] Added memory_limit_mb config option. Uses debug.SetMemoryLimit
           (Go 1.19+) to give the runtime a hard memory ceiling. Without this, Go's
           GC has no idea how much RAM the device has and may allocate aggressively.
           Set to (device_total_ram_mb - 10) as a starting point.
           [FIX]  Calls Shutdown() on SIGTERM to signal UDP workers to exit cleanly.
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
		// Go's GC is unaware of total device RAM without this — on a 32MB router
		// it may allocate far too aggressively. Set to (device_ram_mb - 10).
		// 0 = disabled (default — safe to omit from config).
		MemoryLimitMB int `yaml:"memory_limit_mb"`

		DDR struct {
			Enabled   bool     `yaml:"enabled"`
			Hostnames []string `yaml:"hostnames"`
			IPv4      string   `yaml:"ipv4"`
			IPv6      string   `yaml:"ipv6"`
		} `yaml:"ddr"`
	} `yaml:"server"`

	Logging struct {
		StripTime bool `yaml:"strip_time"`
	} `yaml:"logging"`

	Cache struct {
		Enabled bool `yaml:"enabled"`
		Size    int  `yaml:"size"`
		MinTTL  int  `yaml:"min_ttl"`
	} `yaml:"cache"`

	Identity struct {
		HostsFiles    []string `yaml:"hosts_files"`
		DnsmasqLeases []string `yaml:"dnsmasq_leases"`
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
	macRoutes    map[string]ParsedRoute
	domainRoutes map[string]string
	routeUpstreams map[string][]*Upstream
	ddrHostnames map[string]bool
	ddrIPv4      net.IP
	ddrIPv6      net.IP
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
	// Aggressive GC tuning: prioritise throughput over GC frequency.
	// GOGC=20 means GC triggers when live heap grows by 20% — keeps memory tight.
	debug.SetGCPercent(20)

	configFile := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.15.0")

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

	// Hard memory ceiling — critical on routers with 32–128 MB RAM.
	// Without this, the Go runtime has no idea how constrained the device is
	// and may allocate well beyond what the device can sustain.
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
		log.Printf("[INIT] DDR enabled for %d hostnames", len(ddrHostnames))
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

	// 5. Supporting subsystems
	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	InitARP()
	InitIdentity()

	// 6. TLS
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0
	var tlsConfig *tls.Config
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
	}

	// 7. Network listeners
	StartServers(tlsConfig)

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[BOOT] Shutting down sdproxy...")
	Shutdown() // Signal UDP workers to exit cleanly before process exits
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
	certPEM  := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM   := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

