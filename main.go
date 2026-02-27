/*
File: main.go
Version: 1.14.0
Last Updated: 2026-02-27 21:45 CET
Description: Application entry point, Configuration loading, and TLS generation.
             Added DomainRoutes initialization for zero-allocation domain routing.
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

// RouteConfig maps a MAC address to a specific upstream and client identity
type RouteConfig struct {
	Upstream   string `yaml:"upstream"`
	ClientName string `yaml:"client_name"`
}

// Config represents the structured configuration of sdproxy
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
	DomainRoutes map[string]string      `yaml:"domain_routes"` // Maps domain suffixes to upstreams
}

var cfg Config

type ParsedRoute struct {
	Upstream   string
	ClientName string
}

// Global state structures (Read-Only after Init, inherently thread-safe)
var macRoutes map[string]ParsedRoute
var domainRoutes map[string]string
var routeUpstreams map[string][]*Upstream
var ddrHostnames map[string]bool
var ddrIPv4 net.IP
var ddrIPv6 net.IP

// High-performance byte buffer pool to minimize garbage collection latency
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536) 
		return &b
	},
}

func main() {
	// Aggressive GC tuning: optimize for throughput and CPU utilization in network apps
	debug.SetGCPercent(20)

	configFile := flag.String("config", "config.yaml", "Path to configuration file (YAML)")
	flag.Parse()

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.14.0")

	data, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[FATAL] Could not read config file %s: %v", *configFile, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("[FATAL] Could not parse config file %s: %v", *configFile, err)
	}

	if cfg.Logging.StripTime {
		log.SetFlags(0)
	} else {
		log.SetFlags(log.Ldate | log.Ltime) 
	}

	if cfg.Server.UDPWorkers <= 0 {
		cfg.Server.UDPWorkers = 10
	}

	// 1. Initialize MAC-based routes
	macRoutes = make(map[string]ParsedRoute)
	for macStr, route := range cfg.Routes {
		parsedMAC, err := net.ParseMAC(macStr)
		if err == nil {
			macRoutes[parsedMAC.String()] = ParsedRoute{
				Upstream:   route.Upstream,
				ClientName: route.ClientName,
			}
		} else {
			log.Printf("[WARN] Invalid MAC address in routes: %s", macStr)
		}
	}

	// 2. Initialize Domain-based routes (O(1) lookup maps)
	domainRoutes = make(map[string]string)
	for domain, upstream := range cfg.DomainRoutes {
		// Clean the input to ensure reliable suffix matching
		cleanDomain := strings.ToLower(strings.TrimSuffix(domain, "."))
		domainRoutes[cleanDomain] = upstream
		log.Printf("[INIT] Domain Route configured: *.%s -> Upstream: %s", cleanDomain, upstream)
	}

	// 3. Initialize DDR Spoofing configurations
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
		log.Printf("[INIT] DDR Spoofing enabled for %d hostnames", len(ddrHostnames))
	}

	// 4. Initialize Upstream connections
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
		log.Printf("[INIT] Upstream Group '%s' loaded with %d targets", groupName, len(group))
	}

	if len(routeUpstreams["default"]) == 0 {
		log.Fatal("[FATAL] 'default' upstream group is required but missing or empty.")
	}

	// 5. Initialize supporting subsystems
	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	InitARP() 
	InitIdentity() // Background poller for /etc/hosts and leases

	// 6. Setup Crypto/TLS layer
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0
	var tlsConfig *tls.Config
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured. Skipping TLS allocation.")
	}

	// 7. Ignite network listeners
	StartServers(tlsConfig)

	// Await termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[BOOT] Shutting down sdproxy...")
}

// getHardenedTLSConfig provides a highly secure cipher configuration
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

// setupTLS loads specified certs or generates an ephemeral one
func setupTLS() *tls.Config {
	var cert tls.Certificate
	var err error

	if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
		cert, err = tls.LoadX509KeyPair(cfg.Server.TLSCert, cfg.Server.TLSKey)
		if err != nil {
			log.Fatalf("[FATAL] Failed to load TLS certificates: %v", err)
		}
		log.Println("[TLS] Loaded provided certificates.")
	} else {
		log.Println("[TLS] No certificates provided. Generating self-signed ephemeral certificate...")
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("[FATAL] Failed to generate self-signed cert: %v", err)
		}
	}

	conf := getHardenedTLSConfig()
	conf.Certificates = []tls.Certificate{cert}
	// ALPN negotiation support
	conf.NextProtos = []string{"h3", "h2", "doq", "dot", "http/1.1"} 
	return conf
}

// generateSelfSignedCert creates a safe temporary ECDSA certificate
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
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

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

