/*
File: main.go
Version: 1.27.0
Last Updated: 2026-03-05 19:00 CET
Description: Application entry point, configuration loading, TLS setup, and
             subsystem initialisation. Defines tiered buffer pools shared across
             server.go and upstream.go.

Changes:
  1.27.0 - [FEAT] InitThrottle() called after InitIdentity(). Derives initial
           query and upstream concurrency limits from udp_workers and starts
           the 500 ms AIMD pressure monitor. No new config keys needed.
  1.26.1 - [FEAT] Pre-pack policy RCODE response templates for zero-alloc
           policy fast-paths.
  1.25.0 - [FEAT] domain_policy config section: maps domain suffixes (and all
           their sub-domains) to an immediate RCODE. Parsed into domainPolicy
           map[string]int at startup. Hot-path gated via hasDomainPolicy bool.
           Processed in ProcessDNS at new step 0d — before DDR, local identity,
           domain_routes, and the cache.
  1.24.0 - [FEAT] block_obsolete_qtypes config flag.
  1.23.0 - [FEAT] Cache.MaxTTL config field — caps cached response TTLs.
  1.22.0 - [FEAT] DDR.IPv4/IPv6 changed to []string for multiple addresses.
  1.21.0 - [PERF] Four feature-presence flags set at startup for hot-path gating.
  1.20.0 - [PERF] Route index table: upstream group names mapped to uint8 indices.
  1.19.0 - [FEAT] RType Policy config section.
  1.18.0 - [PERF] logging.log_queries config option.
  1.17.0 - [FEAT] identity.poll_interval config field.
  1.16.0 - [FIX]  DDR SVCB port numbers derived from first configured listener.
  1.15.0 - [PERF] Tiered buffer pools (smallBufPool 4KB, largeBufPool 64KB).
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

		// BlockObsoleteQtypes injects all obsolete/unassigned/reserved RR types
		// into rtypePolicy with NOTIMP at startup, and enables a runtime check
		// for completely unrecognised type numbers (IANA unassigned gaps). See
		// the obsoleteQtypes map for the full list with RFC citations.
		BlockObsoleteQtypes bool `yaml:"block_obsolete_qtypes"`

		DDR struct {
			Enabled   bool     `yaml:"enabled"`
			Hostnames []string `yaml:"hostnames"`
			IPv4      []string `yaml:"ipv4"`
			IPv6      []string `yaml:"ipv6"`
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
		MaxTTL  int  `yaml:"max_ttl"`
	} `yaml:"cache"`

	Identity struct {
		HostsFiles    []string `yaml:"hosts_files"`
		DnsmasqLeases []string `yaml:"dnsmasq_leases"`
		PollInterval  int      `yaml:"poll_interval"`
	} `yaml:"identity"`

	Upstreams    map[string][]string    `yaml:"upstreams"`
	Routes       map[string]RouteConfig `yaml:"routes"`
	DomainRoutes map[string]string      `yaml:"domain_routes"`
	RtypePolicy  map[string]string      `yaml:"rtype_policy"`
	DomainPolicy map[string]string      `yaml:"domain_policy"`
}

var cfg Config

type ParsedRoute struct {
	Upstream   string
	ClientName string
}

// obsoleteQtypes maps IANA RR type numbers to a short label for every type that
// is obsolete, withdrawn, experimental-and-never-standardised, or IANA-reserved
// with no published specification.
var obsoleteQtypes = map[uint16]string{
	3:   "MD",
	4:   "MF",
	7:   "MB",
	8:   "MG",
	9:   "MR",
	10:  "NULL",
	11:  "WKS",
	14:  "MINFO",
	19:  "X25",
	20:  "ISDN",
	21:  "RT",
	22:  "NSAP",
	23:  "NSAP-PTR",
	24:  "SIG",
	25:  "KEY",
	26:  "PX",
	27:  "GPOS",
	30:  "NXT",
	31:  "EID",
	32:  "NIMLOC",
	34:  "ATMA",
	38:  "A6",
	40:  "SINK",
	99:  "SPF",
	100: "UINFO",
	101: "UID",
	102: "GID",
	103: "UNSPEC",
	253: "MAILB",
	254: "MAILA",
}

var (
	macRoutes      map[string]ParsedRoute
	domainRoutes   map[string]string
	routeUpstreams map[string][]*Upstream
	ddrHostnames   map[string]bool

	ddrIPv4 []net.IP
	ddrIPv6 []net.IP

	ddrDoHPort uint16 = 443
	ddrDoTPort uint16 = 853

	rtypePolicy  map[uint16]int
	domainPolicy map[string]int

	routeIdxByName  map[string]uint8
	routeIdxLocal   uint8 = 0
	routeIdxDefault uint8

	hasMACRoutes          bool
	hasDomainRoutes       bool
	hasRtypePolicy        bool
	hasDomainPolicy       bool
	hasClientNameUpstream bool
	blockUnknownQtypes    bool
)

// Tiered buffer pools — shared by server.go and upstream.go.
var (
	smallBufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}
	largeBufPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

func main() {
	debug.SetGCPercent(100)

	configFile := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.27.0")

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
	rtypePolicy = make(map[uint16]int, len(cfg.RtypePolicy)+len(obsoleteQtypes))
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

	// 5b. Domain policy
	domainPolicy = make(map[string]int, len(cfg.DomainPolicy))
	for domainStr, rcodeName := range cfg.DomainPolicy {
		clean := strings.ToLower(strings.TrimSuffix(domainStr, "."))
		if clean == "" {
			log.Printf("[WARN] domain_policy: empty domain key — skipped")
			continue
		}
		rcode, ok := dns.StringToRcode[strings.ToUpper(rcodeName)]
		if !ok {
			log.Printf("[WARN] domain_policy: unknown RCODE %q for domain %q — skipped", rcodeName, domainStr)
			continue
		}
		domainPolicy[clean] = rcode
		log.Printf("[INIT] Domain Policy: *.%s (and apex) -> %s", clean, dns.RcodeToString[rcode])
	}
	hasDomainPolicy = len(domainPolicy) > 0

	// 6. Obsolete qtype blocking
	if cfg.Server.BlockObsoleteQtypes {
		added := 0
		for qtype, label := range obsoleteQtypes {
			if _, userSet := rtypePolicy[qtype]; !userSet {
				rtypePolicy[qtype] = dns.RcodeNotImplemented
				added++
				_ = label
			}
		}
		blockUnknownQtypes = true
		log.Printf("[INIT] Obsolete qtype blocking: %d types injected into rtype_policy (NOTIMP); unassigned type numbers also blocked at query time", added)
	} else {
		log.Println("[INIT] Obsolete qtype blocking: disabled (block_obsolete_qtypes: false)")
	}
	hasRtypePolicy = len(rtypePolicy) > 0

	buildPolicyRespCache()

	// 7. Route index table
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

	// 8. Cache
	InitCache(cfg.Cache.Size, cfg.Cache.MinTTL)
	if cfg.Cache.Enabled {
		if cfg.Cache.MaxTTL > 0 {
			log.Printf("[INIT] Cache TTL bounds: min=%ds, max=%ds", cfg.Cache.MinTTL, cfg.Cache.MaxTTL)
		} else {
			log.Printf("[INIT] Cache TTL bounds: min=%ds, max=unlimited", cfg.Cache.MinTTL)
		}
	}

	// ARP polling is Linux-only and only useful when MAC-based routes are configured.
	if hasMACRoutes {
		InitARP()
	} else {
		log.Println("[ARP] No MAC routes configured — ARP polling disabled.")
	}

	InitIdentity()

	// Adaptive admission control — self-calibrating AIMD throttle.
	// Derives initial concurrency limits from udp_workers and monitors goroutine
	// count + heap pressure every 500 ms. No configuration needed.
	InitThrottle()

	// 9. TLS
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0
	var tlsConfig *tls.Config
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
	}

	// 10. Network listeners
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

