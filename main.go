/*
File:    main.go
Version: 1.30.0
Updated: 2026-03-14 12:00 CET

Description:
  Application entry point, configuration loading, TLS setup, and subsystem
  initialisation. Defines tiered buffer pools shared across server.go and
  upstream.go.

Changes:
  1.30.0 - [FEAT] bypass_local per-route flag: when true, local A/AAAA/PTR
           answers from hosts/leases files are skipped for that route and the
           query goes straight to the upstream. Client identification (clientName
           for logging and {client-name} substitution) is unaffected — the
           identity tables are still consulted for that purpose.
           Added BypassLocal bool to RouteConfig and ParsedRoute (MAC routes).
           Added DomainRouteConfig struct with custom UnmarshalYAML so existing
           compact "domain": "upstream" YAML entries remain valid unchanged.
           Added domainRouteEntry runtime struct. Changed domainRoutes global
           from map[string]string to map[string]domainRouteEntry. Updated init
           blocks for MAC routes (step 1), domain routes (step 2), and the
           route index table (step 7) accordingly.
  1.29.2 - [FEAT] Config.Identity: added IscLeases, KeaLeases, and OdhcpdLeases
           []string fields (yaml: "isc_leases", "kea_leases", "odhcpd_leases")
           for ISC DHCP, Kea DHCP4, and odhcpd lease file support.
  1.29.1 - [FIX] Restored getHardenedTLSConfig() which was accidentally dropped
           during the v1.29.0 rewrite. upstream.go calls it directly 4× for its
           DoT/DoH/DoH3/DoQ client TLS configs. setupTLS() now builds on it
           correctly again. generateSelfSignedCert() aligned with the original.
  1.29.0 - [FEAT] Cache.NegativeTTL: dedicated TTL floor for NXDOMAIN/NODATA
           responses, independent of min_ttl.
           [FEAT] Cache.StaleTTL: serve-stale window length in seconds per
           RFC 8767.
  1.28.0 - [FEAT] Global bootstrap servers: added BootstrapServers []string to
           the Server config struct (yaml: "bootstrap_servers").
  1.27.0 - [FEAT] InitThrottle() called after InitIdentity().
  1.26.1 - [FEAT] Pre-pack policy RCODE response templates for zero-alloc
           policy fast-paths.
  1.25.0 - [FEAT] domain_policy config section: maps domain suffixes to RCODE.
  1.24.0 - [FEAT] block_obsolete_qtypes config flag.
  1.23.0 - [FEAT] Cache.MaxTTL config field.
  1.22.0 - [FEAT] DDR.IPv4/IPv6 changed to []string for multiple addresses.
  1.21.0 - [PERF] Four feature-presence flags set at startup for hot-path gating.
  1.20.0 - [PERF] Route index table: upstream group names mapped to uint8 indices.
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

// RouteConfig maps a MAC address to a specific upstream group, an optional
// client name override, and the optional bypass_local flag.
type RouteConfig struct {
	Upstream   string `yaml:"upstream"`
	ClientName string `yaml:"client_name"`
	// BypassLocal — when true, local A/AAAA/PTR answers from hosts/leases files
	// are not returned for queries from this client. Queries always go to the
	// upstream instead. Identity lookups for {client-name} and logging are
	// unaffected — the identity tables are still used for naming purposes.
	BypassLocal bool `yaml:"bypass_local"`
}

// DomainRouteConfig is the per-entry configuration for domain_routes.
// Supports both the compact string form and the new expanded map form:
//
//	compact:  "lan": "local_network"
//	expanded: "lan": { upstream: "local_network", bypass_local: true }
//
// The custom UnmarshalYAML makes both forms transparent — no migration needed.
type DomainRouteConfig struct {
	Upstream string `yaml:"upstream"`
	// BypassLocal — when true, local A/AAAA/PTR answers from hosts/leases files
	// are skipped for queries matching this domain suffix. See RouteConfig.BypassLocal.
	BypassLocal bool `yaml:"bypass_local"`
}

// UnmarshalYAML handles both the compact scalar form ("upstream_name") and the
// expanded map form ({ upstream: "name", bypass_local: true }).
func (d *DomainRouteConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		// Old compact string form — just an upstream group name.
		d.Upstream = value.Value
		return nil
	}
	// New expanded map form — decode normally. Use a type alias to avoid
	// infinite recursion through this same UnmarshalYAML.
	type plain DomainRouteConfig
	return value.Decode((*plain)(d))
}

// domainRouteEntry is the normalised runtime form of a DomainRouteConfig entry.
// Stored in the domainRoutes map after startup; read on every query by walkDomainMaps.
type domainRouteEntry struct {
	upstream    string
	bypassLocal bool
}

// Config is the structured representation of config.yaml.
// All fields have yaml tags matching the config file keys.
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

		// MemoryLimitMB sets a hard memory ceiling via debug.SetMemoryLimit.
		// 0 = disabled (default).
		MemoryLimitMB int `yaml:"memory_limit_mb"`

		FilterAAAA     bool `yaml:"filter_aaaa"`
		StrictPTR      bool `yaml:"strict_ptr"`
		FlattenCNAME   bool `yaml:"flatten_cname"`
		MinimizeAnswer bool `yaml:"minimize_answer"`

		// BlockObsoleteQtypes injects all obsolete/unassigned/reserved RR types
		// into rtypePolicy with NOTIMP at startup, and enables a runtime check
		// for completely unrecognised type numbers (IANA unassigned gaps).
		BlockObsoleteQtypes bool `yaml:"block_obsolete_qtypes"`

		DDR struct {
			Enabled   bool     `yaml:"enabled"`
			Hostnames []string `yaml:"hostnames"`
			IPv4      []string `yaml:"ipv4"`
			IPv6      []string `yaml:"ipv6"`
		} `yaml:"ddr"`

		// UpstreamStaggerMs is the delay between the first and subsequent upstream
		// probes in a parallel race. 0 = sequential (default).
		UpstreamStaggerMs int `yaml:"upstream_stagger_ms"`

		// BootstrapServers is an optional list of plain-DNS servers (IP or IP:port,
		// UDP only) used to resolve upstream hostnames that have no per-URL
		// bootstrap IPs. Entries without a port default to :53.
		// Per-URL bootstrap IPs always take precedence over these global servers.
		// When empty, upstreams with hostnames (not bare IPs) and no per-URL
		// bootstrap IPs fall back to the OS resolver at connection time.
		BootstrapServers []string `yaml:"bootstrap_servers"`
	} `yaml:"server"`

	Logging struct {
		LogQueries *bool `yaml:"log_queries"`
		StripTime  bool  `yaml:"strip_time"`
	} `yaml:"logging"`

	Cache struct {
		Enabled     bool `yaml:"enabled"`
		Size        int  `yaml:"size"`
		MinTTL      int  `yaml:"min_ttl"`
		MaxTTL      int  `yaml:"max_ttl"`
		NegativeTTL int  `yaml:"negative_ttl"`
		StaleTTL    int  `yaml:"stale_ttl"`
	} `yaml:"cache"`

	Identity struct {
		// HostsFiles lists standard /etc/hosts-format files to load.
		HostsFiles []string `yaml:"hosts_files"`

		// DnsmasqLeases lists dnsmasq flat-file lease databases to load.
		// Format: <expiry> <mac> <ip> <hostname> <clientid>
		DnsmasqLeases []string `yaml:"dnsmasq_leases"`

		// IscLeases lists ISC DHCP block-structured lease files to load.
		// Block-structured dhcpd.leases; only active/static bindings imported.
		// Common paths: /var/lib/dhcp/dhcpd.leases, /var/db/dhcpd.leases
		IscLeases []string `yaml:"isc_leases"`

		// KeaLeases lists Kea DHCP4 CSV lease files to load.
		// Only state=0 (active) rows are imported.
		// Common path: /var/lib/kea/kea-leases4.csv
		KeaLeases []string `yaml:"kea_leases"`

		// OdhcpdLeases lists odhcpd internal state files to load.
		// Data lines start with '#'; format: # iface mac/duid iaid hostname ttl ip/plen...
		// Used when running odhcpd standalone (no dnsmasq). The standard
		// /tmp/hosts/odhcpd file (hosts format) should go in HostsFiles instead.
		// Common path: /var/lib/odhcpd/dhcp.leases
		OdhcpdLeases []string `yaml:"odhcpd_leases"`

		// PollInterval is how often (in seconds) all identity files are re-checked.
		// 0 = load once at startup only. Minimum enforced: 5 seconds.
		PollInterval int `yaml:"poll_interval"`
	} `yaml:"identity"`

	Upstreams    map[string][]string          `yaml:"upstreams"`
	Routes       map[string]RouteConfig       `yaml:"routes"`
	// DomainRoutes maps domain suffixes to upstream groups. Both forms are valid:
	//   compact:  "lan": "local_network"
	//   expanded: "lan": { upstream: "local_network", bypass_local: true }
	DomainRoutes map[string]DomainRouteConfig `yaml:"domain_routes"`
	RtypePolicy  map[string]string            `yaml:"rtype_policy"`
	DomainPolicy map[string]string            `yaml:"domain_policy"`
}

var cfg Config

// ParsedRoute is the resolved form of a RouteConfig entry after MAC validation.
type ParsedRoute struct {
	Upstream    string
	ClientName  string
	// BypassLocal mirrors RouteConfig.BypassLocal — carried into the hot-path.
	BypassLocal bool
}

// obsoleteQtypes maps IANA RR type numbers to a short label for every type that
// is obsolete, withdrawn, experimental-and-never-standardised, or reserved.
// Injected into rtypePolicy when block_obsolete_qtypes is true.
var obsoleteQtypes = map[uint16]string{
	3: "MD", 4: "MF", 7: "MB", 8: "MG", 9: "MR", 10: "NULL",
	11: "WKS", 14: "MINFO", 19: "X25", 20: "ISDN", 21: "RT",
	22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
	27: "GPOS", 30: "NXT", 31: "EID", 32: "NIMLOC", 34: "ATMA",
	38: "A6", 40: "SINK", 99: "SPF", 100: "UINFO", 101: "UID",
	102: "GID", 103: "UNSPEC", 253: "MAILB", 254: "MAILA",
}

var (
	macRoutes      map[string]ParsedRoute
	domainRoutes   map[string]domainRouteEntry // key: lowercase trimmed domain suffix
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

	// globalBootstrapServers is populated from cfg.Server.BootstrapServers at
	// startup. Entries are normalised to "ip:port" form (default port 53).
	// Declared here (main.go) and read by upstream.go (same package).
	globalBootstrapServers []string
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

	log.Println("[BOOT] Starting sdproxy (Simple DNS Proxy) - v1.30.0")

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

	// --- Global bootstrap servers ---
	// Normalise each entry to "ip:port" (default port 53 for plain DNS).
	// These are used by ParseUpstream when an upstream hostname has no per-URL
	// bootstrap IPs — resolved once at startup, not at query time.
	for _, s := range cfg.Server.BootstrapServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host, port, splitErr := net.SplitHostPort(s)
		if splitErr != nil {
			// No port — treat the whole string as a bare IP.
			if net.ParseIP(s) == nil {
				log.Printf("[WARN] bootstrap_servers: %q is not a valid IP address — skipped", s)
				continue
			}
			globalBootstrapServers = append(globalBootstrapServers, net.JoinHostPort(s, "53"))
		} else {
			if net.ParseIP(host) == nil {
				log.Printf("[WARN] bootstrap_servers: %q — host part is not a valid IP address — skipped", s)
				continue
			}
			if _, err := strconv.ParseUint(port, 10, 16); err != nil {
				log.Printf("[WARN] bootstrap_servers: %q — invalid port — skipped", s)
				continue
			}
			globalBootstrapServers = append(globalBootstrapServers, s)
		}
	}
	if len(globalBootstrapServers) > 0 {
		log.Printf("[INIT] Global bootstrap servers: %v", globalBootstrapServers)
	} else {
		log.Println("[INIT] Global bootstrap servers: none — upstreams with hostname URLs require per-URL bootstrap IPs (#ip)")
	}

	// 1. MAC-based routes
	macRoutes = make(map[string]ParsedRoute)
	for macStr, route := range cfg.Routes {
		parsedMAC, err := net.ParseMAC(macStr)
		if err != nil {
			log.Printf("[WARN] Invalid MAC in routes: %s", macStr)
			continue
		}
		macRoutes[parsedMAC.String()] = ParsedRoute{
			Upstream:    route.Upstream,
			ClientName:  route.ClientName,
			BypassLocal: route.BypassLocal,
		}
		if route.BypassLocal {
			log.Printf("[INIT] MAC Route: %s -> %s (bypass_local=true)", parsedMAC, route.Upstream)
		} else {
			log.Printf("[INIT] MAC Route: %s -> %s", parsedMAC, route.Upstream)
		}
	}
	hasMACRoutes = len(macRoutes) > 0
	log.Printf("[INIT] MAC routes: %d entries (ARP polling enabled: %v)", len(macRoutes), hasMACRoutes)

	// 2. Domain-based routes
	// DomainRouteConfig.UnmarshalYAML handles both compact ("lan": "upstream")
	// and expanded ("lan": { upstream: "...", bypass_local: true }) YAML forms.
	domainRoutes = make(map[string]domainRouteEntry, len(cfg.DomainRoutes))
	for domain, dr := range cfg.DomainRoutes {
		if dr.Upstream == "" {
			log.Printf("[WARN] domain_routes: entry %q has no upstream — skipped", domain)
			continue
		}
		clean := strings.ToLower(strings.TrimSuffix(domain, "."))
		domainRoutes[clean] = domainRouteEntry{
			upstream:    dr.Upstream,
			bypassLocal: dr.BypassLocal,
		}
		if dr.BypassLocal {
			log.Printf("[INIT] Domain Route: *.%s -> %s (bypass_local=true)", clean, dr.Upstream)
		} else {
			log.Printf("[INIT] Domain Route: *.%s -> %s", clean, dr.Upstream)
		}
	}
	hasDomainRoutes = len(domainRoutes) > 0

	// 3. DDR spoofing
	if cfg.Server.DDR.Enabled {
		ddrHostnames = make(map[string]bool)
		for _, h := range cfg.Server.DDR.Hostnames {
			ddrHostnames[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}
		for _, s := range cfg.Server.DDR.IPv4 {
			if ip := net.ParseIP(s); ip != nil {
				ddrIPv4 = append(ddrIPv4, ip)
			}
		}
		for _, s := range cfg.Server.DDR.IPv6 {
			if ip := net.ParseIP(s); ip != nil {
				ddrIPv6 = append(ddrIPv6, ip)
			}
		}
		for _, addr := range cfg.Server.ListenDoH {
			ddrDoHPort = extractPort(addr, 443)
		}
		for _, addr := range cfg.Server.ListenDoT {
			ddrDoTPort = extractPort(addr, 853)
		}
		log.Printf("[INIT] DDR enabled: %d hostname(s), %d IPv4, %d IPv6, DoH port %d, DoT port %d",
			len(ddrHostnames), len(ddrIPv4), len(ddrIPv6), ddrDoHPort, ddrDoTPort)
	} else {
		log.Println("[INIT] DDR disabled.")
	}

	// 4. Upstream groups
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
		for qtype := range obsoleteQtypes {
			if _, userSet := rtypePolicy[qtype]; !userSet {
				rtypePolicy[qtype] = dns.RcodeNotImplemented
				added++
			}
		}
		blockUnknownQtypes = true
		log.Printf("[INIT] Obsolete qtype blocking: %d types injected into rtype_policy (NOTIMP); unassigned type numbers also blocked at query time", added)
	} else {
		log.Println("[INIT] Obsolete qtype blocking: disabled (block_obsolete_qtypes: false)")
	}
	hasRtypePolicy = len(rtypePolicy) > 0

	buildPolicyRespCache()

	// 7. Route index table — assigns a compact uint8 index to each upstream group
	// name. Used as part of the cache key to keep per-route cache entries separate.
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
	// DomainRouteConfig used here — iterate over the parsed structs.
	for _, dr := range cfg.DomainRoutes {
		assignIdx(dr.Upstream)
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
		if cfg.Cache.NegativeTTL > 0 {
			log.Printf("[INIT] Cache negative TTL: %ds (NXDOMAIN/NODATA floor, independent of min_ttl)", cfg.Cache.NegativeTTL)
		}
		if cfg.Cache.StaleTTL > 0 {
			log.Printf("[INIT] Cache serve-stale window: %ds past expiry (RFC 8767)", cfg.Cache.StaleTTL)
		}
	}

	if hasMACRoutes {
		InitARP()
	} else {
		log.Println("[ARP] No MAC routes configured — ARP polling disabled.")
	}

	InitIdentity()
	InitThrottle()

	// 9. TLS
	needsTLS := len(cfg.Server.ListenDoT) > 0 || len(cfg.Server.ListenDoH) > 0 || len(cfg.Server.ListenDoQ) > 0
	var tlsConfig *tls.Config
	if needsTLS {
		tlsConfig = setupTLS()
	} else {
		log.Println("[TLS] No encrypted listeners configured — skipping TLS.")
	}

	// 10. Start listeners
	StartServers(tlsConfig)

	// 11. Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[BOOT] Received signal %v — shutting down", sig)
	Shutdown()
}

// extractPort parses a "host:port" listener address and returns the port as
// uint16. Returns defaultPort when parsing fails.
func extractPort(addr string, defaultPort uint16) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return defaultPort
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return defaultPort
	}
	return uint16(p)
}

// getHardenedTLSConfig returns a *tls.Config with a conservative cipher suite
// and curve list, suitable for both server listeners and upstream client dials.
// Called by upstream.go (4×) for DoT/DoH/DoH3/DoQ client transports, and by
// setupTLS() below as the base for the server listener config.
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

// setupTLS loads or auto-generates the TLS configuration for encrypted listeners.
//
// When tls_cert and tls_key are both set: loads the certificate from disk.
// When either is empty: generates an ephemeral self-signed P-256 certificate
// valid for 10 years. The ephemeral cert is regenerated on every restart.
//
// Builds on getHardenedTLSConfig() and adds the certificate + ALPN tokens.
// ALPN tokens cover all three encrypted protocols:
//
//	"doq"      — DNS over QUIC (RFC 9250)
//	"dot"      — DNS over TLS  (RFC 7858)
//	"h2"       — HTTP/2 for DoH
//	"http/1.1" — HTTP/1.1 for DoH fallback
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
		log.Println("[TLS] No cert/key configured — generating ephemeral self-signed certificate.")
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("[FATAL] Failed to generate self-signed cert: %v", err)
		}
	}

	base             := getHardenedTLSConfig()
	base.Certificates = []tls.Certificate{cert}
	base.NextProtos   = []string{"h2", "http/1.1", "dot", "doq"}
	return base
}

// generateSelfSignedCert creates an ephemeral P-256 ECDSA certificate valid
// for 10 years. Used when no tls_cert/tls_key are configured.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sdproxy"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM  := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

