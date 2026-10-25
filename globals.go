/*
File:    globals.go
Version: 1.40.0
Last Updated: 25-Oct-2026 15:10 CET

Description:
  All package-level variables and feature-presence flags for sdproxy.

Changes:
  1.40.0 - [SECURITY/FEAT] Added `trustedProxies` and `isTrustedProxy(addr)` helper
           to enforce a strict security boundary around client-supplied EDNS0 Option
           65001 (`mac:`) and EDNS0 Client Subnet (`ecs:`) assertions.
  1.39.1 - [FIX] Wrapped atomic pointer state in `domainPolicyState` with helper
           methods so `globals.go`, `init_policy.go`, `policy.go`, and
           `process_filters.go` never require generic square-bracket syntax.
  1.39.0 - [FEAT] Added regex support structures (`spoofRegexRecord`, `dpRegexEntry`,
           `DpRegexEntryGob`) and runtime tables (`globalRRRegexes`, `groupRRRegexes`,
           `domainPolicyRegexSnap`) for `rrs:` and `domain_policy:`.
  1.38.0 - [FEAT] Added `ednsMACRoutes`, `ednsMACWildRoutes`, `hasEDNSMACRoutes`,
           and `hasEDNSMACWildRoutes` to support EDNS0 Option 65001 (`mac:`) exact
           and glob matching in `routes:`.
  1.37.0 - [FEAT] Added `ecsIPRoutes`, `ecsCIDRRoutes`, `hasECSIPRoutes`, and
           `hasECSCIDRRoutes` to support `ecs:` IP and CIDR matching in `routes:`.
  1.36.0 - [FEAT] Added `hasSubdomainLimit` toggle natively to dynamically orchestrate 
           subdomain exfiltration evaluations inside the core pipeline.
  1.35.0 - [BUG/FIX] Repaired uninitialized `untriggerLogTimers` assignment natively.
*/

package main

import (
	"net"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// History Helpers
// ---------------------------------------------------------------------------

func historyDir() string {
	return cfg.WebUI.HistoryDir
}

func retentionHours() int {
	if cfg.WebUI.HistoryRetentionHours > 0 {
		return cfg.WebUI.HistoryRetentionHours
	}
	return 24
}

// ---------------------------------------------------------------------------
// Global Block Action Config
// ---------------------------------------------------------------------------

const (
	BlockActionNull = iota
	BlockActionDrop
	BlockActionIP
	BlockActionLog
	BlockActionRcode
)

var (
	globalBlockAction int
	globalBlockRcode  int
	globalBlockIPv4   []net.IP
	globalBlockIPv6   []net.IP
)

// ---------------------------------------------------------------------------
// Routing tables (populated at startup by main())
// ---------------------------------------------------------------------------

type cidrRouteEntry struct {
	net   netip.Prefix
	route ParsedRoute
}

type macWildRoute struct {
	pattern string
	route   ParsedRoute
}

type compoundRouteMap struct {
	keys  []string
	route ParsedRoute
}

var (
	macRoutes         map[string]ParsedRoute
	macWildRoutes     []macWildRoute
	ednsMACRoutes     map[string]ParsedRoute
	ednsMACWildRoutes []macWildRoute
	ipRoutes          map[string]ParsedRoute
	cidrRoutes        []cidrRouteEntry
	ecsIPRoutes       map[string]ParsedRoute
	ecsCIDRRoutes     []cidrRouteEntry
	asnRoutes         map[string]ParsedRoute
	countryRoutes     map[string]ParsedRoute

	clientNameRoutes map[string]ParsedRoute
	sniRoutes        map[string]ParsedRoute
	pathRoutes       map[string]ParsedRoute
	portRoutes       map[string]ParsedRoute

	compoundRouteMappings []compoundRouteMap

	domainRoutes map[string]domainRouteEntry

	routeUpstreams map[string]*UpstreamGroup
)

// ---------------------------------------------------------------------------
// Spoofed Records (RRs)
// ---------------------------------------------------------------------------

type spoofRecord struct {
	IPs   []netip.Addr
	CNAME string
}

type spoofRegexRecord struct {
	raw string
	re  *regexp.Regexp
	rec spoofRecord
}

var (
	globalRRs       map[string]spoofRecord
	globalRRRegexes []spoofRegexRecord
	groupRRs        map[string]map[string]spoofRecord
	groupRRRegexes  map[string][]spoofRegexRecord
	hasRRs          bool
)

// ---------------------------------------------------------------------------
// DDR — Discovery of Designated Resolvers (RFC 9462)
// ---------------------------------------------------------------------------

var (
	ddrHostnames     map[string]bool
	ddrHostnamesList []string
	ddrIPv4          []net.IP
	ddrIPv6          []net.IP
	ddrDoHPort       uint16 = 443
	ddrDoTPort       uint16 = 853
	ddrDoQPort       uint16 = 853
	ddrECHConfig     []byte
)

// ---------------------------------------------------------------------------
// TLS Runtime Parameters
// ---------------------------------------------------------------------------

var (
	tlsAuthorizedNames []string
)

// ---------------------------------------------------------------------------
// Policy maps (populated at startup/polling)
// ---------------------------------------------------------------------------

type dpCidrEntry struct {
	prefix netip.Prefix
	action int
}

type dpRegexEntry struct {
	raw    string
	re     *regexp.Regexp
	action int
}

type dpMapHolder struct{ v atomic.Value }

func (h *dpMapHolder) Load() *map[string]int {
	if x := h.v.Load(); x != nil {
		return x.(*map[string]int)
	}
	return nil
}

func (h *dpMapHolder) Store(p *map[string]int) { h.v.Store(p) }

type dpCIDRHolder struct{ v atomic.Value }

func (h *dpCIDRHolder) Load() *[]dpCidrEntry {
	if x := h.v.Load(); x != nil {
		return x.(*[]dpCidrEntry)
	}
	return nil
}

func (h *dpCIDRHolder) Store(p *[]dpCidrEntry) { h.v.Store(p) }

type dpRegexHolder struct{ v atomic.Value }

func (h *dpRegexHolder) Load() *[]dpRegexEntry {
	if x := h.v.Load(); x != nil {
		return x.(*[]dpRegexEntry)
	}
	return nil
}

func (h *dpRegexHolder) Store(p *[]dpRegexEntry) { h.v.Store(p) }

var (
	rtypePolicy           map[uint16]int
	domainPolicySnap      dpMapHolder
	domainPolicyCIDRSnap  dpCIDRHolder
	domainPolicyRegexSnap dpRegexHolder
)

// ---------------------------------------------------------------------------
// Policy Actions (Custom Internal RCODEs)
// ---------------------------------------------------------------------------

const (
	PolicyActionDrop  = -1
	PolicyActionBlock = -2
)

// ---------------------------------------------------------------------------
// Route index table
// ---------------------------------------------------------------------------

var (
	routeIdxByName  map[string]uint16
	routeIdxLocal   uint16 = 0
	routeIdxDefault uint16
)

// ---------------------------------------------------------------------------
// Security ACLs & Trusted Forwarder Proxies
// ---------------------------------------------------------------------------

var (
	dnsACLAllow []netip.Prefix
	dnsACLDeny  []netip.Prefix
	hasDNSACL   bool

	webUIACLAllow []netip.Prefix
	webUIACLDeny  []netip.Prefix
	hasWebUIACL   bool

	trustedProxies []netip.Prefix
)

// isTrustedProxy reports whether addr is an authorized local forwarder permitted
// to supply client EDNS0 Option 65001 (MAC) and EDNS0 Client Subnet (ECS) assertions.
// When `server.trusted_proxies` is not explicitly configured, only loopback
// addresses (127.0.0.0/8, ::1/128) are trusted.
func isTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if len(trustedProxies) == 0 {
		return addr.IsLoopback()
	}
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Feature-presence flags
// ---------------------------------------------------------------------------

var (
	hasMACRoutes         bool
	hasMACWildRoutes     bool
	hasEDNSMACRoutes     bool
	hasEDNSMACWildRoutes bool
	hasIPRoutes          bool
	hasCIDRRoutes        bool
	hasECSIPRoutes       bool
	hasECSCIDRRoutes     bool
	hasASNRoutes         bool
	hasCountryRoutes     bool
	hasClientNameRoutes  bool
	hasSNIRoutes         bool
	hasPathRoutes        bool
	hasPortRoutes        bool

	hasDomainRoutes    bool
	hasRtypePolicy     bool
	hasDomainPolicy    atomic.Bool
	blockUnknownQtypes bool

	hasRateLimit               bool
	hasRebindingProtection     bool
	searchDomainLeakPrevention bool
	hasDGA                     bool
	hasExfiltration            bool
	hasSubdomainLimit          bool

	forceRefreshStartup     bool
	catMapInitialized       atomic.Bool
	autoEnabledFlattenCNAME bool
)

// ---------------------------------------------------------------------------
// Hot-path query-level settings
// ---------------------------------------------------------------------------

var logQueries    bool
var logASNDetails bool
var logStrategy   bool

var logParental bool
var logIdentity bool
var logCaching  bool
var logDDR      bool
var logTLS      bool
var logSystem   bool
var logWebUI    bool
var logRouting  bool

var syntheticTTL uint32
var ipVersionSupport string

// ---------------------------------------------------------------------------
// Obsolete/withdrawn DNS RR types
// ---------------------------------------------------------------------------

var obsoleteQtypes = map[uint16]string{
	3: "MD", 4: "MF", 7: "MB", 8: "MG", 9: "MR", 10: "NULL",
	11: "WKS", 14: "MINFO", 19: "X25", 20: "ISDN", 21: "RT",
	22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
	27: "GPOS", 30: "NXT", 31: "EID", 32: "NIMLOC", 34: "ATMA",
	38: "A6", 40: "SINK", 99: "SPF", 100: "UINFO", 101: "UID",
	102: "GID", 103: "UNSPEC", 253: "MAILB", 254: "MAILA",
}

// ---------------------------------------------------------------------------
// Bootstrap DNS servers
// ---------------------------------------------------------------------------

var globalBootstrapServers []*Upstream

// ---------------------------------------------------------------------------
// Parental UNTRIGGER window expiry timers
// ---------------------------------------------------------------------------

var untriggerLogTimers sync.Map

// ---------------------------------------------------------------------------
// Buffer pools
// ---------------------------------------------------------------------------

var (
	smallBufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}
	largeBufPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)
