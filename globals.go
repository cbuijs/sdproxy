/*
File:    globals.go
Version: 1.25.0
Updated: 07-May-2026 09:20 CEST

Description:
  All package-level variables and feature-presence flags for sdproxy.

Changes:
  1.25.0 - [FEAT] Introduced `spoofRecord` structs and mapping variables globally 
           to natively govern explicit `rrs:` (A/AAAA/CNAME) policy overrides.
  1.24.0 - [FEAT] Added global storage arrays for `tlsAuthorizedNames` and 
           `ddrHostnamesList` to organically bind TLS parameters across the 
           initialization boundaries into the DDR execution pipeline.
*/

package main

import (
	"net"
	"net/netip"
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
	return 24 // default
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

var (
	// Address-based routing
	macRoutes     map[string]ParsedRoute
	macWildRoutes []macWildRoute
	ipRoutes      map[string]ParsedRoute
	cidrRoutes    []cidrRouteEntry
	asnRoutes     map[string]ParsedRoute

	// String-based routing maps
	clientNameRoutes map[string]ParsedRoute
	sniRoutes        map[string]ParsedRoute
	pathRoutes       map[string]ParsedRoute

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

var (
	globalRRs map[string]spoofRecord
	groupRRs  map[string]map[string]spoofRecord
	hasRRs    bool
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
	// Populated during boot initialization directly from loaded certificates
	tlsAuthorizedNames []string
)

// ---------------------------------------------------------------------------
// Policy maps (populated at startup/polling)
// ---------------------------------------------------------------------------

type dpCidrEntry struct {
	prefix netip.Prefix
	action int
}

var (
	rtypePolicy          map[uint16]int
	domainPolicySnap     atomic.Pointer[map[string]int]
	domainPolicyCIDRSnap atomic.Pointer[[]dpCidrEntry]
)

// ---------------------------------------------------------------------------
// Policy Actions (Custom Internal RCODEs)
// ---------------------------------------------------------------------------

const (
	PolicyActionDrop = -1
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
// Security ACLs (Access Control Lists)
// ---------------------------------------------------------------------------

var (
	dnsACLAllow []netip.Prefix
	dnsACLDeny  []netip.Prefix
	hasDNSACL   bool

	webUIACLAllow []netip.Prefix
	webUIACLDeny  []netip.Prefix
	hasWebUIACL   bool
)

// ---------------------------------------------------------------------------
// Feature-presence flags
// ---------------------------------------------------------------------------

var (
	hasClientRoutes bool

	hasMACRoutes        bool
	hasMACWildRoutes    bool
	hasIPRoutes         bool
	hasCIDRRoutes       bool
	hasASNRoutes        bool
	hasClientNameRoutes bool
	hasSNIRoutes        bool
	hasPathRoutes       bool

	hasDomainRoutes       bool
	hasRtypePolicy        bool
	hasDomainPolicy       atomic.Bool
	hasClientNameUpstream bool
	blockUnknownQtypes    bool

	hasRateLimit           bool
	hasRebindingProtection bool
	hasDGA                 bool
	hasExfiltration        bool
	
	forceRefreshStartup    bool
)

// ---------------------------------------------------------------------------
// Hot-path query-level settings
// ---------------------------------------------------------------------------

var logQueries bool
var logASNDetails bool
var logStrategy bool
var syntheticTTL uint32
var ipVersionSupport string // "ipv4", "ipv6", or "both"

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
// Buffer pools
// ---------------------------------------------------------------------------

var (
	smallBufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}
	largeBufPool = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

