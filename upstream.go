/*
File:    upstream.go
Version: 2.36.0 (Split)
Updated: 03-May-2026 21:46 CEST

Description:
  Core data structures, contexts, and lightweight hot-path utilities for 
  external DNS upstream providers. 
  
  Logic has been heavily modularized into:
    - upstream.go          (Core Data Structures & Contexts)
    - upstream_parser.go   (Initialization & Routing Setup)
    - upstream_exchange.go (Protocol Multiplexer)
    - upstream_ddr.go      (Security & SVCB Discovery)
    - upstream_net.go      (Low-level dials and stream bindings)
    - upstream_race.go     (Parallel execution strategies)

Changes:
  2.36.0 - [SECURITY/FIX] Implemented robust exponential backoff mechanics for 
           both DoH3 (QUIC) and Encrypted Client Hello (ECH) fallbacks natively. 
           `h3Fails` and `echFails` now gracefully escalate cooldowns (15s, 60s, 5m), 
           preventing immediate 5-minute lockouts when initial handshakes timeout.
  2.35.0 - [PERF/FIX] Remedied a critical multiplexing starvation flaw in DoT/TCP 
           exchanges. The `streamConns` map was converted from a solitary pointer 
           (`*streamConnEntry`) into a slice map (`[]*streamConnEntry`), empowering 
           true connection pooling natively. Up to 10 idle connections are now 
           retained per endpoint, averting extreme TLS re-handshake bottlenecks 
           under concurrent cache-miss bursts.
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/singleflight"
)

const (
	streamTimeout   = 5 * time.Second
	streamIdleMax   = 30 * time.Second
	doqIdleMax      = 25 * time.Second
	healthThreshold = int32(3)
)

// upstreamStagger is set once at startup from cfg.Server.UpstreamStaggerMs.
var upstreamStagger time.Duration

// upstreamTimeout is the per-exchange deadline. Set once at startup from
// cfg.Server.UpstreamTimeoutMs. 0 means no deadline (upstream's own TCP/TLS
// timeout applies). Used by newUpstreamCtx() on every upstream call.
var upstreamTimeout time.Duration

type streamConnEntry struct {
	conn   *dns.Conn
	idleAt time.Time
}

// doqConnEntry holds a pooled QUIC connection.
// dialAddr is the actual IP:port that was dialled — preserved for logging.
type doqConnEntry struct {
	conn     *quic.Conn // pointer to quic.Conn struct (quic-go v0.40+ removed interfaces)
	dialAddr string
	idleAt   time.Time
}

// UpstreamGroup is a container that oversees multiple upstream servers and enforces
// specific routing and load-balancing algorithms against them.
type UpstreamGroup struct {
	Name       string
	Strategy   string
	Preference string // e.g., "fastest", "ordered"
	Mode       string // e.g., "loose", "strict"
	Servers    []*Upstream
	rrCount    atomic.Uint64 // Used for round-robin strategy
}

// Upstream represents a single parsed and initialised upstream DNS target.
type Upstream struct {
	Proto                 string
	RawURL                string
	BootstrapIPs          []string // per-URL bootstrap IPs — always take precedence
	hasClientNameTemplate bool

	// useGET controls the HTTP method used for DoH/DoH3 outbound queries.
	// false (default) = POST; true = GET (RFC 8484 §4.1, cacheable, ?dns=<b64>).
	// Set once at ParseUpstream time via the +get URL modifier; never changes.
	useGET bool

	// ECHConfigList holds the Encrypted Client Hello configuration data natively.
	// Used by outbound dialers to encrypt SNI during the TLS connection handshake.
	ECHConfigList []byte

	// dialHost: static hostname used for TLS SNI — may contain {client-name},
	//           which is substituted with the real client name at query time.
	// dialAddrs: pre-computed IP:port dial targets, always ready after
	//            ParseUpstream returns.
	dialHost  string
	dialAddrs []string

	udpClient *dns.Client

	// [PERF] streamConns manages up to N idle TCP/DoT connections per target natively, 
	// eliminating costly TLS renegotiations during concurrent cache misses.
	streamConns map[string][]*streamConnEntry
	streamMu    sync.Mutex
	
	baseTLSConf      *tls.Config
	baseTLSConfNoECH *tls.Config // Fallback config isolated strictly without ECH bindings

	h2Client      *http.Client
	h2ClientNoECH *http.Client   // Fallback client isolated strictly without ECH bindings

	h3Client      *http.Client
	h3ClientNoECH *http.Client   // Fallback client isolated strictly without ECH bindings

	// Atomic flags coordinating the dynamic HTTP/3 upgrade sequence based on Alt-Svc headers
	h3Upgraded atomic.Bool
	h3Cooldown atomic.Int64
	h3Fails    atomic.Int32

	// echCooldown is latched for backoff when ECH fails, to prevent
	// continuously negotiating failing ECH payloads on strict networks.
	echCooldown atomic.Int64
	echFails    atomic.Int32

	doqConns     map[string]*doqConnEntry
	doqMu        sync.Mutex
	doqDialGroup singleflight.Group

	// consFails counts consecutive failures. Reset to 0 on any success.
	consFails atomic.Int32

	// emaRTT Tracks the Exponential Moving Average of response latency in Nanoseconds.
	// Exploited natively by the "fastest" strategy constraint to favor top performers.
	emaRTT atomic.Int64

	// doqNo0RTT is latched to true on DOQ_PROTOCOL_ERROR (RFC 9250 §10.5).
	// All subsequent dials use Allow0RTT: false. Never reset.
	doqNo0RTT atomic.Bool
}

func (u *Upstream) recordSuccess() { u.consFails.Store(0) }
func (u *Upstream) recordFailure() { u.consFails.Add(1) }
func (u *Upstream) isHealthy() bool { return u.consFails.Load() < healthThreshold }

// ---------------------------------------------------------------------------
// newUpstreamCtx — per-exchange context factory
// ---------------------------------------------------------------------------

// newUpstreamCtx returns a context and cancel function for one upstream exchange.
//
//   - upstreamTimeout > 0 → context.WithTimeout: bounds goroutine lifetime on
//     slow or unreachable upstreams, preventing goroutine pile-up under load.
//   - upstreamTimeout == 0 → context.WithCancel: no deadline; the upstream's
//     own TCP/TLS/QUIC timeout governs how long we wait.
//
// Callers must always call the returned cancel (typically via defer).
func newUpstreamCtx() (context.Context, context.CancelFunc) {
	if upstreamTimeout > 0 {
		return context.WithTimeout(context.Background(), upstreamTimeout)
	}
	return context.WithCancel(context.Background())
}

// ---------------------------------------------------------------------------
// Common Lightweight Utilities
// ---------------------------------------------------------------------------

// prepareForwardQuery builds a minimal, sanitised DNS query for upstream forwarding.
func prepareForwardQuery(req *dns.Msg, encrypted bool) *dns.Msg {
	fwd := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: req.RecursionDesired,
			CheckingDisabled: req.CheckingDisabled,
		},
	}
	fwd.Question = make([]dns.Question, len(req.Question))
	copy(fwd.Question, req.Question)

	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
	}
	opt.SetUDPSize(4096)
	
	if clientOpt := req.IsEdns0(); clientOpt != nil {
		if clientOpt.Do() {
			opt.SetDo()
		}
	}
	fwd.Extra = []dns.RR{opt}

	if !encrypted {
		return fwd
	}

	msgLen    := fwd.Len()
	remainder := (msgLen + 4) % 128
	if remainder != 0 {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
			Padding: make([]byte, 128-remainder),
		})
	}
	return fwd
}

// formatUpstreamLog generates the "URL (IP)" telemetry string for the logs.
// Protocol modifiers like "+ECH" are explicitly prepended by the caller.
func formatUpstreamLog(proto, displayURL, dialAddr string) string {
	displayURL = strings.TrimPrefix(displayURL, "https://")
	if dialAddr == "" {
		return fmt.Sprintf("%s://%s", proto, displayURL)
	}
	if displayURL == dialAddr {
		return fmt.Sprintf("%s://%s", proto, displayURL)
	}
	if displayURL+":53" == dialAddr || displayURL+":853" == dialAddr || displayURL+":443" == dialAddr {
		return fmt.Sprintf("%s://%s", proto, dialAddr)
	}
	return fmt.Sprintf("%s://%s (%s)", proto, displayURL, dialAddr)
}

// getUpstreamURL formats the upstream's URL for telemetry, natively reflecting dynamic protocol upgrades.
func getUpstreamURL(up *Upstream, clientName string) string {
	url := up.RawURL
	if up.hasClientNameTemplate && clientName != "" {
		url = strings.ReplaceAll(url, "{client-name}", clientName)
	}
	if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}
	proto := up.Proto
	if proto == "doh" && cfg.Server.UpgradeDoH3 && up.h3Upgraded.Load() {
		proto = "doh3"
	}
	
	// Natively evaluate ECH deployment and active cooldown fallback statuses
	if len(up.ECHConfigList) > 0 {
		if cfg.Server.UseUpstreamECH == "try" && time.Now().UnixNano() < up.echCooldown.Load() {
			// ECH is on fallback cooldown; do not append marker
		} else {
			proto += "+ECH"
		}
	}
	
	return proto + "://" + url
}

// parseHostPort extracts host and port from a raw URL string.
func parseHostPort(rawURL, proto string) (host, port string) {
	defaults := map[string]string{
		"udp": "53", "tcp": "53",
		"dot": "853", "doq": "853",
		"doh": "443", "doh3": "443",
	}
	
	// Strip protocol scheme if present to prevent splitting on its colon natively
	clean := rawURL
	if idx := strings.Index(clean, "://"); idx >= 0 {
		clean = clean[idx+3:]
	}
	
	// Strip trailing HTTP paths to isolate the host:port boundary
	if idx := strings.IndexByte(clean, '/'); idx >= 0 {
		clean = clean[:idx]
	}

	h, p, err := net.SplitHostPort(clean)
	if err != nil {
		// Unbracketed IPv6 addresses or hostnames without ports will safely fall here
		return clean, defaults[proto]
	}
	return h, p
}

