/*
File:    upstream.go
Version: 2.44.0 (Split)
Updated: 06-Jun-2026 14:47 CEST

Description:
  Core data structures, contexts, and lightweight hot-path utilities for 
  external DNS upstream providers.

Changes:
  2.44.0 - [PERF] Eradicated Garbage Collection thrashing within `SweepUpstreamConns`. 
           Sweeper iterations now utilize zero-allocation slice filtering (`active := conns[:0]`) 
           to cleanly purge expired TCP/DoT connections organically without dynamically 
           allocating new array arrays natively.
  2.43.0 - [SECURITY/FIX] Added a background idle connection sweeper to proactively
           prune expired TCP, DoT, and DoQ connections from the pool, preventing
           fatal file descriptor leaks on public servers.
  2.42.0 - [SECURITY/FIX] Enforced a strict 15-second maximum global deadline 
           inside `newUpstreamCtx` natively. Definitively neutralizes SingleFlight 
           goroutine leaks and upstream Slow-Read attacks on DoH/DoH3 transports 
           when administrators leave the `upstream_timeout_ms` unbound (0).
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
	Name              string
	Strategy          string
	Preference        string // e.g., "fastest", "ordered"
	Mode              string // e.g., "loose", "strict"
	IgnoreQnameLabels bool
	ECSAction         string
	ECSV4Mask         int
	ECSV6Mask         int
	HasClientName     bool   // [SECURITY/FIX] Flags if any upstream utilizes {client-name} dynamically
	Servers           []*Upstream
	rrCount           atomic.Uint64 // Used for round-robin strategy
}

// Upstream represents a single parsed and initialised upstream DNS target.
type Upstream struct {
	Proto                 string
	RawURL                string
	BootstrapIPs          []string // per-URL bootstrap IPs — always take precedence
	hasClientNameTemplate bool

	// ECS Parameters
	ECSAction string
	ECSV4Mask int
	ECSV6Mask int

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
//   - upstreamTimeout <= 0 → context.WithTimeout: enforces a strict 15-second 
//     maximum deadline natively. Protects against upstream Slow-Read attacks 
//     and SingleFlight Goroutine leaks when no global timeout is defined.
//
// Callers must always call the returned cancel (typically via defer).
func newUpstreamCtx() (context.Context, context.CancelFunc) {
	timeout := upstreamTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

// ---------------------------------------------------------------------------
// Common Lightweight Utilities
// ---------------------------------------------------------------------------

// prepareForwardQuery builds a minimal, sanitised DNS query for upstream forwarding.
// Dynamically intercepts EDNS0 Client Subnet (ECS) structures based on localized 
// configurations to mask, strip, or inject client telemetry privately natively.
func prepareForwardQuery(req *dns.Msg, encrypted bool, u *Upstream, clientAddr netip.Addr) *dns.Msg {
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
	
	var clientECS *dns.EDNS0_SUBNET

	if clientOpt := req.IsEdns0(); clientOpt != nil {
		if clientOpt.Do() {
			opt.SetDo()
		}
		// Isolate existing ECS components from the client to safely evaluate them later
		for _, o := range clientOpt.Option {
			if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
				clientECS = ecs
				break
			}
		}
	}

	action := "remove"
	if u != nil && u.ECSAction != "" {
		action = u.ECSAction
	}

	// Natively resolve configured ECS behaviors while preserving EDNS0 capacities natively
	if action == "pass" && clientECS != nil {
		opt.Option = append(opt.Option, clientECS)
	} else if action == "add" && clientAddr.IsValid() {
		var family uint16
		var mask uint8
		var ip net.IP

		if clientAddr.Is4() {
			family = 1
			mask = uint8(u.ECSV4Mask)
			if mask > 32 {
				mask = 32
			}
			prefix, _ := clientAddr.Prefix(int(mask))
			ip = prefix.Masked().Addr().AsSlice()
		} else if clientAddr.Is6() {
			family = 2
			mask = uint8(u.ECSV6Mask)
			if mask > 128 {
				mask = 128
			}
			prefix, _ := clientAddr.Prefix(int(mask))
			ip = prefix.Masked().Addr().AsSlice()
		}

		if ip != nil {
			ecs := &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        family,
				SourceNetmask: mask,
				SourceScope:   0,
				Address:       ip,
			}
			opt.Option = append(opt.Option, ecs)
		}
	}

	fwd.Extra = []dns.RR{opt}

	if !encrypted {
		return fwd
	}

	// [SECURITY/FIX] Unconditionally append EDNS0 Padding Options natively.
	// Dynamically calculate padding block size with precise modulo arithmetic.
	// Using (128 - ((msgLen + 4) % 128)) % 128 natively ensures we don't allocate 
	// 128 bytes of blank padding unnecessarily if the packet already perfectly aligns 
	// to the block boundary, neutralizing packet-length fingerprinting vectors completely.
	msgLen := fwd.Len()
	padLen := (128 - ((msgLen + 4) % 128)) % 128
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
		Padding: make([]byte, padLen),
	})
	
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

// InitUpstreamSweeper starts the background goroutine that periodically
// sweeps expired idle connections across all upstreams.
func InitUpstreamSweeper() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				SweepUpstreamConns()
			case <-shutdownCh:
				return
			}
		}
	}()
}

// SweepUpstreamConns scans all active upstreams in all route groups,
// evicting and closing any idle TCP, DoT, or DoQ connections whose
// idle lifetime has exceeded their respective limits.
func SweepUpstreamConns() {
	var connsToClose []*dns.Conn
	var doqToClose []*doqConnEntry

	now := time.Now()

	// Capture all active upstream groups under read lock if we had one,
	// but routeUpstreams is read-only after initialization, so we can
	// safely iterate it without locks.
	for _, group := range routeUpstreams {
		for _, u := range group.Servers {
			// 1. Sweep TCP/DoT Stream Conns
			u.streamMu.Lock()
			for addr, conns := range u.streamConns {
				// [PERF/OPTIMIZATION] Zero-allocation slice filtering.
				// Prevents generating massive GC spikes across 30-second sweep intervals natively.
				active := conns[:0]
				for _, entry := range conns {
					if now.Sub(entry.idleAt) > streamIdleMax {
						connsToClose = append(connsToClose, entry.conn)
					} else {
						active = append(active, entry)
					}
				}
				
				// Nullify trailing pointers to release memory back to GC
				for i := len(active); i < len(conns); i++ {
					conns[i] = nil
				}
				
				if len(active) == 0 {
					delete(u.streamConns, addr)
				} else {
					u.streamConns[addr] = active
				}
			}
			u.streamMu.Unlock()

			// 2. Sweep DoQ Conns
			u.doqMu.Lock()
			for key, entry := range u.doqConns {
				if now.Sub(entry.idleAt) > doqIdleMax {
					doqToClose = append(doqToClose, entry)
					delete(u.doqConns, key)
				}
			}
			u.doqMu.Unlock()
		}
	}

	// Close evicted connections outside of any lock to prevent blocking the DNS pipeline
	for _, c := range connsToClose {
		c.Close()
	}
	for _, entry := range doqToClose {
		entry.conn.CloseWithError(0, "idle sweeper")
	}
}

