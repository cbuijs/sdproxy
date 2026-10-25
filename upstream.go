/*
File:    upstream.go
Version: 2.48.0 (Split)
Last Updated: 25-Oct-2026 15:10 CET

Description:
  Core data structures, contexts, and lightweight hot-path utilities for 
  external DNS upstream providers.

Changes:
  2.48.0 - [SECURITY/FIX] Enforced `isTrustedProxy(clientAddr)` in `prepareForwardQuery`
           when `action == "pass"` so client-supplied `EDNS0_SUBNET` (`clientECS`)
           options from untrusted clients are stripped instead of forwarded upstream.
  2.47.0 - [SECURITY/FIX] Sanitized incoming `EDNS0_SUBNET` (`clientECS`) in
           `prepareForwardQuery` when `action == "pass"` by cloning and normalizing
           its address and netmask (`SourceScope: 0`).
  2.46.0 - [FEAT] Added `MaxSecureUpstreams` field to `UpstreamGroup`, populated 
           from `server.max_secure_upstreams` at init time.
  2.45.0 - [FEAT] Added `echDomain` to natively support distinct DDR discovery 
           domains mapped dynamically from `?echdomain=` upstream configurations.
  2.44.0 - [PERF] Eradicated Garbage Collection thrashing within `SweepUpstreamConns`. 
  2.43.0 - [SECURITY/FIX] Added a background idle connection sweeper to proactively
           prune expired TCP, DoT, and DoQ connections from the pool.
  2.42.0 - [SECURITY/FIX] Enforced a strict 15-second maximum global deadline 
           inside `newUpstreamCtx` natively.
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

var upstreamStagger time.Duration

var upstreamTimeout time.Duration

type streamConnEntry struct {
	conn   *dns.Conn
	idleAt time.Time
}

type doqConnEntry struct {
	conn     *quic.Conn
	dialAddr string
	idleAt   time.Time
}

type UpstreamGroup struct {
	Name               string
	Strategy           string
	Preference         string
	Mode               string
	IgnoreQnameLabels  bool
	ECSAction          string
	ECSV4Mask          int
	ECSV6Mask          int
	HasClientName      bool
	MaxSecureUpstreams int
	Servers            []*Upstream
	rrCount            atomic.Uint64
}

type Upstream struct {
	Proto                 string
	RawURL                string
	BootstrapIPs          []string
	hasClientNameTemplate bool

	ECSAction string
	ECSV4Mask int
	ECSV6Mask int

	useGET bool

	echDomain string

	ECHConfigList []byte

	dialHost  string
	dialAddrs []string

	udpClient *dns.Client

	streamConns map[string][]*streamConnEntry
	streamMu    sync.Mutex

	baseTLSConf      *tls.Config
	baseTLSConfNoECH *tls.Config

	h2Client      *http.Client
	h2ClientNoECH *http.Client

	h3Client      *http.Client
	h3ClientNoECH *http.Client

	h3Upgraded atomic.Bool
	h3Cooldown atomic.Int64
	h3Fails    atomic.Int32

	echCooldown atomic.Int64
	echFails    atomic.Int32

	doqConns     map[string]*doqConnEntry
	doqMu        sync.Mutex
	doqDialGroup singleflight.Group

	consFails atomic.Int32

	emaRTT atomic.Int64

	doqNo0RTT atomic.Bool
}

func (u *Upstream) recordSuccess() { u.consFails.Store(0) }
func (u *Upstream) recordFailure() { u.consFails.Add(1) }
func (u *Upstream) isHealthy() bool { return u.consFails.Load() < healthThreshold }

// ---------------------------------------------------------------------------
// newUpstreamCtx — per-exchange context factory
// ---------------------------------------------------------------------------

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

	// Only pass client-supplied ECS when the request originated from a trusted proxy
	// (or from backgroundRevalidate where clientECS was synthesized from the validated cache key).
	if action == "pass" && clientECS != nil && (!clientAddr.IsValid() || isTrustedProxy(clientAddr)) {
		if addr, ok := netip.AddrFromSlice(clientECS.Address); ok {
			unmapped := addr.Unmap()
			var family uint16 = 1
			maxBits := 32
			if unmapped.Is6() {
				family = 2
				maxBits = 128
			}
			bits := int(clientECS.SourceNetmask)
			if bits < 0 {
				bits = 0
			} else if bits > maxBits {
				bits = maxBits
			}
			if prefix, err := unmapped.Prefix(bits); err == nil {
				opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        family,
					SourceNetmask: uint8(bits),
					SourceScope:   0,
					Address:       prefix.Masked().Addr().AsSlice(),
				})
			}
		}
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

	msgLen := fwd.Len()
	padLen := (128 - ((msgLen + 4) % 128)) % 128
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
		Padding: make([]byte, padLen),
	})

	return fwd
}

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

	if len(up.ECHConfigList) > 0 {
		if cfg.Server.UseUpstreamECH == "try" && time.Now().UnixNano() < up.echCooldown.Load() {
		} else {
			proto += "+ECH"
		}
	}

	return proto + "://" + url
}

func parseHostPort(rawURL, proto string) (host, port string) {
	defaults := map[string]string{
		"udp": "53", "tcp": "53",
		"dot": "853", "doq": "853",
		"doh": "443", "doh3": "443",
	}

	clean := rawURL
	if idx := strings.Index(clean, "://"); idx >= 0 {
		clean = clean[idx+3:]
	}

	if idx := strings.IndexByte(clean, '/'); idx >= 0 {
		clean = clean[:idx]
	}

	h, p, err := net.SplitHostPort(clean)
	if err != nil {
		return clean, defaults[proto]
	}
	return h, p
}

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

func SweepUpstreamConns() {
	var connsToClose []*dns.Conn
	var doqToClose []*doqConnEntry

	now := time.Now()

	for _, group := range routeUpstreams {
		for _, u := range group.Servers {
			u.streamMu.Lock()
			for addr, conns := range u.streamConns {
				active := conns[:0]
				for _, entry := range conns {
					if now.Sub(entry.idleAt) > streamIdleMax {
						connsToClose = append(connsToClose, entry.conn)
					} else {
						active = append(active, entry)
					}
				}

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

	for _, c := range connsToClose {
		c.Close()
	}
	for _, entry := range doqToClose {
		entry.conn.CloseWithError(0, "idle sweeper")
	}
}
