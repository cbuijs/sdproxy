/*
File:    upstream.go
Version: 2.56.0 (Split)
Last Updated: 10-Nov-2026 11:45 CET

Description:
  Core data structures, contexts, and lightweight hot-path utilities for 
  external DNS upstream providers.

Changes:
  2.56.0 - [FEAT] Added `DoH3FallbackThreshold` (`doh3_fallback_threshold`),
           `dohAvailable`, and `dohSticky` fields to `Upstream` / `UpstreamGroup`
           and updated `getUpstreamURL` to reflect sticky downgrade to `doh`
           when an upgraded `doh://` or explicit `doh3://` upstream latches onto
           standard DoH.
  2.55.0 - [SECURITY/FIX] Enforced RFC 7873 §5.2.2 length and hex-character
           validation on received `EDNS0_COOKIE` payloads in `validateUpstreamResponse`,
           rejecting malformed or odd-length cookie options.
  2.54.0 - [SECURITY/FIX] Closed idle HTTP/3 QUIC sessions (`CloseIdleConnections`)
           on `h3Client` and `h3ClientNoECH` in `SweepUpstreamConns` so stale
           QUIC connections after WAN/NAT rebindings are periodically reaped.
  2.53.0 - [SECURITY/FIX] Set `fwd.Id = 0` in `prepareForwardQuery` for DoQ
           (RFC 9250 §4.2.1 mandatory `ID=0`), DoH, and DoH3 (RFC 8484 §4.1
           recommended `ID=0`) upstreams, and tightened RFC 7873 Server Cookie
           validation in `validateUpstreamResponse`.
  2.52.0 - [SECURITY/FIX] Added `stripEDNS0Cookie` helper so UDP `TC=1` -> TCP
           fallback queries strip UDP-only `EDNS0_COOKIE` options before
           transmitting over TCP.
  2.51.0 - [SECURITY/FEAT] Implemented Transport & Protocol Cache-Poisoning Defenses.
  2.50.0 - [SECURITY/FIX] Set `SourceScope: 255` internal pre-validated marker in
           `injectPassedECS` and used `CloseIdleConnections()` in `SweepUpstreamConns`.
  2.49.0 - [SECURITY/FIX] Removed the `!clientAddr.IsValid()` exemption in
           `prepareForwardQuery` when `action == "pass"`.
  2.48.0 - [SECURITY/FIX] Enforced `isTrustedProxy(clientAddr)` in `prepareForwardQuery`
           when `action == "pass"`.
  2.47.0 - [SECURITY/FIX] Sanitized incoming `EDNS0_SUBNET` (`clientECS`) in
           `prepareForwardQuery` when `action == "pass"`.
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
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
	Name                  string
	Strategy              string
	Preference            string
	Mode                  string
	IgnoreQnameLabels     bool
	DNS0x20               bool
	DNSCookies            bool
	RequireDNSSECAD       bool
	DoH3FallbackThreshold int
	ECSAction             string
	ECSV4Mask             int
	ECSV6Mask             int
	HasClientName         bool
	MaxSecureUpstreams    int
	Servers               []*Upstream
	rrCount               atomic.Uint64
}

type Upstream struct {
	Proto                 string
	RawURL                string
	BootstrapIPs          []string
	hasClientNameTemplate bool

	DNS0x20               bool
	DNSCookies            bool
	RequireDNSSECAD       bool
	DoH3FallbackThreshold int32

	clientCookieHex string
	serverCookieHex atomic.Value

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

	h3Upgraded   atomic.Bool
	dohAvailable atomic.Bool
	dohSticky    atomic.Bool
	h3Cooldown   atomic.Int64
	h3Fails      atomic.Int32

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
// 0x20 Bit-Case Randomization & Transport Response Verification
// ---------------------------------------------------------------------------

func randomizeCase0x20(s string) string {
	hasAlpha := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
			break
		}
	}
	if !hasAlpha {
		return s
	}

	b := []byte(s)
	r := rand.Uint64()
	bitIdx := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			if bitIdx == 64 {
				r = rand.Uint64()
				bitIdx = 0
			}
			if (r>>bitIdx)&1 == 1 {
				b[i] = c &^ 0x20 // Uppercase
			} else {
				b[i] = c | 0x20 // Lowercase
			}
			bitIdx++
		}
	}
	return string(b)
}

func hasAnyRRSIG(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	return false
}

func stripEDNS0Cookie(msg *dns.Msg) {
	if msg == nil {
		return
	}
	opt := msg.IsEdns0()
	if opt == nil || len(opt.Option) == 0 {
		return
	}
	clean := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isCookie := o.(*dns.EDNS0_COOKIE); !isCookie {
			clean = append(clean, o)
		}
	}
	opt.Option = clean
}

func isValidHexString(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if parseHexNibble(s[i]) > 15 {
			return false
		}
	}
	return true
}

// validateUpstreamResponse enforces strict RFC protocol, Question, 0x20,
// DNS Cookie, and DNSSEC AD/RRSIG invariants on every upstream reply before
// it is accepted by the transport layer.
func (u *Upstream) validateUpstreamResponse(fwd, resp *dns.Msg, checkID bool, check0x20 bool, checkCookie bool) error {
	if resp == nil {
		return fmt.Errorf("nil upstream response")
	}
	if !resp.Response {
		return fmt.Errorf("upstream packet has QR=0 (query flag instead of response)")
	}
	if resp.Opcode != fwd.Opcode {
		return fmt.Errorf("upstream opcode mismatch: got %d, want %d", resp.Opcode, fwd.Opcode)
	}
	if checkID && resp.Id != fwd.Id {
		return fmt.Errorf("upstream txid mismatch: got %d, want %d", resp.Id, fwd.Id)
	}
	if len(fwd.Question) == 1 {
		if len(resp.Question) != 1 {
			return fmt.Errorf("upstream question count mismatch: got %d, want 1", len(resp.Question))
		}
		fq := fwd.Question[0]
		rq := resp.Question[0]
		if rq.Qtype != fq.Qtype || rq.Qclass != fq.Qclass {
			return fmt.Errorf("upstream qtype/qclass mismatch: got %d/%d, want %d/%d", rq.Qtype, rq.Qclass, fq.Qtype, fq.Qclass)
		}
		if check0x20 {
			if rq.Name != fq.Name {
				return fmt.Errorf("upstream 0x20 qname case mismatch: got %q, want %q", rq.Name, fq.Name)
			}
		} else if !strings.EqualFold(rq.Name, fq.Name) {
			return fmt.Errorf("upstream qname mismatch: got %q, want %q", rq.Name, fq.Name)
		}
	}

	if checkCookie && u != nil && u.DNSCookies && u.clientCookieHex != "" {
		var gotCookie string
		if opt := resp.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if c, ok := o.(*dns.EDNS0_COOKIE); ok {
					gotCookie = strings.ToLower(c.Cookie)
					break
				}
			}
		}

		prevSrv, _ := u.serverCookieHex.Load().(string)
		if gotCookie != "" {
			if !strings.HasPrefix(gotCookie, u.clientCookieHex) {
				return fmt.Errorf("upstream DNS cookie client-prefix mismatch")
			}
			// RFC 7873 §5.2.2: Cookie option must be either 8 bytes (16 hex chars,
			// Client Cookie only) or 16..40 bytes (32..80 even hex chars, Client + Server Cookie).
			if (len(gotCookie) != 16 && (len(gotCookie) < 32 || len(gotCookie) > 80)) || !isValidHexString(gotCookie) {
				return fmt.Errorf("upstream DNS cookie malformed length or hex (%d chars)", len(gotCookie))
			}
			if len(gotCookie) >= 32 {
				u.serverCookieHex.Store(gotCookie)
			}
		} else if prevSrv != "" && !resp.Truncated {
			// Upstream previously proved RFC 7873 Cookie support; missing cookie on
			// a non-truncated UDP packet indicates an off-path spoofed injection.
			return fmt.Errorf("upstream omitted expected RFC 7873 DNS cookie")
		}
	}

	if u != nil && u.RequireDNSSECAD && !fwd.CheckingDisabled && !resp.Truncated {
		if resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError {
			if !resp.AuthenticatedData && !hasAnyRRSIG(resp) {
				return fmt.Errorf("upstream response failed require_dnssec_ad check (AD=0 and no RRSIG present)")
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Common Lightweight Utilities
// ---------------------------------------------------------------------------

func injectPassedECS(req *dns.Msg, ecsAddr netip.Addr, ecsPrefix netip.Prefix) {
	if req == nil || !ecsAddr.IsValid() {
		return
	}
	unmapped := ecsAddr.Unmap()
	var family uint16 = 1
	bits := 32
	if unmapped.Is6() {
		family = 2
		bits = 128
	}
	if ecsPrefix.IsValid() && ecsPrefix.Addr().Is4() == unmapped.Is4() {
		bits = ecsPrefix.Bits()
	}
	p, err := unmapped.Prefix(bits)
	if err != nil {
		return
	}
	opt := req.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		req.Extra = append(req.Extra, opt)
	}
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(bits),
		SourceScope:   255, // Internal pre-validated marker (reset to 0 in prepareForwardQuery)
		Address:       p.Masked().Addr().AsSlice(),
	})
}

func prepareForwardQuery(req *dns.Msg, encrypted bool, u *Upstream, clientAddr netip.Addr) *dns.Msg {
	// RFC 9250 §4.2.1 (DoQ) mandates ID=0; RFC 8484 §4.1 (DoH) recommends ID=0.
	var txid uint16
	if u == nil || u.Proto == "udp" || u.Proto == "tcp" || u.Proto == "dot" {
		txid = dns.Id()
	}

	fwd := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               txid,
			RecursionDesired: req.RecursionDesired,
			CheckingDisabled: req.CheckingDisabled,
		},
	}
	fwd.Question = make([]dns.Question, len(req.Question))
	copy(fwd.Question, req.Question)

	if !encrypted && u != nil && u.DNS0x20 && len(fwd.Question) > 0 {
		fwd.Question[0].Name = randomizeCase0x20(fwd.Question[0].Name)
	}

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

	if u != nil && u.RequireDNSSECAD {
		opt.SetDo()
	}

	if !encrypted && u != nil && u.DNSCookies && u.Proto == "udp" && u.clientCookieHex != "" {
		cookieVal := u.clientCookieHex
		if srvCookie, ok := u.serverCookieHex.Load().(string); ok && len(srvCookie) >= 32 {
			cookieVal = srvCookie
		}
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: cookieVal,
		})
	}

	action := "remove"
	if u != nil && u.ECSAction != "" {
		action = u.ECSAction
	}

	// Only pass client-supplied ECS when the request originated from a trusted proxy
	// (or from an internal probe/background worker that sets SourceScope == 255 as an internal marker).
	if action == "pass" && clientECS != nil && (isTrustedProxy(clientAddr) || clientECS.SourceScope == 255) {
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
	if proto == "doh" && cfg.Server.UpgradeDoH3 && up.h3Upgraded.Load() && !up.dohSticky.Load() {
		proto = "doh3"
	} else if proto == "doh3" && up.dohSticky.Load() {
		proto = "doh"
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

			if u.h2Client != nil {
				u.h2Client.CloseIdleConnections()
			}
			if u.h2ClientNoECH != nil {
				u.h2ClientNoECH.CloseIdleConnections()
			}
			if u.h3Client != nil {
				u.h3Client.CloseIdleConnections()
			}
			if u.h3ClientNoECH != nil {
				u.h3ClientNoECH.CloseIdleConnections()
			}
		}
	}

	for _, c := range connsToClose {
		c.Close()
	}
	for _, entry := range doqToClose {
		entry.conn.CloseWithError(0, "idle sweeper")
	}
}
