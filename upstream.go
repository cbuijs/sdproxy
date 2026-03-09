/*
File: upstream.go
Version: 1.28.0
Last Updated: 2026-03-09 10:45 CET
Description: Manages connections to external DNS upstream providers.
             Supports UDP, TCP, DoT, DoH (HTTP/2), DoH3 (QUIC/HTTP3), and DoQ.
             TCP and DoT connections are cached and reused across queries.
             DoH/DoH3 reuse is handled by Go's http.Client transport.
             DoQ reuses QUIC connections with retry-on-stale.

             STAGGERED PARALLEL RACING (raceExchange):
               When an upstream group has multiple targets and upstream_stagger_ms > 0,
               queries are sent in parallel with a stagger delay between launches.
               First successful response wins; losing goroutines are canceled via
               context. This eliminates "context deadline exceeded" in practice.

             HEALTH TRACKING (per-upstream, lock-free):
               Each Upstream tracks consecutive failures via atomic counters.
               After 3 consecutive failures the upstream is marked unhealthy and
               the stagger wait before the next upstream is skipped. One success
               resets the counter. No timestamps, no background goroutines.

Changes:
  1.28.0 - [FIX] DoQ 0-RTT: RFC 9250 §10.5 prohibits sending DNS messages as
           QUIC 0-RTT (early) data because early data is replay-unsafe. Strict
           DoQ servers (e.g. ControlD) enforce this by sending APPLICATION_ERROR
           0x2 (DOQ_PROTOCOL_ERROR) and closing the connection immediately on
           receiving any early data. Added doqNo0RTT atomic.Bool per Upstream.
           On first exchange with a fresh connection, 0-RTT is attempted. If the
           server responds with ApplicationError 0x2 (remote), the flag is latched,
           a clean 1-RTT connection is dialled, and the query is retried once —
           transparent to the caller. All subsequent dials for this upstream skip
           0-RTT permanently (flag survives for the process lifetime). Zero
           overhead on the hot path once the flag is set.
  1.27.0 - [FIX] doqStreamExchange: RFC 9250 §4.2 violation — the write side
           of the QUIC stream was half-closed via defer stream.Close(), which
           runs AFTER the function returns and therefore AFTER io.ReadFull.
           Strict DoQ servers (e.g. ControlD) wait for the stream FIN before
           sending the response, causing both sides to stall until the server
           times out and sends APPLICATION_ERROR 0x2 (DOQ_PROTOCOL_ERROR).
           Fix: call stream.Close() explicitly after the write and BEFORE the
           read. Replaced defer stream.Close() with defer stream.CancelRead(0)
           which cancels the read side on any error path without conflicting
           with the now-explicit write-side close.
  1.26.0 - [FIX] exchangeDoQ: {client-name} in a DoQ hostname was never
           substituted — the literal placeholder was used as TLS ServerName,
           causing CRYPTO_ERROR "certificate not valid for {client-name}"
           because no server cert matches that placeholder string. exchangeDoQ
           now accepts the caller-resolved effective host and uses it for both
           TLS SNI and the per-client connection-pool key. Connections are keyed
           by the expanded hostname so each device gets its own QUIC session
           rather than sharing one misdirected connection.
           [FIX] Exchange tcp/dot: same root cause — {client-name} in a DoT
           hostname was passed raw to dialStream/TLS ServerName. Now resolved
           to effectiveHost before the per-dialAddr loop, consistent with how
           DoH already resolves targetURL before calling exchangeHTTP.
           [FIX] ParseUpstream: DoQ with {client-name} in the hostname but no
           bootstrap IPs now fails at startup with a clear, actionable error.
           Without bootstrap IPs dialAddrs contains the unresolvable placeholder
           literal and TLS SNI would also be wrong — better to catch it at load
           time than produce cryptic CRYPTO_ERROR messages at runtime.
  1.25.0 - [FIX] exchangeDoQ: new connection now stored in pool ONLY after a
           successful doqStreamExchange. Previously putDoQConn was called before
           the exchange — on failure removeDoQConn raced with concurrent
           putDoQConn calls from other goroutines, potentially evicting a valid
           replacement connection they had just stored.
           [FIX] doqConnEntry: added dialAddr string field. takeDoQConn now
           returns the full *doqConnEntry so the reused-connection path returns
           the actual dialled IP:port for logging instead of falling back to
           u.RawURL (the hostname). putDoQConn signature updated to accept
           dialAddr. removeDoQConn retained for completeness but no longer
           called from exchangeDoQ.
  1.24.0 - [FEAT] AcquireUpstream/ReleaseUpstream added at the top of
           Exchange(). All protocol paths (UDP, TCP, DoT, DoH, DoH3, DoQ)
           are covered with one acquire/release pair. When the upstream
           concurrency limit is reached Exchange returns an error immediately
           so raceExchange falls through to the next upstream or surfaces a
           SERVFAIL — no goroutine is left blocked waiting.
  1.23.0 - [PERF] doqStreamExchange: the 2-byte length prefix and DNS payload
           are now written in a single stream.Write call. Two separate Write
           calls each triggered a distinct QUIC STREAM frame; combining them
           halves the frame count per query exchange, reducing RTTs on slow links.
           Achieved by packing the query directly into pooled buf[2:] and writing
           buf[:2+len(packed)] in one shot — no extra copy needed.
           [FIX]  doqStreamExchange: moved smallBufPool.Put to a defer so the
           pooled buffer stays live until after the Write completes.
           [FIX]  exchangeHTTP: same early-Put race corrected.
           [FIX]  Version header corrected from 1.21.0 to 1.22.0.
  1.22.0 - [PERF] Pre-allocated udpClient *dns.Client on Upstream struct.
  1.21.0 - [PERF] Pre-computed dialHost and dialAddrs fields on Upstream.
  1.20.0 - [LOG] Exchange() prefixes returned address with protocol scheme.
  1.19.0 - [LOG] Exchange() returns actual IP:port dialled.
  1.18.0 - [FEAT] raceExchange: staggered parallel upstream queries.
           [FEAT] Per-upstream health tracking via atomic.Int32.
  1.17.0 - [PERF] prepareForwardQuery: eliminated first Pack() via wire-size estimate.
  1.16.0 - [PERF] Eliminated redundant dns.Msg.Copy() on the hot path.
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	streamIdleMax = 50 * time.Second
	streamTimeout = 3 * time.Second
	doqIdleMax    = 5 * time.Second

	// healthThreshold: an upstream is marked unhealthy after this many consecutive
	// failures. Unhealthy upstreams still receive queries (they might recover) but
	// the stagger wait before the next upstream is skipped so the fallback fires
	// immediately. One success resets the counter.
	healthThreshold = 3
)

// upstreamStagger is the delay between launching parallel upstream queries in
// raceExchange. Set once at startup from cfg.Server.UpstreamStaggerMs.
// 0 = sequential (no parallelism). Read-only after init — no sync needed.
var upstreamStagger time.Duration

type streamConnEntry struct {
	conn   *dns.Conn
	idleAt time.Time
}

// doqConnEntry caches a live QUIC connection between queries.
//
// dialAddr holds the actual IP:port that was successfully dialled (e.g.
// "9.9.9.9:853"). It is stored alongside the connection so that the
// reused-connection path in exchangeDoQ can return the real address for
// logging — previously this path returned u.RawURL (the hostname) because
// the dialled address was not preserved anywhere.
type doqConnEntry struct {
	conn     *quic.Conn
	idleAt   time.Time
	dialAddr string // actual IP:port dialled, e.g. "9.9.9.9:853"
}

type Upstream struct {
	Proto        string
	RawURL       string
	BootstrapIPs []string

	hasClientNameTemplate bool
	baseTLSConf           *tls.Config

	h2Client  *http.Client
	h3Client  *http.Client
	udpClient *dns.Client

	streamMu    sync.Mutex
	streamConns map[string]*streamConnEntry

	doqMu    sync.Mutex
	doqConns map[string]*doqConnEntry

	dialHost  string
	dialAddrs []string

	// Health tracking — lock-free via atomics.
	// consFails counts consecutive failures. Reset to 0 on any success.
	// isHealthy() returns false once consFails >= healthThreshold, causing
	// raceExchange to skip the stagger delay before the next upstream.
	consFails atomic.Int32

	// doqNo0RTT is latched to true the first time this upstream sends back
	// DOQ_PROTOCOL_ERROR (0x2) on a fresh connection. Once set, all subsequent
	// dials use Allow0RTT: false (standard 1-RTT handshake), which is what
	// RFC 9250 §10.5 requires. Never reset — survives for the process lifetime.
	doqNo0RTT atomic.Bool
}

func (u *Upstream) recordSuccess() { u.consFails.Store(0) }
func (u *Upstream) recordFailure() { u.consFails.Add(1) }

func (u *Upstream) isHealthy() bool { return u.consFails.Load() < healthThreshold }

func ParseUpstream(raw string) (*Upstream, error) {
	u := &Upstream{}

	parts   := strings.Split(raw, "#")
	urlPart := parts[0]
	if len(parts) > 1 {
		u.BootstrapIPs = strings.Split(parts[1], ",")
	}

	u.hasClientNameTemplate = strings.Contains(urlPart, "{client-name}")

	switch {
	case strings.HasPrefix(urlPart, "udp://"):
		u.Proto     = "udp"
		u.RawURL    = strings.TrimPrefix(urlPart, "udp://")
		u.udpClient = &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	case strings.HasPrefix(urlPart, "tcp://"):
		u.Proto       = "tcp"
		u.RawURL      = strings.TrimPrefix(urlPart, "tcp://")
		u.streamConns = make(map[string]*streamConnEntry)

	case strings.HasPrefix(urlPart, "dot://"), strings.HasPrefix(urlPart, "tls://"):
		u.Proto       = "dot"
		u.RawURL      = strings.TrimPrefix(strings.TrimPrefix(urlPart, "dot://"), "tls://")
		u.baseTLSConf = getHardenedTLSConfig()
		u.streamConns = make(map[string]*streamConnEntry)

	case strings.HasPrefix(urlPart, "doh://"), strings.HasPrefix(urlPart, "https://"):
		u.Proto  = "doh"
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh://"), "https://")
		dialer  := &net.Dialer{Timeout: 3 * time.Second}
		u.h2Client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     getHardenedTLSConfig(),
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        5,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     5 * time.Second,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
								return conn, nil
							}
						}
						return nil, errors.New("all bootstrap IPs failed")
					}
					return dialer.DialContext(ctx, network, addr)
				},
			},
		}

	case strings.HasPrefix(urlPart, "doh3://"), strings.HasPrefix(urlPart, "h3://"):
		u.Proto  = "doh3"
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh3://"), "h3://")
		u.h3Client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http3.Transport{
				TLSClientConfig: getHardenedTLSConfig(),
				QUICConfig: &quic.Config{
					Allow0RTT:          true,
					MaxIdleTimeout:     5 * time.Second,
					MaxIncomingStreams: 10,
				},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							if conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip, port), tlsCfg, cfg); err == nil {
								return conn, nil
							}
						}
						return nil, errors.New("all bootstrap IPs failed")
					}
					return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
				},
			},
		}

	case strings.HasPrefix(urlPart, "doq://"):
		u.Proto    = "doq"
		u.RawURL   = strings.TrimPrefix(urlPart, "doq://")
		u.doqConns = make(map[string]*doqConnEntry)

	default:
		return nil, fmt.Errorf("unsupported protocol scheme in: %s", raw)
	}

	switch u.Proto {
	case "udp", "tcp", "dot", "doq":
		host, port := parseHostPort(u.RawURL, u.Proto)
		u.dialHost  = host
		if len(u.BootstrapIPs) > 0 {
			u.dialAddrs = make([]string, len(u.BootstrapIPs))
			for i, ip := range u.BootstrapIPs {
				u.dialAddrs[i] = net.JoinHostPort(ip, port)
			}
		} else {
			u.dialAddrs = []string{net.JoinHostPort(host, port)}
		}
	}

	// A DoQ upstream with {client-name} in the hostname MUST have bootstrap IPs.
	//
	// Why: dialHost and dialAddrs are computed at startup from the raw URL. If
	// no bootstrap IPs are provided, dialAddrs contains the literal placeholder
	// string (e.g. "prefix-{client-name}-suffix.dns.controld.com:853"), which
	// the OS resolver will never resolve. Additionally, dialHost is used as TLS
	// ServerName — the placeholder would not match any server certificate even
	// before the substitution bug was fixed.
	//
	// The bootstrap IPs are just the actual IP addresses of the upstream server;
	// they don't contain {client-name} and are not affected by the substitution.
	// The substituted hostname is only used for TLS SNI and the connection-pool
	// key, both of which happen at query time in exchangeDoQ.
	if u.Proto == "doq" && u.hasClientNameTemplate && len(u.BootstrapIPs) == 0 {
		return nil, fmt.Errorf(
			"doq upstream %q: {client-name} in hostname requires bootstrap IPs "+
				"— append #ip1,ip2 to bypass DNS for the upstream host itself", raw)
	}

	return u, nil
}

// Exchange forwards a DNS query to this upstream and returns the response.
// The second return value is a loggable string combining protocol and address.
// The caller's req is never modified — prepareForwardQuery creates an internal copy.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	// Upstream admission control — cap total concurrent outbound exchanges so a
	// slow or unreachable upstream can't cause unbounded goroutine and memory
	// growth. Returns an error (not a silent drop) so raceExchange can try the
	// next upstream or propagate a SERVFAIL via dns.HandleFailed. The query slot
	// acquired in ProcessDNS stays held throughout, ensuring the two limits are
	// always consistent.
	if !AcquireUpstream() {
		return nil, u.Proto + "://" + u.RawURL, errors.New("upstream throttled: concurrency limit reached")
	}
	defer ReleaseUpstream()

	// targetURL is used by DoH/DoH3 where {client-name} lives in the URL path.
	// For DoT and DoQ the placeholder is in the hostname; those cases compute
	// effectiveHost below instead.
	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(u.RawURL, "{client-name}", clientName)
	}

	encrypted := u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq"
	fwd := prepareForwardQuery(req, encrypted)

	switch u.Proto {
	case "udp":
		var (
			resp *dns.Msg
			err  error
		)
		for _, dialAddr := range u.dialAddrs {
			resp, _, err = u.udpClient.ExchangeContext(ctx, fwd, dialAddr)
			if err == nil && resp != nil {
				return resp, "udp://"+dialAddr, nil
			}
		}
		return nil, "udp://"+u.RawURL, err

	case "tcp", "dot":
		// Resolve {client-name} in the hostname at query time. u.dialHost is the
		// raw static hostname set at startup; effectiveHost is what gets used for
		// TLS ServerName in dialStream. Without this substitution a DoT upstream
		// whose hostname contains {client-name} would pass the literal placeholder
		// as SNI and receive a TLS certificate mismatch error.
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}
		var lastErr error
		for _, dialAddr := range u.dialAddrs {
			resp, err := u.exchangeStream(ctx, fwd, dialAddr, effectiveHost)
			if err == nil && resp != nil {
				return resp, u.Proto+"://"+dialAddr, nil
			}
			lastErr = err
		}
		return nil, u.Proto+"://"+u.RawURL, lastErr

	case "doh":
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h2Client)
		return resp, "doh://"+strings.TrimPrefix(targetURL, "https://"), err

	case "doh3":
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h3Client)
		return resp, "doh3://"+strings.TrimPrefix(targetURL, "https://"), err

	case "doq":
		// Resolve {client-name} in the hostname at query time.
		//
		// ControlD-style DoQ URLs embed the per-device token in the hostname
		// itself (e.g. "prefix-{client-name}-ams.dns.controld.com:853"). The
		// expanded hostname is passed to exchangeDoQ for two purposes:
		//   1. TLS ServerName — must match the server's wildcard cert SAN.
		//   2. Connection-pool key — so each device gets its own QUIC session
		//      instead of sharing one session dialled to the wrong hostname.
		// u.dialAddrs (bootstrap IPs) are plain IP:port strings and are not
		// affected by the substitution; they are used unchanged for dialling.
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}
		resp, dialAddr, err := u.exchangeDoQ(ctx, fwd, effectiveHost)
		return resp, "doq://"+dialAddr, err

	default:
		return nil, targetURL, errors.New("unknown protocol")
	}
}

// --- Staggered Parallel Racing ---

type raceResult struct {
	msg  *dns.Msg
	addr string
	up   *Upstream
	err  error
}

// raceExchange sends a DNS query to an upstream group using staggered parallelism.
// When upstreamStagger > 0 and the group has more than one upstream, each upstream
// is launched after a delay. If the previous upstream responds in time, the race
// ends early; otherwise the next upstream starts and they run concurrently.
// First success wins; all others are canceled via the shared context.
func raceExchange(upstreams []*Upstream, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	n := len(upstreams)
	if n == 0 {
		return nil, "", errors.New("no upstreams configured")
	}

	if n == 1 || upstreamStagger <= 0 {
		return sequentialExchange(upstreams, req, clientName)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch       := make(chan raceResult, n)
	launched := 0

	for i, up := range upstreams {
		if i > 0 {
			prevHealthy := upstreams[i-1].isHealthy()
			if prevHealthy {
				t := time.NewTimer(upstreamStagger)
				select {
				case r := <-ch:
					t.Stop()
					launched--
					if r.err == nil && r.msg != nil {
						r.up.recordSuccess()
						return r.msg, r.addr, nil
					}
					r.up.recordFailure()
				case <-t.C:
				}
			}
		}

		launched++
		go func(u *Upstream) {
			msg, addr, err := u.Exchange(ctx, req, clientName)
			ch <- raceResult{msg, addr, u, err}
		}(up)
	}

	var lastErr error
	for i := 0; i < launched; i++ {
		r := <-ch
		if r.err == nil && r.msg != nil {
			r.up.recordSuccess()
			return r.msg, r.addr, nil
		}
		r.up.recordFailure()
		lastErr = r.err
	}
	return nil, "", lastErr
}

// sequentialExchange tries upstreams one by one with no parallelism.
func sequentialExchange(upstreams []*Upstream, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	var lastErr error
	for _, up := range upstreams {
		resp, addr, err := up.Exchange(context.Background(), req, clientName)
		if err == nil && resp != nil {
			up.recordSuccess()
			return resp, addr, nil
		}
		up.recordFailure()
		lastErr = err
	}
	return nil, "", lastErr
}

// prepareForwardQuery creates a sanitised copy of a DNS query for upstream forwarding:
// deep-copy, fresh random ID, EDNS0 options stripped, optional RFC 7830/8467 padding.
func prepareForwardQuery(req *dns.Msg, encrypted bool) *dns.Msg {
	msg    := req.Copy()
	msg.Id  = dns.Id()

	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		msg.Extra = append(msg.Extra, opt)
	}
	opt.Option = opt.Option[:0]

	if !encrypted {
		return msg
	}

	const blockSize = 128
	wireEst   := 12 + len(msg.Question[0].Name) + 4 + 11
	remainder := wireEst % blockSize

	var paddingLen int
	if remainder != 0 {
		paddingLen = blockSize - remainder - 4
		if paddingLen < 0 {
			paddingLen += blockSize
		}
	}

	if paddingLen > 0 {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
			Padding: make([]byte, paddingLen),
		})
	}

	return msg
}

// --- TCP / DoT Connection Reuse ---

func (u *Upstream) takeStreamConn(addr string) *dns.Conn {
	u.streamMu.Lock()
	entry := u.streamConns[addr]
	delete(u.streamConns, addr)
	u.streamMu.Unlock()

	if entry == nil {
		return nil
	}
	if time.Since(entry.idleAt) > streamIdleMax {
		entry.conn.Close()
		return nil
	}
	return entry.conn
}

func (u *Upstream) putStreamConn(addr string, conn *dns.Conn) {
	u.streamMu.Lock()
	if old := u.streamConns[addr]; old != nil {
		old.conn.Close()
	}
	u.streamConns[addr] = &streamConnEntry{conn: conn, idleAt: time.Now()}
	u.streamMu.Unlock()
}

func (u *Upstream) dialStream(addr, tlsHost string) (*dns.Conn, error) {
	if u.Proto == "dot" {
		tlsConf           := u.baseTLSConf.Clone()
		tlsConf.ServerName = tlsHost
		return dns.DialTimeoutWithTLS("tcp-tls", addr, tlsConf, streamTimeout)
	}
	return dns.DialTimeout("tcp", addr, streamTimeout)
}

func (u *Upstream) exchangeStream(ctx context.Context, req *dns.Msg, dialAddr, tlsHost string) (*dns.Msg, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	}

	if conn := u.takeStreamConn(dialAddr); conn != nil {
		conn.SetDeadline(deadline)
		if err := conn.WriteMsg(req); err == nil {
			if resp, err := conn.ReadMsg(); err == nil && resp != nil {
				u.putStreamConn(dialAddr, conn)
				return resp, nil
			}
		}
		conn.Close()
	}

	conn, err := u.dialStream(dialAddr, tlsHost)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(deadline)
	if err := conn.WriteMsg(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := conn.ReadMsg()
	if err != nil || resp == nil {
		conn.Close()
		return nil, err
	}

	u.putStreamConn(dialAddr, conn)
	return resp, nil
}

// --- HTTP (DoH / DoH3) ---

func (u *Upstream) exchangeHTTP(ctx context.Context, req *dns.Msg, targetURL string, client *http.Client) (*dns.Msg, error) {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return nil, err
	}
	// defer Put: packed shares the pool buffer's backing array. The buffer must
	// stay live until http.NewRequestWithContext has consumed packed into the
	// request body reader — which happens synchronously inside client.Do.
	defer smallBufPool.Put(bufPtr)

	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	rBufPtr := largeBufPool.Get().(*[]byte)
	defer largeBufPool.Put(rBufPtr)
	rBuf := *rBufPtr

	n := 0
	lr := io.LimitReader(resp.Body, int64(len(rBuf)))
	for {
		c, readErr := lr.Read(rBuf[n:])
		n += c
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(rBuf[:n]); err != nil {
		return nil, err
	}
	return dnsResp, nil
}

// --- QUIC (DoQ) ---

// exchangeDoQ tries a cached QUIC connection first, dials fresh on miss/stale,
// and stores the connection in the pool ONLY after a successful exchange.
//
// host is the fully resolved hostname for this query — {client-name} has already
// been substituted by Exchange() before calling here. It serves two roles:
//   1. TLS ServerName: the QUIC handshake presents this to the server for SNI,
//      so the server cert's SAN is checked against the real expanded hostname
//      (e.g. "prefix-macbook-ams.dns.controld.com") not the placeholder literal.
//   2. Connection-pool key: each unique expanded hostname gets its own cached
//      QUIC connection. Without this, all devices would compete for one shared
//      connection that was dialled to a single (probably wrong) hostname.
//
// BUG FIX (v1.25.0): putDoQConn is called AFTER a successful doqStreamExchange.
// Previously it was called before, causing a race: on failure removeDoQConn
// could evict a valid connection that a concurrent goroutine had just stored.
func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, host string) (*dns.Msg, string, error) {
	// Use the expanded hostname as pool key so per-device connections stay isolated.
	key := host

	// Try cached connection.
	if entry := u.takeDoQConn(key); entry != nil {
		resp, err := u.doqStreamExchange(ctx, entry.conn, req)
		if err == nil {
			// Successful reuse — return connection to pool with its dialled address.
			u.putDoQConn(key, entry.conn, entry.dialAddr)
			return resp, entry.dialAddr, nil
		}
		// Stale — close and fall through to fresh dial.
		(*entry.conn).CloseWithError(0, "stale")
	}

	// Dial a fresh connection using the caller-resolved host for TLS SNI.
	// u.dialAddrs are the bootstrap IP:port strings — they are unaffected by
	// {client-name} substitution and can be used directly here.
	newConn, dialAddr, err := u.dialDoQ(host, u.dialAddrs)
	if err != nil {
		return nil, u.RawURL, err
	}

	// Exchange FIRST — pool ONLY after success. This eliminates the race where
	// a concurrent goroutine takes the connection mid-exchange, and makes
	// removeDoQConn unnecessary (no partial pool state can exist).
	resp, err := u.doqStreamExchange(ctx, newConn, req)
	if err != nil {
		(*newConn).CloseWithError(0, "exchange failed")

		// RFC 9250 §10.5: DoQ clients MUST NOT send DNS messages as 0-RTT data.
		// If the server sent DOQ_PROTOCOL_ERROR (ApplicationError 0x2) on this
		// fresh connection and we had 0-RTT enabled, that's the likely cause.
		// Latch doqNo0RTT so all future dials use a clean 1-RTT handshake, then
		// retry this query once — transparent to the caller, at most one retry
		// per process lifetime per upstream.
		var appErr *quic.ApplicationError
		if errors.As(err, &appErr) && appErr.ErrorCode == 0x2 && appErr.Remote && !u.doqNo0RTT.Load() {
			u.doqNo0RTT.Store(true)
			log.Printf("[DoQ] %s: DOQ_PROTOCOL_ERROR on 0-RTT connection — disabling 0-RTT, retrying", host)
			if retryConn, retryAddr, dialErr := u.dialDoQ(host, u.dialAddrs); dialErr == nil {
				retryResp, retryErr := u.doqStreamExchange(ctx, retryConn, req)
				if retryErr == nil {
					u.putDoQConn(key, retryConn, retryAddr)
					return retryResp, retryAddr, nil
				}
				(*retryConn).CloseWithError(0, "retry exchange failed")
				return nil, retryAddr, retryErr
			}
		}

		return nil, dialAddr, err
	}
	u.putDoQConn(key, newConn, dialAddr)
	return resp, dialAddr, nil
}

// takeDoQConn pops a cached connection entry from the pool.
// Returns nil when the pool is empty or the entry has exceeded doqIdleMax.
// Returns the full *doqConnEntry (not just the conn) so the caller has access
// to dialAddr for accurate logging on the reused-connection path.
func (u *Upstream) takeDoQConn(key string) *doqConnEntry {
	u.doqMu.Lock()
	entry := u.doqConns[key]
	delete(u.doqConns, key)
	u.doqMu.Unlock()

	if entry == nil {
		return nil
	}
	if time.Since(entry.idleAt) > doqIdleMax {
		(*entry.conn).CloseWithError(0, "idle timeout")
		return nil
	}
	return entry
}

// putDoQConn stores a QUIC connection in the pool after a successful exchange.
// dialAddr is the actual IP:port that was dialled — preserved for logging on reuse.
// If an old entry exists (two goroutines racing to store), the old connection is
// closed first so we don't leak QUIC connections.
func (u *Upstream) putDoQConn(key string, conn *quic.Conn, dialAddr string) {
	u.doqMu.Lock()
	if old := u.doqConns[key]; old != nil {
		(*old.conn).CloseWithError(0, "replaced")
	}
	u.doqConns[key] = &doqConnEntry{conn: conn, idleAt: time.Now(), dialAddr: dialAddr}
	u.doqMu.Unlock()
}

// removeDoQConn evicts a connection from the pool by key.
// No longer called from exchangeDoQ (the pool-before-exchange pattern is gone)
// but retained for any future callers that need explicit eviction.
func (u *Upstream) removeDoQConn(key string) {
	u.doqMu.Lock()
	delete(u.doqConns, key)
	u.doqMu.Unlock()
}

// dialDoQ tries each dialAddr in order and returns the first successful QUIC
// connection alongside the address that was actually used.
// host is the expanded SNI hostname (already has {client-name} substituted).
func (u *Upstream) dialDoQ(host string, dialAddrs []string) (*quic.Conn, string, error) {
	tlsConf           := getHardenedTLSConfig()
	tlsConf.ServerName = host // expanded hostname: cert SAN check uses this
	tlsConf.NextProtos = []string{"doq"}

	var lastErr error
	for _, dialAddr := range dialAddrs {
		conn, err := quic.DialAddr(context.Background(), dialAddr, tlsConf, &quic.Config{
			// Allow0RTT: honour the per-upstream 0-RTT flag. Starts true (attempt
			// 0-RTT for servers that support it). Latched to false permanently on
			// the first DOQ_PROTOCOL_ERROR so subsequent dials are always 1-RTT.
			Allow0RTT:          !u.doqNo0RTT.Load(),
			MaxIdleTimeout:     5 * time.Second,
			MaxIncomingStreams: 10,
		})
		if err == nil {
			return conn, dialAddr, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// doqStreamExchange sends one DNS query over a new QUIC stream and reads the
// response. The 2-byte length prefix and DNS payload are packed into a single
// pooled buffer and written in one stream.Write call — halving the number of
// QUIC STREAM frames per exchange compared to the previous two-Write approach.
//
// RFC 9250 §4.2 stream lifecycle:
//   Client writes query → Client MUST half-close write side (FIN) → Server
//   sends response → Server half-closes write side → Client reads response.
//
// The half-close (stream.Close()) MUST happen BEFORE the read. Strict DoQ
// servers wait for the client's FIN before sending any response. Deferring
// Close() until after the function returns means the FIN arrives after
// io.ReadFull — both sides stall waiting on each other until the server gives
// up and sends DOQ_PROTOCOL_ERROR (Application error 0x2).
func (u *Upstream) doqStreamExchange(ctx context.Context, conn *quic.Conn, req *dns.Msg) (*dns.Msg, error) {
	stream, err := (*conn).OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	// CancelRead on any error exit: tells the server to stop sending and lets
	// quic-go release the stream immediately. Safe to call after a successful
	// read — it becomes a no-op once the receive side is already exhausted.
	defer stream.CancelRead(0)

	sBufPtr := smallBufPool.Get().(*[]byte)
	defer smallBufPool.Put(sBufPtr) // buffer must stay live until Write returns

	// Pack directly into buf[2:] so the length prefix can be prepended in-place.
	packed, err := req.PackBuffer((*sBufPtr)[2:2])
	if err != nil {
		return nil, err
	}
	pn := len(packed)

	if pn <= len(*sBufPtr)-2 {
		// Happy path: message fits in pool buffer — write length + payload in one call.
		(*sBufPtr)[0] = byte(pn >> 8)
		(*sBufPtr)[1] = byte(pn)
		if _, err = stream.Write((*sBufPtr)[:2+pn]); err != nil {
			return nil, err
		}
	} else {
		// Oversized (> ~4094 B): fall back to two writes — length header first.
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(pn))
		if _, err = stream.Write(hdr[:]); err != nil {
			return nil, err
		}
		if _, err = stream.Write(packed); err != nil {
			return nil, err
		}
	}

	// RFC 9250 §4.2: half-close the write side NOW, before reading the response.
	// stream.Close() sends a STREAM FIN to the server and returns immediately —
	// it does NOT block waiting for the server's acknowledgement. The pool buffer
	// is safe to release after this point; the data is already in quic-go's send
	// buffer. The defer above (CancelRead) handles the receive side on exit.
	if err = stream.Close(); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err = io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	rBufPtr := largeBufPool.Get().(*[]byte)
	defer largeBufPool.Put(rBufPtr)

	if _, err = io.ReadFull(stream, (*rBufPtr)[:length]); err != nil {
		return nil, err
	}

	dnsResp := new(dns.Msg)
	if err = dnsResp.Unpack((*rBufPtr)[:length]); err != nil {
		return nil, err
	}
	return dnsResp, nil
}

// --- Shared Helpers ---

// parseHostPort is used only at ParseUpstream time (startup). No longer called
// on the query hot path — results are stored in dialHost/dialAddrs.
func parseHostPort(raw, proto string) (string, string) {
	host, port := raw, ""
	if parsed, err := url.Parse("http://" + raw); err == nil {
		host = parsed.Hostname()
		port = parsed.Port()
	} else if strings.Contains(raw, ":") {
		host, port, _ = net.SplitHostPort(raw)
	}
	if port == "" {
		switch proto {
		case "udp", "tcp":
			port = "53"
		case "dot", "doq":
			port = "853"
		}
	}
	return host, port
}

