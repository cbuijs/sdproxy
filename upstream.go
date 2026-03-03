/*
File: upstream.go
Version: 1.21.0
Last Updated: 2026-03-04 14:00 CET
Description: Manages connections to external DNS upstream providers.
             Supports UDP, TCP, DoT, DoH (HTTP/2), DoH3 (QUIC/HTTP3), and DoQ.
             TCP and DoT connections are cached and reused across queries.
             DoH/DoH3 reuse is handled by Go's http.Client transport.
             DoQ reuses QUIC connections with retry-on-stale.

             STAGGERED PARALLEL RACING (raceExchange):
               When an upstream group has multiple targets and upstream_stagger_ms > 0,
               queries are sent in parallel with a stagger delay between launches.
               First successful response wins; losing goroutines are canceled via
               context. This eliminates "context deadline exceeded" in practice:
               you'd need ALL upstreams to be simultaneously unreachable.

             HEALTH TRACKING (per-upstream, lock-free):
               Each Upstream tracks consecutive failures via atomic counters.
               After 3 consecutive failures, the upstream is marked unhealthy and
               the stagger wait before the next upstream is skipped (fire immediately).
               One success resets the counter. No timestamps, no background goroutines —
               the natural cadence of DNS queries provides the probing.

Changes:
  1.21.0 - [PERF] Pre-computed dialHost and dialAddrs fields on Upstream.
           parseHostPort (which calls url.Parse + allocates "http://"+raw) was
           called on every Exchange() for UDP, TCP, DoT, and DoQ. These values
           are entirely static after startup. ParseUpstream now pre-computes them
           once and stores them in the struct. Exchange() reads a []string field
           instead of calling url.Parse. Also dropped the targetURL parameter from
           exchangeDoQ — it was always u.RawURL and the receiver already has it.
  1.20.0 - [LOG] Exchange() prefixes the returned address with the protocol scheme
           (e.g. "udp://1.1.1.1:53", "dot://9.9.9.9:853", "doh://…"). process.go
           logs this value as-is — no changes needed there.
  1.19.0 - [LOG] Exchange() now returns the actual IP:port dialled for UDP, TCP, DoT,
           and DoQ instead of the raw configured URL. This makes the UPSTREAM field in
           log lines show the real address used — useful when bootstrap IPs are
           configured and the URL contains a hostname rather than an IP.
           For DoH/DoH3 the HTTPS URL is kept as-is: the actual IP is transparent
           inside http.Transport and not surfaceable without invasive hooks.
           dialDoQ() now returns the successful dialAddr alongside the connection so
           exchangeDoQ() and Exchange() can thread it through to the caller.
  1.18.0 - [FEAT] raceExchange: staggered parallel upstream queries. Launches
           upstreams with a configurable delay (upstream_stagger_ms) between them.
           First good response wins, context.WithCancel aborts the rest. Sequential
           fallback when stagger is 0 or only one upstream in the group.
           [FEAT] Per-upstream health tracking via atomic.Int32. Consecutive failures
           are counted; >=3 = unhealthy. Unhealthy upstreams don't get a stagger
           grace period — the next upstream fires immediately alongside them.
           One success resets the counter to 0.
           [PERF] context.WithCancel (not WithTimeout) for racing — no timer goroutine.
           Individual upstream transports still enforce their own deadlines.
  1.17.0 - [PERF] prepareForwardQuery: eliminated first Pack() via wire-size estimate.
  1.16.0 - [PERF] Eliminated redundant dns.Msg.Copy() on the hot path.
  1.15.0 - [PERF] Connection reuse for TCP/DoT/DoQ upstreams.
  1.14.0 - [FEAT] EDNS0 stripping and RFC 7830/8467 padding.
  1.13.0 - [PERF] hasClientNameTemplate, baseTLSConf, tiered buffer pools.
  1.12.0 - Exchange returns actual resolved URL for accurate logging.
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
	// the stagger wait before the *next* upstream is skipped so the fallback fires
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

type doqConnEntry struct {
	conn   *quic.Conn
	idleAt time.Time
}

type Upstream struct {
	Proto        string
	RawURL       string
	BootstrapIPs []string

	hasClientNameTemplate bool
	baseTLSConf           *tls.Config

	h2Client *http.Client
	h3Client *http.Client

	streamMu    sync.Mutex
	streamConns map[string]*streamConnEntry

	doqMu    sync.Mutex
	doqConns map[string]*doqConnEntry

	// dialHost is the pre-parsed TLS SNI hostname for DoT and DoQ upstreams.
	// For UDP and TCP it's the bare target hostname. Empty for DoH/DoH3 — those
	// protocols let http.Transport manage dialing entirely.
	dialHost string

	// dialAddrs holds the pre-computed dial address(es) for explicit-dial protocols
	// (UDP, TCP, DoT, DoQ). Computed once in ParseUpstream from RawURL + BootstrapIPs.
	// Eliminates a parseHostPort (url.Parse + alloc) call on every Exchange().
	// len==1 for plain upstreams; len==len(BootstrapIPs) when bootstrap IPs are set.
	// Unused for DoH/DoH3 — dialing is handled inside http.Transport.
	dialAddrs []string

	// Health tracking — lock-free via atomics.
	// consFails counts consecutive Exchange failures. Incremented on failure,
	// reset to 0 on success. When >= healthThreshold the upstream is considered
	// unhealthy and the stagger delay before the next upstream is skipped.
	consFails atomic.Int32
}

// recordSuccess resets the consecutive failure counter.
func (u *Upstream) recordSuccess() { u.consFails.Store(0) }

// recordFailure increments the consecutive failure counter.
func (u *Upstream) recordFailure() { u.consFails.Add(1) }

// isHealthy returns true if the upstream has fewer than healthThreshold
// consecutive failures. Unhealthy upstreams still participate in exchanges
// (they're probed naturally by DNS traffic) but don't get stagger grace time.
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
		u.Proto  = "udp"
		u.RawURL = strings.TrimPrefix(urlPart, "udp://")

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

	// Pre-compute dial host and addresses for explicit-dial protocols (UDP, TCP, DoT,
	// DoQ). parseHostPort is called once here at startup instead of on every Exchange.
	// DoH and DoH3 are excluded — http.Transport owns dialing for those protocols.
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

	return u, nil
}

// Exchange forwards a DNS query to this upstream and returns the response.
// The second return value is a loggable string combining protocol and address:
//   - UDP/TCP/DoT/DoQ: "proto://ip:port" using the actual IP dialled.
//   - DoH/DoH3: "doh://…" or "doh3://…" prefixed full HTTPS URL. The actual IP
//     is opaque inside http.Transport and not surfaceable without invasive hooks.
//
// The caller's req is never modified — prepareForwardQuery creates an internal
// copy. Callers must NOT pre-copy; that would be a redundant deep copy.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	// {client-name} substitution only applies to DoH/DoH3 where it appears in the
	// URL path. For explicit-dial protocols the RawURL is host:port and substitution
	// there would be a misconfiguration — dialAddrs is always pre-computed correctly.
	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(u.RawURL, "{client-name}", clientName)
	}

	encrypted := u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq"
	fwd := prepareForwardQuery(req, encrypted)

	switch u.Proto {
	case "udp":
		// u.dialAddrs is pre-computed in ParseUpstream — no parseHostPort here.
		client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		var (
			resp *dns.Msg
			err  error
		)
		for _, dialAddr := range u.dialAddrs {
			resp, _, err = client.ExchangeContext(ctx, fwd, dialAddr)
			if err == nil && resp != nil {
				return resp, "udp://"+dialAddr, nil
			}
		}
		return nil, "udp://"+u.RawURL, err

	case "tcp", "dot":
		// u.dialAddrs and u.dialHost are pre-computed in ParseUpstream.
		var lastErr error
		for _, dialAddr := range u.dialAddrs {
			resp, err := u.exchangeStream(ctx, fwd, dialAddr, u.dialHost)
			if err == nil && resp != nil {
				return resp, u.Proto+"://"+dialAddr, nil
			}
			lastErr = err
		}
		return nil, u.Proto+"://"+u.RawURL, lastErr

	case "doh":
		// DoH: actual IP is managed by http.Transport (bootstrap DialContext).
		// Replace "https://" with "doh://" so the log output is consistent with
		// the other protocols and the config file scheme names.
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h2Client)
		return resp, "doh://"+strings.TrimPrefix(targetURL, "https://"), err

	case "doh3":
		// DoH3: same as DoH — actual IP is inside http3.Transport, not surfaceable.
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h3Client)
		return resp, "doh3://"+strings.TrimPrefix(targetURL, "https://"), err

	case "doq":
		// exchangeDoQ uses u.RawURL as pool key and u.dialHost/u.dialAddrs for
		// dialing — no targetURL parameter needed.
		resp, dialAddr, err := u.exchangeDoQ(ctx, fwd)
		return resp, "doq://"+dialAddr, err

	default:
		return nil, targetURL, errors.New("unknown protocol")
	}
}

// --- Staggered Parallel Racing ---

// raceResult is the channel payload for raceExchange goroutines.
type raceResult struct {
	msg  *dns.Msg
	addr string // actual IP:port or URL used (from Exchange second return value)
	up   *Upstream
	err  error
}

// raceExchange sends a DNS query to an upstream group using staggered parallelism.
//
// ALGORITHM (Happy Eyeballs for DNS):
//  1. Launch upstream[0] immediately.
//  2. Wait upstreamStagger (e.g. 150ms). If a response arrives during the wait,
//     return it immediately (fast path — typical for healthy upstreams).
//  3. If no response yet, launch upstream[1] in parallel. Repeat for each upstream.
//  4. First successful response wins. context.WithCancel aborts the losers.
//
// HEALTH-AWARE STAGGER:
//
//	If the *previous* upstream is unhealthy (>=3 consecutive failures), the stagger
//	wait is skipped entirely — the next upstream fires at t=0 alongside the sick one.
//	This means a dead primary adds zero latency from the second query onward.
//
// SEQUENTIAL FALLBACK:
//
//	When upstreamStagger is 0 or the group has only one target, queries are sent
//	sequentially with no goroutine overhead (same as pre-v1.18.0 behaviour).
//
// GOROUTINE SAFETY:
//
//	The channel is buffered to len(upstreams), so losing goroutines can always
//	send their result without blocking even after the winner returns. They'll be
//	GC'd after their transport timeout fires or context cancellation propagates.
func raceExchange(upstreams []*Upstream, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	n := len(upstreams)
	if n == 0 {
		return nil, "", errors.New("no upstreams configured")
	}

	// Fast path: single upstream or sequential mode — no goroutine overhead.
	if n == 1 || upstreamStagger <= 0 {
		return sequentialExchange(upstreams, req, clientName)
	}

	// Staggered parallel path.
	// WithCancel (not WithTimeout): no timer goroutine. Individual transports
	// enforce their own deadlines. Cancel fires only when we have a winner.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch       := make(chan raceResult, n)
	launched := 0

	for i, up := range upstreams {
		// Between launches (except the first), wait for stagger or an early result.
		// Skip the wait if the *previous* upstream is unhealthy — fire immediately
		// so the healthy fallback starts without delay.
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
					// Previous upstream failed fast (e.g. connection refused) —
					// continue launching the next one immediately.
				case <-t.C:
					// Stagger elapsed, no early result — launch next upstream in parallel.
				}
			}
			// If !prevHealthy: skip wait entirely, fire next upstream immediately.
		}

		launched++
		go func(u *Upstream) {
			msg, addr, err := u.Exchange(ctx, req, clientName)
			ch <- raceResult{msg, addr, u, err}
		}(up)
	}

	// All upstreams launched — collect remaining results.
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
// Used when upstreamStagger is 0 or only one upstream exists.
// Zero goroutine overhead — just a plain loop.
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
//
//  1. Deep-copies the message so the caller's original is never modified.
//  2. Assigns a fresh random message ID.
//  3. Strips all EDNS0 options (ECS, cookies, etc.) to prevent identity leakage.
//  4. For encrypted upstreams: adds RFC 7830/8467 padding to the next 128-byte block.
//
// Padding size is calculated from a wire-length estimate rather than a full Pack().
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
		tlsConf            := u.baseTLSConf.Clone()
		tlsConf.ServerName  = tlsHost
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
	smallBufPool.Put(bufPtr)
	if err != nil {
		return nil, err
	}

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

// exchangeDoQ returns the DNS response, the actual IP:port dialled, and any error.
// Uses u.RawURL as the connection pool key and u.dialHost/u.dialAddrs for dialing —
// no targetURL parameter needed since all required values live on the receiver.
func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	key := u.RawURL // stable pool key — u.RawURL never contains {client-name} for DoQ

	if conn := u.takeDoQConn(key); conn != nil {
		resp, err := u.doqStreamExchange(ctx, conn, req)
		if err == nil {
			u.putDoQConn(key, conn)
			// Re-use path: report the raw host:port since the cached conn's original
			// dial address is not tracked after the initial dial.
			return resp, key, nil
		}
		(*conn).CloseWithError(0, "stale")
	}

	newConn, dialAddr, err := u.dialDoQ(u.dialHost, u.dialAddrs)
	if err != nil {
		return nil, key, err
	}
	u.putDoQConn(key, newConn)

	resp, err := u.doqStreamExchange(ctx, newConn, req)
	if err != nil {
		u.removeDoQConn(key)
		(*newConn).CloseWithError(0, "exchange failed")
		return nil, dialAddr, err
	}
	return resp, dialAddr, nil
}

func (u *Upstream) takeDoQConn(key string) *quic.Conn {
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
	return entry.conn
}

func (u *Upstream) putDoQConn(key string, conn *quic.Conn) {
	u.doqMu.Lock()
	if old := u.doqConns[key]; old != nil {
		(*old.conn).CloseWithError(0, "replaced")
	}
	u.doqConns[key] = &doqConnEntry{conn: conn, idleAt: time.Now()}
	u.doqMu.Unlock()
}

func (u *Upstream) removeDoQConn(key string) {
	u.doqMu.Lock()
	delete(u.doqConns, key)
	u.doqMu.Unlock()
}

// dialDoQ tries each dialAddr in order and returns the successful connection
// alongside the address that was actually used. The address is returned so
// callers can log the real IP:port rather than the configured hostname.
func (u *Upstream) dialDoQ(host string, dialAddrs []string) (*quic.Conn, string, error) {
	tlsConf            := getHardenedTLSConfig()
	tlsConf.ServerName  = host
	tlsConf.NextProtos  = []string{"doq"}

	var lastErr error
	for _, dialAddr := range dialAddrs {
		conn, err := quic.DialAddr(context.Background(), dialAddr, tlsConf, &quic.Config{
			Allow0RTT:          true,
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

func (u *Upstream) doqStreamExchange(ctx context.Context, conn *quic.Conn, req *dns.Msg) (*dns.Msg, error) {
	stream, err := (*conn).OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	sBufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*sBufPtr)[:0])
	smallBufPool.Put(sBufPtr)
	if err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := stream.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := stream.Write(packed); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	rBufPtr := largeBufPool.Get().(*[]byte)
	defer largeBufPool.Put(rBufPtr)

	if _, err := io.ReadFull(stream, (*rBufPtr)[:length]); err != nil {
		return nil, err
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack((*rBufPtr)[:length]); err != nil {
		return nil, err
	}
	return dnsResp, nil
}

// --- Shared Helpers ---

// parseHostPort is used only at ParseUpstream time (startup) to pre-compute
// dialHost and dialAddrs. It is no longer called on the query hot path.
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

