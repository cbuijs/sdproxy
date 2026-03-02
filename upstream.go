/*
File: upstream.go
Version: 1.15.0
Last Updated: 2026-03-02 18:00 CET
Description: Manages connections to external DNS upstream providers.
             Supports UDP, TCP, DoT, DoH (HTTP/2), DoH3 (QUIC/HTTP3), and DoQ.
             TCP and DoT connections are cached and reused across queries to avoid
             repeated handshake overhead. DoH/DoH3 reuse is handled by Go's
             http.Client transport. DoQ reuses QUIC connections with retry-on-stale.

Changes:
  1.15.0 - [PERF] Connection reuse for TCP and DoT upstreams. One idle connection
           is cached per dial address. TCP queries skip the 3-way handshake; DoT
           queries skip both the TCP and TLS handshakes on cache hit — the TLS
           handshake alone can cost 1-2 RTTs, which dominates latency on embedded
           hardware. Falls back to a fresh dial transparently when the cached
           connection is stale, closed by the server, or idle for too long.
           No upstream capability detection needed: RFC 7766 (TCP), RFC 7858 (DoT),
           and RFC 9250 (DoQ) all mandate persistent connections. If a server
           closes early, the next write fails and we fresh-dial — zero impact.
           [PERF] DoQ retry: when the cached QUIC connection fails to open a new
           stream (server-side close, idle timeout), a fresh connection is dialled
           and the exchange is retried once before giving up. Previously a stale
           DoQ connection would just fail and move to the next upstream in the group.
           [PERF] DoQ idle tracking: cached QUIC connections older than the QUIC
           MaxIdleTimeout are proactively discarded instead of waiting for a failed
           stream open.
  1.14.0 - [FEAT] prepareForwardQuery strips all EDNS0 options from outgoing
           queries to prevent leaking client-specific data (ECS, cookies, etc.)
           to upstream resolvers. For encrypted upstreams (DoT, DoH, DoH3, DoQ),
           RFC 7830 / RFC 8467 DNS padding is added to round the query up to the
           next 128-byte block boundary, making traffic analysis harder.
           OPT record is always preserved (or created) so EDNS0 payload size
           negotiation continues to work on all upstream types.
  1.13.0 - [PERF] Added hasClientNameTemplate bool to Upstream — checked once at
           ParseUpstream time. Avoids scanning RawURL on every DNS query for
           upstreams without {client-name}.
           [PERF] Added baseTLSConf *tls.Config to Upstream for DoT — the hardened
           TLS config is built once at parse time and Clone()'d per connection.
           [PERF] Uses tiered buffer pools: smallBufPool (4KB) for message packing,
           largeBufPool (64KB) for stream/HTTP body reads.
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
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// streamIdleMax is the maximum time a cached TCP/DoT connection may sit idle
	// before it is discarded and a fresh dial is used. Most DNS servers keep TCP
	// connections open for 60–120s; 50s is conservative enough to avoid hitting
	// server-side closes while still saving the vast majority of handshakes.
	streamIdleMax = 50 * time.Second

	// streamTimeout is the per-exchange deadline for TCP/DoT write+read.
	// Matches the previous dns.Client{Timeout: 3s} behaviour.
	streamTimeout = 3 * time.Second

	// doqIdleMax mirrors the MaxIdleTimeout we configure on QUIC connections (5s).
	// Connections idle longer than this are proactively discarded rather than
	// waiting for a failed OpenStreamSync to discover the staleness.
	doqIdleMax = 5 * time.Second
)

// streamConnEntry holds a cached TCP or DoT connection with idle-since tracking.
// Taken out of the pool on use, put back after a successful exchange.
// If exchange fails the connection is closed and discarded — no put-back.
type streamConnEntry struct {
	conn   *dns.Conn
	idleAt time.Time
}

// doqConnEntry wraps a cached QUIC connection with idle-since tracking.
// Unlike TCP/DoT, QUIC connections support concurrent streams so the entry
// stays in the map during use — only removed on connection failure.
type doqConnEntry struct {
	conn   *quic.Conn
	idleAt time.Time
}

type Upstream struct {
	Proto        string
	RawURL       string
	BootstrapIPs []string

	// hasClientNameTemplate is checked once at ParseUpstream time.
	// Avoids scanning RawURL on every DNS query for upstreams without {client-name}.
	hasClientNameTemplate bool

	// baseTLSConf is the pre-built hardened TLS config for DoT upstreams.
	// Clone()'d per connection to set ServerName — much cheaper than rebuilding
	// the full struct + cipher suite + curve slices on every exchange.
	baseTLSConf *tls.Config

	h2Client *http.Client
	h3Client *http.Client

	// streamMu guards streamConns — one idle TCP/DoT connection per dial address.
	// Pattern: take-out on use, put-back after success, close on failure.
	// Concurrent queries to the same dial address: first takes the cached conn,
	// second gets nil and dials fresh. Both put back after success — second put
	// closes the previous, so we never accumulate. Correct for low-concurrency
	// home router workloads.
	streamMu    sync.Mutex
	streamConns map[string]*streamConnEntry

	doqMu    sync.Mutex
	doqConns map[string]*doqConnEntry
}

func ParseUpstream(raw string) (*Upstream, error) {
	u := &Upstream{}

	parts   := strings.Split(raw, "#")
	urlPart := parts[0]
	if len(parts) > 1 {
		u.BootstrapIPs = strings.Split(parts[1], ",")
	}

	// Check once here so Exchange() can skip ReplaceAll for plain upstreams
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
		u.baseTLSConf = getHardenedTLSConfig() // Built once; Clone()'d in dialStream()
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

	return u, nil
}

func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	// Conditional ReplaceAll: skip the scan for the majority of upstreams
	// that don't use {client-name} — checked once at ParseUpstream time.
	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(u.RawURL, "{client-name}", clientName)
	}

	// Strip EDNS0 options and apply RFC 7830 padding for encrypted upstreams.
	encrypted := u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq"
	req = prepareForwardQuery(req, encrypted)

	switch u.Proto {
	case "udp":
		// UDP is connectionless — no reuse applicable. Plain dns.Client per query.
		host, port := parseHostPort(targetURL, u.Proto)

		dialAddrs := []string{net.JoinHostPort(host, port)}
		if len(u.BootstrapIPs) > 0 {
			dialAddrs = nil
			for _, ip := range u.BootstrapIPs {
				dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
			}
		}

		client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		var resp *dns.Msg
		var err  error
		for _, dialAddr := range dialAddrs {
			resp, _, err = client.ExchangeContext(ctx, req, dialAddr)
			if err == nil && resp != nil {
				return resp, targetURL, nil
			}
		}
		return nil, targetURL, err

	case "tcp", "dot":
		// Connection reuse: one idle connection cached per dial address.
		// TCP saves a 3-way handshake per query; DoT saves TCP + TLS handshake
		// (1-2 RTTs) — the dominant latency cost on embedded hardware.
		// Falls back to fresh dial transparently on stale/broken connections.
		host, port := parseHostPort(targetURL, u.Proto)

		dialAddrs := []string{net.JoinHostPort(host, port)}
		if len(u.BootstrapIPs) > 0 {
			dialAddrs = nil
			for _, ip := range u.BootstrapIPs {
				dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
			}
		}

		var lastErr error
		for _, dialAddr := range dialAddrs {
			resp, err := u.exchangeStream(ctx, req, dialAddr, host)
			if err == nil && resp != nil {
				return resp, targetURL, nil
			}
			lastErr = err
		}
		return nil, targetURL, lastErr

	case "doh":
		resp, err := u.exchangeHTTP(ctx, req, targetURL, u.h2Client)
		return resp, targetURL, err

	case "doh3":
		resp, err := u.exchangeHTTP(ctx, req, targetURL, u.h3Client)
		return resp, targetURL, err

	case "doq":
		resp, err := u.exchangeDoQ(ctx, req, targetURL)
		return resp, targetURL, err

	default:
		return nil, targetURL, errors.New("unknown protocol")
	}
}

// --- TCP / DoT Connection Reuse ---

// takeStreamConn removes and returns the cached connection for addr, or nil
// if none exists or the cached entry has been idle too long. Expired connections
// are closed here so callers don't need to handle that case.
func (u *Upstream) takeStreamConn(addr string) *dns.Conn {
	u.streamMu.Lock()
	entry := u.streamConns[addr]
	delete(u.streamConns, addr)
	u.streamMu.Unlock()

	if entry == nil {
		return nil
	}
	if time.Since(entry.idleAt) > streamIdleMax {
		entry.conn.Close() // Idle too long — server likely closed its end already
		return nil
	}
	return entry.conn
}

// putStreamConn stores a connection back into the pool after a successful exchange.
// If another goroutine already stored one (concurrent queries), the old one is closed.
// At most one connection per dial address is kept — fine for home router concurrency.
func (u *Upstream) putStreamConn(addr string, conn *dns.Conn) {
	u.streamMu.Lock()
	if old := u.streamConns[addr]; old != nil {
		old.conn.Close()
	}
	u.streamConns[addr] = &streamConnEntry{conn: conn, idleAt: time.Now()}
	u.streamMu.Unlock()
}

// dialStream opens a fresh TCP or DoT connection to addr.
// For DoT, the pre-built baseTLSConf is Clone()'d and ServerName set to tlsHost.
func (u *Upstream) dialStream(addr, tlsHost string) (*dns.Conn, error) {
	if u.Proto == "dot" {
		tlsConf            := u.baseTLSConf.Clone()
		tlsConf.ServerName  = tlsHost
		return dns.DialTimeoutWithTLS("tcp-tls", addr, tlsConf, streamTimeout)
	}
	return dns.DialTimeout("tcp", addr, streamTimeout)
}

// exchangeStream sends a DNS query over a cached or fresh TCP/DoT connection.
//
// Flow:
//  1. Take cached connection from pool (if any, and not expired).
//  2. Set deadline from context (or fall back to streamTimeout).
//  3. WriteMsg + ReadMsg on the cached connection.
//  4. On success: put connection back for reuse, return response.
//  5. On failure: close broken connection, dial fresh, retry once.
//  6. On second success: put fresh connection back, return response.
//  7. On second failure: close, return error. Next call in the bootstrap loop
//     will try the next dial address.
//
// This pattern means:
//   - Best case: zero handshake, just write+read on a warm connection.
//   - Stale case: one failed write (fast — usually RST), then full fresh dial.
//   - Same total cost as no-reuse in the worst case, strictly better otherwise.
func (u *Upstream) exchangeStream(ctx context.Context, req *dns.Msg, dialAddr, tlsHost string) (*dns.Msg, error) {
	// Derive deadline from parent context if available, otherwise use our own.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	}

	// 1. Try cached connection
	if conn := u.takeStreamConn(dialAddr); conn != nil {
		conn.SetDeadline(deadline)
		if err := conn.WriteMsg(req); err == nil {
			if resp, err := conn.ReadMsg(); err == nil && resp != nil {
				u.putStreamConn(dialAddr, conn)
				return resp, nil
			}
		}
		// Cached connection is broken/stale — close and fall through to fresh dial
		conn.Close()
	}

	// 2. Fresh dial + exchange
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

	// Fresh connection worked — cache it for the next query
	u.putStreamConn(dialAddr, conn)
	return resp, nil
}

// --- HTTP (DoH / DoH3) ---
// Connection reuse is handled internally by Go's http.Transport (HTTP/2 multiplexing)
// and http3.Transport (QUIC multiplexing). No manual pooling needed.

func (u *Upstream) exchangeHTTP(ctx context.Context, req *dns.Msg, targetURL string, client *http.Client) (*dns.Msg, error) {
	// smallBufPool for packing outgoing request — DNS messages are always small
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

	// largeBufPool for reading the response body — size is unknown ahead of time
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
// Connection reuse with retry-on-stale. Unlike TCP/DoT, QUIC connections support
// concurrent streams so the entry stays in the map during use — only removed on
// connection failure. If the cached connection is stale, a fresh one is dialled
// and the exchange retried once before reporting failure.

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, targetURL string) (*dns.Msg, error) {
	host, port := parseHostPort(targetURL, "doq")

	dialAddrs := []string{net.JoinHostPort(host, port)}
	if len(u.BootstrapIPs) > 0 {
		dialAddrs = nil
		for _, ip := range u.BootstrapIPs {
			dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
		}
	}

	// 1. Try cached connection
	conn := u.takeDoQConn(targetURL)
	if conn != nil {
		resp, err := u.doqStreamExchange(ctx, conn, req)
		if err == nil {
			u.putDoQConn(targetURL, conn) // Still good — put back
			return resp, nil
		}
		// Stale — close and fall through to fresh dial
		(*conn).CloseWithError(0, "stale")
	}

	// 2. Fresh dial
	newConn, err := u.dialDoQ(host, dialAddrs)
	if err != nil {
		return nil, err
	}
	u.putDoQConn(targetURL, newConn)

	resp, err := u.doqStreamExchange(ctx, newConn, req)
	if err != nil {
		u.removeDoQConn(targetURL)
		(*newConn).CloseWithError(0, "exchange failed")
		return nil, err
	}
	return resp, nil
}

// takeDoQConn removes and returns the cached QUIC connection for key, or nil
// if none exists or the entry has been idle beyond doqIdleMax.
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

// putDoQConn stores a QUIC connection in the cache, closing any previous entry.
func (u *Upstream) putDoQConn(key string, conn *quic.Conn) {
	u.doqMu.Lock()
	if old := u.doqConns[key]; old != nil {
		(*old.conn).CloseWithError(0, "replaced")
	}
	u.doqConns[key] = &doqConnEntry{conn: conn, idleAt: time.Now()}
	u.doqMu.Unlock()
}

// removeDoQConn deletes the cached entry without closing (caller handles close).
func (u *Upstream) removeDoQConn(key string) {
	u.doqMu.Lock()
	delete(u.doqConns, key)
	u.doqMu.Unlock()
}

// dialDoQ opens a fresh QUIC connection, trying each address in order.
func (u *Upstream) dialDoQ(host string, dialAddrs []string) (*quic.Conn, error) {
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
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// doqStreamExchange opens a QUIC stream on conn, sends the DNS query (with the
// RFC 9250 two-byte length prefix), reads the response, and returns it.
func (u *Upstream) doqStreamExchange(ctx context.Context, conn *quic.Conn, req *dns.Msg) (*dns.Msg, error) {
	stream, err := (*conn).OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// smallBufPool for packing outgoing request
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

	// largeBufPool for reading the response
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

// prepareForwardQuery sanitises a DNS query before forwarding to an upstream:
//
//  1. Strips all EDNS0 options from the OPT record. Client-specific options
//     such as ECS (option 8), DNS Cookies (option 10), and any others must not
//     be leaked to upstream resolvers — they carry client identity information.
//     The OPT record itself is preserved (or created) so EDNS0 payload size
//     negotiation continues to work on all upstream types.
//
//  2. For encrypted upstreams (DoT, DoH, DoH3, DoQ) only: adds RFC 7830 DNS
//     Padding (option 12) to round the query up to the next 128-byte block
//     boundary (per RFC 8467 recommended padding policy). This makes it harder
//     for a passive observer to infer the queried name from packet size alone.
//
// The input message is copied — the original is never modified.
func prepareForwardQuery(req *dns.Msg, encrypted bool) *dns.Msg {
	msg := req.Copy()

	// Find existing OPT record or create one.
	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		msg.Extra = append(msg.Extra, opt)
	}

	// Strip all existing options — removes ECS, cookies, client padding, etc.
	opt.Option = opt.Option[:0]

	if !encrypted {
		return msg
	}

	// RFC 7830 / RFC 8467: pad to the next 128-byte block boundary.
	// Pack the message as-is first to measure its current wire size, then
	// calculate how many padding bytes are needed.
	// The EDNS0 padding option header itself costs 4 bytes (2 option code +
	// 2 length), so we subtract that from the available padding budget.
	const blockSize = 128
	packed, err := msg.Pack()
	if err != nil {
		return msg // Packing failed — return without padding rather than dropping
	}

	remainder := len(packed) % blockSize
	var paddingLen int
	if remainder == 0 {
		paddingLen = 0 // Already on a block boundary — no padding needed
	} else {
		paddingLen = blockSize - remainder - 4 // 4 = padding option header size
		if paddingLen < 0 {
			// Subtracting the header pushed us past the boundary — go to the next block
			paddingLen += blockSize
		}
	}

	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
		Padding: make([]byte, paddingLen),
	})

	return msg
}

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

