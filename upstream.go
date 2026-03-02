/*
File: upstream.go
Version: 1.16.0
Last Updated: 2026-03-02 20:00 CET
Description: Manages connections to external DNS upstream providers.
             Supports UDP, TCP, DoT, DoH (HTTP/2), DoH3 (QUIC/HTTP3), and DoQ.
             TCP and DoT connections are cached and reused across queries to avoid
             repeated handshake overhead. DoH/DoH3 reuse is handled by Go's
             http.Client transport. DoQ reuses QUIC connections with retry-on-stale.

Changes:
  1.16.0 - [PERF] Eliminated redundant dns.Msg.Copy() on the hot path.
           Previously ProcessDNS copied the message before calling Exchange,
           and prepareForwardQuery copied it again — two deep copies per forwarded
           query. Now prepareForwardQuery is the sole copy point and also assigns
           a fresh random message ID, so Exchange receives the original request
           and handles both copying and ID randomisation internally. Saves one
           full dns.Msg deep copy (all RR slices, all sections) per upstream query.
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
	// connections open for 60-120s; 50s is conservative enough to avoid hitting
	// server-side closes while still saving the vast majority of handshakes.
	streamIdleMax = 50 * time.Second

	// streamTimeout is the per-exchange deadline for TCP/DoT write+read.
	streamTimeout = 3 * time.Second

	// doqIdleMax mirrors the MaxIdleTimeout we configure on QUIC connections (5s).
	// Connections idle longer than this are proactively discarded rather than
	// waiting for a failed OpenStreamSync to discover the staleness.
	doqIdleMax = 5 * time.Second
)

// streamConnEntry holds a cached TCP or DoT connection with idle-since tracking.
type streamConnEntry struct {
	conn   *dns.Conn
	idleAt time.Time
}

// doqConnEntry wraps a cached QUIC connection with idle-since tracking.
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

	return u, nil
}

// Exchange forwards a DNS query to this upstream and returns the response.
// The caller's req is never modified — prepareForwardQuery creates an internal
// copy with a fresh random ID and sanitised EDNS0 options. Callers should NOT
// pre-copy the message; doing so would be a redundant deep copy.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(u.RawURL, "{client-name}", clientName)
	}

	// Copy, randomise ID, strip EDNS0, pad encrypted upstreams — all in one shot.
	encrypted := u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq"
	fwd := prepareForwardQuery(req, encrypted)

	switch u.Proto {
	case "udp":
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
			resp, _, err = client.ExchangeContext(ctx, fwd, dialAddr)
			if err == nil && resp != nil {
				return resp, targetURL, nil
			}
		}
		return nil, targetURL, err

	case "tcp", "dot":
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
			resp, err := u.exchangeStream(ctx, fwd, dialAddr, host)
			if err == nil && resp != nil {
				return resp, targetURL, nil
			}
			lastErr = err
		}
		return nil, targetURL, lastErr

	case "doh":
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h2Client)
		return resp, targetURL, err

	case "doh3":
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h3Client)
		return resp, targetURL, err

	case "doq":
		resp, err := u.exchangeDoQ(ctx, fwd, targetURL)
		return resp, targetURL, err

	default:
		return nil, targetURL, errors.New("unknown protocol")
	}
}

// prepareForwardQuery creates a sanitised copy of a DNS query for upstream forwarding:
//
//  1. Deep-copies the message so the caller's original is never modified.
//  2. Assigns a fresh random message ID — never forward the client's original ID.
//  3. Strips all EDNS0 options (ECS, cookies, etc.) to prevent identity leakage.
//  4. For encrypted upstreams: adds RFC 7830/8467 padding to the next 128-byte block.
//
// This is the SOLE copy point for forwarded queries. Callers must not pre-copy.
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
	packed, err := msg.Pack()
	if err != nil {
		return msg
	}

	remainder := len(packed) % blockSize
	var paddingLen int
	if remainder == 0 {
		paddingLen = 0
	} else {
		paddingLen = blockSize - remainder - 4
		if paddingLen < 0 {
			paddingLen += blockSize
		}
	}

	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
		Padding: make([]byte, paddingLen),
	})

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

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, targetURL string) (*dns.Msg, error) {
	host, port := parseHostPort(targetURL, "doq")

	dialAddrs := []string{net.JoinHostPort(host, port)}
	if len(u.BootstrapIPs) > 0 {
		dialAddrs = nil
		for _, ip := range u.BootstrapIPs {
			dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
		}
	}

	conn := u.takeDoQConn(targetURL)
	if conn != nil {
		resp, err := u.doqStreamExchange(ctx, conn, req)
		if err == nil {
			u.putDoQConn(targetURL, conn)
			return resp, nil
		}
		(*conn).CloseWithError(0, "stale")
	}

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

