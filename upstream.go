/*
File: upstream.go
Version: 1.30.0
Last Updated: 2026-03-09 18:00 CET
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
  1.30.0 - [FIX] {client-name} in DoT/DoQ hostnames no longer requires bootstrap
           IPs. The {client-name} token is a local substitution (ARP/DHCP/hosts)
           and is never resolved via DNS. What needs resolving is the upstream
           server hostname itself — e.g. "*.dns.controld.com" — which resolves
           to the same set of IPs regardless of the per-device prefix. Added
           resolveDialAddrs() method: lazily resolves the effective hostname on
           first use per unique expanded host string, using per-URL bootstrap IPs
           first, then globalBootstrapServers, then OS resolver as fallback.
           Results are cached in a sync.Map (effectiveHost -> []dialAddr string)
           for the process lifetime — server IPs don't change on home networks.
           Removed the ParseUpstream fatal-error for {client-name}+no-bootstrap.
           The hasPlaceholderDialAddr flag marks upstreams that need runtime
           resolution (hasClientNameTemplate && no per-URL bootstrap IPs &&
           dialHost is not a bare IP). Non-{client-name} upstreams are unaffected.
  1.29.0 - [FIX] prepareForwardQuery: SetUDPSize always called; msg.Extra rebuilt
           from scratch (strips non-OPT records); msg.Len() used for accurate
           padding; zero-padding option skipped when already aligned.
           [FEAT] Global bootstrap servers: bootstrapResolve() resolves upstream
           hostnames at startup when no per-URL bootstrap IPs are present.
  1.28.0 - [FIX] DoQ 0-RTT: RFC 9250 §10.5 prohibits DNS messages as 0-RTT data.
           Added doqNo0RTT atomic.Bool — latched on DOQ_PROTOCOL_ERROR.
  1.27.0 - [FIX] doqStreamExchange: stream.Close() before io.ReadFull (FIN first).
  1.26.0 - [FEAT] DoQ per-upstream connection pool with idle-timeout eviction.
  1.25.0 - [FIX] putDoQConn called after successful exchange only (race fix).
  1.24.0 - [FEAT] DoH3 (HTTP/3 over QUIC) transport support.
  1.23.0 - [FEAT] Health tracking: consFails atomic, stagger skipped when sick.
  1.22.0 - [FEAT] {client-name} substitution in DoT/DoQ hostnames at query time.
  1.21.0 - [FEAT] Staggered parallel racing (raceExchange).
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	streamTimeout   = 5 * time.Second
	streamIdleMax   = 30 * time.Second
	doqIdleMax      = 25 * time.Second
	healthThreshold = int32(3)
)

// upstreamStagger is set once at startup from cfg.Server.UpstreamStaggerMs.
var upstreamStagger time.Duration

type streamConnEntry struct {
	conn   *dns.Conn
	idleAt time.Time
}

// doqConnEntry holds a pooled QUIC connection.
// dialAddr is the actual IP:port that was dialled — preserved for logging.
type doqConnEntry struct {
	conn     *quic.Conn
	dialAddr string
	idleAt   time.Time
}

// Upstream represents a single parsed and initialised upstream DNS target.
type Upstream struct {
	Proto                 string
	RawURL                string
	BootstrapIPs          []string // per-URL bootstrap IPs — always take precedence
	hasClientNameTemplate bool

	// dialHost: static hostname used for TLS SNI — may contain {client-name},
	//           which is substituted with the real client name at query time.
	// dialAddrs: pre-computed IP:port dial targets, always ready after
	//            ParseUpstream returns. For {client-name} hostnames without
	//            per-URL bootstrap IPs, these are resolved at startup by
	//            substituting "bootstrap" for {client-name} (see ParseUpstream).
	dialHost  string
	dialAddrs []string

	udpClient *dns.Client

	streamConns map[string]*streamConnEntry
	streamMu    sync.Mutex
	baseTLSConf *tls.Config

	h2Client *http.Client
	h3Client *http.Client

	doqConns map[string]*doqConnEntry
	doqMu    sync.Mutex

	// consFails counts consecutive failures. Reset to 0 on any success.
	consFails atomic.Int32

	// doqNo0RTT is latched to true on DOQ_PROTOCOL_ERROR (RFC 9250 §10.5).
	// All subsequent dials use Allow0RTT: false. Never reset.
	doqNo0RTT atomic.Bool
}

func (u *Upstream) recordSuccess() { u.consFails.Store(0) }
func (u *Upstream) recordFailure() { u.consFails.Add(1) }
func (u *Upstream) isHealthy() bool { return u.consFails.Load() < healthThreshold }

// ParseUpstream parses a raw upstream URL string into an initialised Upstream.
//
// URL format:  scheme://host[:port][/path][#{bootstrap_ip,...}]
//
// Per-URL bootstrap IPs (after #) bypass DNS for the upstream hostname itself.
// They always take precedence over globalBootstrapServers.
//
// {client-name} in the URL is a *local* substitution — the token is replaced
// at query time with a name derived from ARP, DHCP leases, or hosts files.
// It is never resolved via DNS. What may need resolving is the upstream server
// hostname itself, which happens lazily via resolveDialAddrs() on first use.
func ParseUpstream(raw string) (*Upstream, error) {
	u := &Upstream{}

	parts   := strings.Split(raw, "#")
	urlPart := parts[0]
	if len(parts) > 1 && parts[1] != "" {
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
				// DialContext uses u.BootstrapIPs at connection time, picking up
				// both per-URL and global-bootstrap-resolved IPs.
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

	// Set dialHost and initial dialAddrs for stream-based protocols.
	switch u.Proto {
	case "udp", "tcp", "dot", "doq":
		host, port := parseHostPort(u.RawURL, u.Proto)
		u.dialHost  = host
		if len(u.BootstrapIPs) > 0 {
			// Per-URL bootstrap IPs provided — use them directly, no DNS needed.
			u.dialAddrs = make([]string, len(u.BootstrapIPs))
			for i, ip := range u.BootstrapIPs {
				u.dialAddrs[i] = net.JoinHostPort(ip, port)
			}
		} else {
			// No per-URL bootstrap IPs. May be overwritten below.
			u.dialAddrs = []string{net.JoinHostPort(host, port)}
		}
	}

	// --- Bootstrap resolution ---
	//
	// Runs when no per-URL bootstrap IPs were provided. Resolves the upstream
	// hostname at startup so dialAddrs contains real IPs rather than a name.
	//
	// For hostnames containing {client-name}: the literal string "bootstrap" is
	// substituted to form a concrete, resolvable name for this step — e.g.
	// "prefix-{client-name}-ams.dns.controld.com" becomes
	// "prefix-bootstrap-ams.dns.controld.com". All per-device variants of such
	// hostnames resolve to the same server IPs (routing is SNI-based server-side),
	// so one resolution covers all clients. The "bootstrap" label also appears
	// clearly in startup logs, making the purpose immediately obvious.
	//
	// After resolution, dialAddrs is rebuilt with the real IPs so it is ready
	// to use at query time without any further DNS lookups.
	// dialHost is left as the original template — {client-name} is substituted
	// with the real client name at query time for TLS SNI.
	if len(u.BootstrapIPs) == 0 {
		var resolveHost string
		switch u.Proto {
		case "udp", "tcp", "dot", "doq":
			if net.ParseIP(u.dialHost) == nil {
				// Substitute "bootstrap" for {client-name} if present, so we
				// always have a concrete hostname to resolve.
				resolveHost = strings.ReplaceAll(u.dialHost, "{client-name}", "bootstrap")
			}
		case "doh", "doh3":
			// Extract hostname from "https://hostname/path...".
			rest := strings.TrimPrefix(u.RawURL, "https://")
			if idx := strings.IndexByte(rest, '/'); idx >= 0 {
				rest = rest[:idx]
			}
			if h, _, err := net.SplitHostPort(rest); err == nil {
				rest = h
			}
			if net.ParseIP(rest) == nil {
				resolveHost = strings.ReplaceAll(rest, "{client-name}", "bootstrap")
			}
		}

		if resolveHost != "" {
			var ips []string
			if len(globalBootstrapServers) > 0 {
				ips = bootstrapResolve(resolveHost, globalBootstrapServers)
			}
			if len(ips) > 0 {
				u.BootstrapIPs = ips
				log.Printf("[INIT] Bootstrap: %s -> %v", resolveHost, ips)
				// Rebuild dialAddrs for stream protocols with the resolved IPs.
				if u.dialHost != "" {
					_, port := parseHostPort(u.RawURL, u.Proto)
					u.dialAddrs = make([]string, len(ips))
					for i, ip := range ips {
						u.dialAddrs[i] = net.JoinHostPort(ip, port)
					}
				}
			} else {
				// No bootstrap servers configured, or resolution failed.
				// Replace the template in dialAddrs with the concrete "bootstrap"
				// hostname so the OS resolver gets a real name at dial time,
				// not a literal "{client-name}" placeholder.
				if u.dialHost != "" && strings.Contains(u.dialHost, "{client-name}") {
					_, port := parseHostPort(u.RawURL, u.Proto)
					u.dialAddrs = []string{net.JoinHostPort(resolveHost, port)}
				}
				log.Printf("[WARN] Bootstrap: could not resolve %s — OS resolver will be used at dial time", resolveHost)
			}
		}
	}

	return u, nil
}

// Exchange forwards a DNS query to this upstream and returns the response.
// The second return value is a loggable string combining protocol and address.
// The caller's req is never modified — prepareForwardQuery creates an internal copy.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	if !AcquireUpstream() {
		return nil, u.Proto + "://" + u.RawURL, errors.New("upstream throttled: concurrency limit reached")
	}
	defer ReleaseUpstream()

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
				return resp, "udp://" + dialAddr, nil
			}
		}
		return nil, "udp://" + u.RawURL, err

	case "tcp", "dot":
		// Substitute {client-name} in the hostname for TLS SNI.
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}
		var lastErr error
		for _, dialAddr := range u.dialAddrs {
			resp, err := u.exchangeStream(ctx, fwd, dialAddr, effectiveHost)
			if err == nil && resp != nil {
				return resp, u.Proto + "://" + dialAddr, nil
			}
			lastErr = err
		}
		return nil, u.Proto + "://" + u.RawURL, lastErr

	case "doh":
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h2Client)
		return resp, "doh://" + strings.TrimPrefix(targetURL, "https://"), err

	case "doh3":
		resp, err := u.exchangeHTTP(ctx, fwd, targetURL, u.h3Client)
		return resp, "doh3://" + strings.TrimPrefix(targetURL, "https://"), err

	case "doq":
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}
		resp, dialAddr, err := u.exchangeDoQ(ctx, fwd, effectiveHost)
		return resp, "doq://" + dialAddr, err

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
// is launched after a delay. First successful response wins; losers are canceled.
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
			if upstreams[i-1].isHealthy() {
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

// prepareForwardQuery creates a sanitised copy of a DNS query for upstream
// forwarding: fresh random ID, EDNS0 options stripped, UDP size normalised,
// non-OPT Extra records removed, and optional RFC 7830/8467 padding added.
func prepareForwardQuery(req *dns.Msg, encrypted bool) *dns.Msg {
	msg   := req.Copy()
	msg.Id = dns.Id()

	// Find or create the EDNS0 OPT pseudo-RR.
	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
	}

	// Always normalise to 4096 regardless of what the client sent — forwarding
	// the client's value leaks implementation details to the upstream.
	opt.SetUDPSize(4096)

	// Strip all EDNS0 options from the client (ECS, cookies, DAU, etc.).
	opt.Option = opt.Option[:0]

	// Rebuild Extra with ONLY the OPT record. Other Extra records (TSIG, SIG(0))
	// are client-to-resolver artefacts that must not be forwarded upstream.
	msg.Extra = msg.Extra[:0]
	msg.Extra = append(msg.Extra, opt)

	if !encrypted {
		return msg
	}

	// RFC 7830 / RFC 8467 padding for encrypted transports (DoT, DoH, DoQ).
	// Pad to the nearest 128-byte boundary to obscure query length on the wire.
	//
	// Adding a padding option costs 4 bytes of overhead (2 option-code + 2 length).
	// So we need: (msg.Len() + 4 + paddingLen) % 128 == 0
	// → paddingLen = 128 - ((msg.Len() + 4) % 128)
	//
	// Special case: when (msg.Len() + 4) % 128 == 0 the message is already
	// aligned — skip the option entirely rather than adding a zero-length field.
	//
	// msg.Len() returns the exact wire-format byte count (correct label encoding),
	// avoiding the ~1-byte-per-label error of hand-rolled string-length estimates.
	const blockSize = 128
	if mod := (msg.Len() + 4) % blockSize; mod != 0 {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{
			Padding: make([]byte, blockSize-mod),
		})
	}

	return msg
}

// bootstrapResolve sends plain-UDP A and AAAA queries for host to each server
// in servers. Returns a deduplicated list of IP strings. Called at startup
// (for non-{client-name} hostnames) and at first query time (for {client-name}
// hostnames). Blocking is acceptable in both cases.
func bootstrapResolve(host string, servers []string) []string {
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	fqdn   := dns.Fqdn(host)
	seen   := make(map[string]struct{})
	var ips []string

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)
		m.RecursionDesired = true
		for _, srv := range servers {
			resp, _, err := client.Exchange(m, srv)
			if err != nil || resp == nil {
				continue
			}
			for _, rr := range resp.Answer {
				var s string
				switch rec := rr.(type) {
				case *dns.A:
					s = rec.A.String()
				case *dns.AAAA:
					s = rec.AAAA.String()
				}
				if s != "" {
					if _, dup := seen[s]; !dup {
						seen[s] = struct{}{}
						ips = append(ips, s)
					}
				}
			}
			break // got a valid response; move to next qtype
		}
	}
	return ips
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
	if err != nil {
		smallBufPool.Put(bufPtr)
		return nil, err
	}
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
// host is the fully expanded hostname ({client-name} already substituted).
// It is used as both the TLS SNI and the connection-pool key.
// Dial addresses are obtained via resolveDialAddrs — handles bootstrap/OS/cache.
func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, host string) (*dns.Msg, string, error) {
	key      := host

	if entry := u.takeDoQConn(key); entry != nil {
		resp, err := u.doqStreamExchange(ctx, entry.conn, req)
		if err == nil {
			u.putDoQConn(key, entry.conn, entry.dialAddr)
			return resp, entry.dialAddr, nil
		}
		(*entry.conn).CloseWithError(0, "stale")
	}

	newConn, dialAddr, err := u.dialDoQ(host, u.dialAddrs)
	if err != nil {
		return nil, u.RawURL, err
	}

	resp, err := u.doqStreamExchange(ctx, newConn, req)
	if err != nil {
		(*newConn).CloseWithError(0, "exchange failed")

		// RFC 9250 §10.5: latch doqNo0RTT on DOQ_PROTOCOL_ERROR, retry once.
		var appErr *quic.ApplicationError
		if errors.As(err, &appErr) && appErr.ErrorCode == 0x2 && appErr.Remote && !u.doqNo0RTT.Load() {
			u.doqNo0RTT.Store(true)
			log.Printf("[DoQ] %s: DOQ_PROTOCOL_ERROR on 0-RTT — disabling 0-RTT, retrying", host)
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

func (u *Upstream) putDoQConn(key string, conn *quic.Conn, dialAddr string) {
	u.doqMu.Lock()
	if old := u.doqConns[key]; old != nil {
		(*old.conn).CloseWithError(0, "replaced")
	}
	u.doqConns[key] = &doqConnEntry{conn: conn, dialAddr: dialAddr, idleAt: time.Now()}
	u.doqMu.Unlock()
}

// dialDoQ dials a fresh QUIC connection to any of addrs.
// Respects doqNo0RTT — uses 1-RTT after the first DOQ_PROTOCOL_ERROR.
// quic.DialAddr / quic.DialAddrEarly both return *quic.Conn directly.
func (u *Upstream) dialDoQ(host string, addrs []string) (*quic.Conn, string, error) {
	tlsConf           := getHardenedTLSConfig().Clone()
	tlsConf.NextProtos = []string{"doq"}
	tlsConf.ServerName = host

	no0RTT := u.doqNo0RTT.Load()
	qConf  := &quic.Config{
		Allow0RTT:          !no0RTT,
		MaxIdleTimeout:     doqIdleMax,
		MaxIncomingStreams: 10,
	}

	for _, addr := range addrs {
		var (
			conn *quic.Conn
			err  error
		)
		if !no0RTT {
			conn, err = quic.DialAddrEarly(context.Background(), addr, tlsConf, qConf)
		} else {
			conn, err = quic.DialAddr(context.Background(), addr, tlsConf, qConf)
		}
		if err == nil {
			return conn, addr, nil
		}
	}
	return nil, "", fmt.Errorf("doq: all dial addresses failed for %s", host)
}

// doqStreamExchange opens a single QUIC stream, writes the DNS query with a
// 2-byte length prefix (RFC 9250 §4.2), closes the write side first (FIN),
// then reads the response. stream.Close() before ReadFull is required —
// strict servers wait for the write-side FIN before sending the response.
func (u *Upstream) doqStreamExchange(ctx context.Context, conn *quic.Conn, req *dns.Msg) (*dns.Msg, error) {
	stream, err := (*conn).OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CancelRead(0) // clean up read side on any error path

	packed, err := req.Pack()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(packed)))
	copy(buf[2:], packed)

	if _, err := stream.Write(buf); err != nil {
		return nil, err
	}
	// Send write-side FIN BEFORE reading — strict DoQ servers stall otherwise.
	if err := stream.Close(); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 {
		return nil, errors.New("doq: zero-length response")
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		return nil, err
	}
	return resp, nil
}

// --- Helpers ---

// parseHostPort splits an upstream URL fragment (host or host:port) into
// host and port strings. When no port is present, returns the protocol default.
func parseHostPort(raw, proto string) (host, port string) {
	defaults := map[string]string{
		"udp": "53", "tcp": "53", "dot": "853", "doq": "853",
	}
	h, p, err := net.SplitHostPort(raw)
	if err != nil {
		return raw, defaults[proto]
	}
	return h, p
}

