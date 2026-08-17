/*
File:    server.go
Version: 1.40.0 (Split)
Last Updated: 07-Aug-2026 21:30 CEST

Description: 
  DNS Request handlers and response writers for TCP, DoT, DoH, and DoQ.
  Listener initialization has been extracted into server_init.go, leaving this
  file purely focused on translating transport protocols into ProcessDNS payloads.

Changes:
  1.40.0  - [SECURITY/FIX] handleDoH accepted a POST body of any media type.
            RFC 8484 §4.1 requires application/dns-message on both request and
            response, and the handler already sets it correctly on the way out —
            it simply never checked the way in.

            The consequence is not a parsing problem (msg.Unpack rejects
            anything that is not a DNS wire message) but a CSRF one. Because
            application/dns-message is NOT one of the three media types a
            browser may send cross-origin without a preflight
            (application/x-www-form-urlencoded, multipart/form-data,
            text/plain), requiring it makes an unpreflighted cross-origin POST
            structurally impossible. Without the check, any page on the internet
            could make a visitor's browser POST attacker-chosen bytes to a
            reachable sdproxy DoH endpoint as a simple request, using the
            resolver as a blind, credential-free request forwarder against
            whatever its upstream policy allows. Wire-format DNS is trivially
            expressible as a text/plain body.
            Unknown types now get 415 and no resolution. Deliberately not a
            penalty strike: a wrong Content-Type is a misconfigured client far
            more often than an attack, and PenalizeClient issues instant bans.
            GET is unaffected — it carries its payload in ?dns= and has never
            had a request body to type.
  1.39.0  - [SECURITY/FIX] Guarded the DoQ response length prefix against uint16
            wraparound (audit item S-C). doqResponseWriter.WriteMsg framed every
            reply with an unchecked `uint16(len(packed))`, so a payload larger
            than 65.535 bytes announced its length modulo 65.536 and then wrote
            the full body behind it.
            The failure mode is not a dropped answer but a DESYNCHRONISED
            STREAM: the peer consumes the announced octet count and parses the
            remainder as the beginning of the next framed message, so every
            later exchange on that stream is read from the wrong offset. On a
            shared QUIC connection that is indistinguishable from an on-path
            attacker splicing responses — and a hostile upstream can deliberately
            manufacture the oversized answer we would relay.
            Oversized responses are now re-emitted as an empty TC=1 reply, which
            is the signal DNS already defines for "retry me on a transport that
            can carry this". Returning a bare error instead would have left the
            client with no response and no explanation, which is strictly worse.
            The sibling sites are fixed in upstream_net.go 1.31.0 (outbound DoQ)
            and upstream_ddr.go 2.51.0 (DDR discovery probes).
  1.38.0  - [SECURITY/FIX] Hardened the DoH POST body reader against a spin.
            The loop advanced only on a non-zero read and treated `readErr == nil`
            as "keep going", so a reader legitimately returning (0, nil) — which
            io.Reader explicitly permits, and which HTTP/2 and HTTP/3 flow
            control can produce between DATA frames — put the goroutine into a
            tight, un-yielding loop burning a core until the client disconnected
            or the server write deadline fired. A handful of such requests is
            enough to saturate a small router's CPU.
            Added a zero-progress counter: consecutive no-progress reads are
            tolerated up to a small bound (they are legal and transient) and then
            treated as a stalled body. The offender is penalised exactly like the
            oversized-payload case, since a peer trickling nothing is a slow-read
            attack whether or not it ever sends another byte.
  1.37.0  - [SECURITY/FIX] Bounded DoQ stream fan-out. handleDoQConnection
            spawned one unbounded goroutine per accepted QUIC stream, so the
            only ceiling was QUIC flow control: MaxIncomingStreams (1000 before
            server_init.go 1.19.0) multiplied by max_tcp_connections (250 by
            default) admitted a theoretical 250.000 concurrent handler
            goroutines. Worse, each one allocated its stack, a dns.Msg and the
            full payload buffer BEFORE AcquireQuery — the adaptive admission
            gate — ever saw the traffic, so the throttler could not protect
            anything. activeDoQConns correctly bounded *connections*; nothing
            bounded *streams*.
            Two non-blocking semaphores now gate goroutine creation: a
            per-connection cap (maxDoQStreamsPerConn) so a single abusive peer
            cannot monopolise the process, and a global cap (doqStreamSem,
            sized in server_init.go) so the aggregate across all peers stays
            bounded. Excess streams are reset immediately rather than queued —
            shedding matches the existing AcquireQuery philosophy, and blocking
            the accept loop instead would create head-of-line blocking for the
            well-behaved streams behind the abusive one.
  1.36.0  - [SECURITY/FIX] Repaired the source-address extraction that fed the
            fail-open admission hole closed in process_security.go 1.15.0.
            handleTCP and handleDoT both performed a bare
            `w.RemoteAddr().(*net.TCPAddr)` type assertion and, on failure,
            silently left the client IP as the empty string. handleDoH fell back
            to the raw `r.RemoteAddr` — which still carries a port — whenever
            net.SplitHostPort failed, producing a string that cannot survive
            netip.ParseAddr either. In both cases the downstream pipeline
            received an address it could not evaluate.
            Introduced remoteIPFromAddr(), a single type-agnostic extractor now
            used by every transport in this file and by both UDP listener
            variants (server_udp_linux.go 1.5.0, server_udp_stub.go 1.3.0). It
            handles the concrete net.Addr types directly, then degrades to a
            SplitHostPort parse of the string form rather than to nothing.
  1.356.0 - [SECURITY/FIX] Eradicated a critical Memory Corruption and Payload Contamination 
            vulnerability within the DoH and DoQ transport unpackers. Enforced strict 
            deep-copy isolation on `sync.Pool` byte arrays prior to executing `miekg/dns` 
            Unpack sequences natively. Prevents concurrent threads from overwriting retained 
            EDNS0/DNSSEC slices mapping back to the actively pooled memory blocks.
            (Version string reset to the 1.3x series in 1.36.0; the 1.356.0 label
            was a typo for 1.35.6 that had propagated through several releases.)
  1.35.0  - [SECURITY/FIX] Addressed a critical Slow-Read (Slowloris) DoS vulnerability 
            within the DoQ stream writer natively. Implemented a rigid 5-second 
            `SetWriteDeadline` prior to transmitting the payload. Definitively prevents 
            malicious clients from intentionally starving Goroutine capacities by 
            refusing to acknowledge byte allocations on the socket stream.
  1.34.0  - [SECURITY/FIX] Eradicated a critical Slow-Read / Slow-Loris Denial 
            of Service vulnerability within the DoQ (DNS over QUIC) stream unpacker. 
            Instantiated strict 5-second `ReadDeadline` boundaries directly on 
            the ephemeral streams natively. Ensures attackers cannot silently 
            exhaust Goroutine pools by abandoning unfulfilled connection channels.
*/

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ---------------------------------------------------------------------------
// DoQ stream admission bounds
// ---------------------------------------------------------------------------

const (
	// maxDoQStreamsPerConn caps concurrently-executing stream handlers for a
	// SINGLE DoQ connection.
	//
	// RFC 9250 mandates one query per stream, and a stream's handler lives only
	// as long as that one exchange. A legitimate stub resolver pipelines a
	// handful of lookups at a time; 64 leaves an enormous margin over real
	// client behaviour while ensuring one peer cannot convert its connection
	// into a goroutine factory.
	maxDoQStreamsPerConn = 64

	// doqSheddingErrorCode is the QUIC application error code returned when a
	// stream is refused for capacity reasons. Zero is the conventional
	// "no error / unspecified" value; the peer simply observes the stream being
	// reset and retries, exactly as it would on any transient DNS failure.
	doqSheddingErrorCode = 0
)

// dohMediaType is the media type RFC 8484 §4.1 mandates for DNS-over-HTTPS
// request and response bodies.
//
// [SECURITY 1.40.0] Enforcing this on the REQUEST is a CSRF control, not a
// pedantry. The HTML fetch/XHR specifications let a page issue a cross-origin
// POST without a CORS preflight only when the body's media type is one of
// application/x-www-form-urlencoded, multipart/form-data, or text/plain.
// application/dns-message is none of those, so demanding it means a browser
// cannot be induced to submit a DNS query to this endpoint on behalf of a
// visitor without the endpoint's explicit CORS consent — which sdproxy does not
// grant.
//
// Without the check, any page could use a reachable sdproxy as a blind
// forwarder: wire-format DNS bytes are perfectly expressible as a text/plain
// body, the browser attaches the victim's source address, and the resolver
// answers under whatever ACL and upstream policy that address is entitled to.
const dohMediaType = "application/dns-message"

// doqStreamSem bounds DoQ stream handlers process-wide, across every connection
// and every DoQ listener.
//
// [SECURITY 1.37.0] The per-connection cap alone is insufficient: 250 connections
// × 64 streams is still 16.000 goroutines. This is the aggregate ceiling, sized
// in StartServers() from max_tcp_connections. It is intentionally a package-level
// channel rather than a field so that multiple DoQ listen addresses share one
// budget — the machine has one goroutine scheduler, not one per listener.
//
// Nil until initDoQStreamBudget() runs. acquireDoQStream() treats nil as
// "unbounded", which keeps the handler usable in tests that never boot the
// listener stack.
var doqStreamSem chan struct{}

// initDoQStreamBudget sizes the global DoQ stream semaphore. Called once from
// StartServers() before any listener is bound.
func initDoQStreamBudget(maxConns int) {
	// 4× the connection ceiling. Enough that a fully-loaded, entirely legitimate
	// client population never touches the limit, small enough that the worst
	// case is a four-figure goroutine count rather than a six-figure one.
	budget := maxConns * 4
	if budget < maxDoQStreamsPerConn {
		budget = maxDoQStreamsPerConn
	}
	doqStreamSem = make(chan struct{}, budget)
}

// acquireDoQStream reserves one slot in both the per-connection and the global
// budget. Returns false when either is saturated, having released anything it
// already took.
//
// Deliberately non-blocking. Blocking here would stall the connection's accept
// loop, so one saturated peer would delay the streams queued behind it and
// convert a capacity problem into a latency problem for everyone on that
// connection. A refused DNS query is retried in milliseconds; a stalled one is not.
func acquireDoQStream(connSem chan struct{}) bool {
	select {
	case connSem <- struct{}{}:
	default:
		return false
	}

	if doqStreamSem == nil {
		return true // Budget never initialised (unit tests) — per-conn cap only.
	}

	select {
	case doqStreamSem <- struct{}{}:
		return true
	default:
		<-connSem // Roll back the per-connection reservation.
		return false
	}
}

// releaseDoQStream returns a slot to both budgets. Must mirror every successful
// acquireDoQStream call exactly once.
func releaseDoQStream(connSem chan struct{}) {
	if doqStreamSem != nil {
		<-doqStreamSem
	}
	<-connSem
}

// doqShedLastLog debounces the capacity-shedding notice to one line per minute,
// so a stream flood cannot be turned into a log-write flood.
var doqShedLastLog atomic.Int64

// dohMediaTypeLastLog debounces the RFC 8484 media-type rejection notice.
//
// A misconfigured client retries relentlessly, and an attacker probing the
// endpoint would otherwise convert the diagnostic into unbounded disk I/O. One
// line per minute is enough for an operator to see the problem and identify the
// offending source.
var dohMediaTypeLastLog atomic.Int64

// ---------------------------------------------------------------------------
// Source address extraction
// ---------------------------------------------------------------------------

// remoteIPFromAddr renders any net.Addr a transport hands us as a bare IP
// literal suitable for netip.ParseAddr, or "" when the address genuinely
// carries no IP at all.
//
// [SECURITY 1.36.0] This exists because the previous per-handler pattern —
// a bare type assertion to one concrete type, with an empty string on failure —
// silently produced unidentifiable clients. Downstream, an unidentifiable
// client used to bypass the ACL and the rate limiter outright.
//
// The concrete types are handled first because they are the overwhelmingly
// common case and reading v.IP avoids formatting a string only to reparse it.
// The String()+SplitHostPort path then covers wrapped, proxied, or
// implementation-specific addresses (quic-go internals, test doubles, future
// transports) instead of discarding them.
//
// Note the deliberate absence of a nil-IP shortcut to "": a *net.TCPAddr with a
// nil IP formats as ":<port>", and SplitHostPort correctly yields "" for it, so
// the fall-through remains honest either way.
func remoteIPFromAddr(a net.Addr) string {
	if a == nil {
		return ""
	}

	switch v := a.(type) {
	case *net.UDPAddr:
		if v.IP != nil {
			return v.IP.String()
		}
	case *net.TCPAddr:
		if v.IP != nil {
			return v.IP.String()
		}
	case *net.IPAddr:
		if v.IP != nil {
			return v.IP.String()
		}
	}

	s := a.String()
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	// No port present — the string is already a bare host/IP literal.
	return s
}

// dohRemoteHost extracts the bare client IP from an *http.Request.
//
// net/http hands RemoteAddr over as a pre-formatted "host:port" string rather
// than a net.Addr, so this cannot reuse remoteIPFromAddr directly. The failure
// mode it fixes is the same one: the previous inline fallback assigned the raw
// r.RemoteAddr — port included — which no address parser downstream accepts.
//
// Deliberately does NOT consult X-Forwarded-For or any similar header. Those are
// attacker-controlled on a directly reachable listener, and honouring them here
// would hand every client a trivial ACL-, rate-limit- and penalty-box-evasion
// primitive. Reverse-proxy deployments must terminate in front of sdproxy and
// preserve the transport-level peer address.
func dohRemoteHost(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// isDoHMediaType reports whether a Content-Type header value names the RFC 8484
// DNS message media type.
//
// [SECURITY 1.40.0] Parsing is done by hand rather than through mime.ParseMediaType
// because this runs on the request hot path and the grammar we need is trivial:
// take everything before the first ';' (dropping any parameters such as an
// erroneous charset), trim surrounding whitespace, and fold case. Media types
// and subtypes are case-insensitive per RFC 9110 §8.3.1, so a client sending
// "Application/DNS-Message" is conforming and must be accepted.
//
// An empty header is rejected along with everything else. RFC 8484 §4.1 states
// the client MUST set it, and the whole value of the check comes from the fact
// that a browser cannot set it cross-origin without a preflight — an exemption
// for "unset" would be an exemption for exactly the request shape being
// defended against, since a cross-origin fetch with no explicit Content-Type
// still sends one of the three simple types.
func isDoHMediaType(v string) bool {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.EqualFold(strings.TrimSpace(v), dohMediaType)
}

// --- Protocol handlers ---

func handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	// [SECURITY 1.36.0] Type-agnostic extraction; a failed assertion no longer
	// degrades the client into an unidentifiable (and formerly unpoliced) origin.
	ip := remoteIPFromAddr(w.RemoteAddr())
	ProcessDNS(w, r, ip, "TCP", "", "")
}

func handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	// [SECURITY 1.36.0] See handleTCP.
	ip := remoteIPFromAddr(w.RemoteAddr())
	var sni string
	proto := "DoT"
	if cs, ok := w.(dns.ConnectionStater); ok {
		if state := cs.ConnectionState(); state != nil {
			sni = state.ServerName
			if state.ECHAccepted {
				proto += "+ECH"
			}
		}
	}
	ProcessDNS(w, r, ip, proto, sni, "")
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	var (
		payload []byte
		err     error
	)

	switch r.Method {
	case http.MethodPost:
		// ── [SECURITY 1.40.0] RFC 8484 §4.1 media-type gate ──────────────
		//
		// Checked BEFORE a single byte of the body is read, so a request that
		// will be refused never gets to occupy a 64KB pool buffer or to run the
		// read loop at all.
		//
		// See the dohMediaType and isDoHMediaType comments for why this is a
		// CSRF control rather than a conformance nicety: it is what makes an
		// unpreflighted cross-origin POST to this endpoint structurally
		// impossible from a browser.
		if !isDoHMediaType(r.Header.Get("Content-Type")) {
			r.Body.Close()

			now := time.Now().UnixNano()
			last := dohMediaTypeLastLog.Load()
			if now-last > int64(60*time.Second) && dohMediaTypeLastLog.CompareAndSwap(last, now) {
				log.Printf("[SECURITY] Rejected a DoH POST from %s with Content-Type %q; RFC 8484 requires %q. "+
					"Legitimate DoH clients always set it — an unexpected type here is either a misconfigured client "+
					"or an attempt to reach this endpoint from a browser page.",
					dohRemoteHost(r), r.Header.Get("Content-Type"), dohMediaType)
			}

			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		bufPtr := largeBufPool.Get().(*[]byte)
		buf    := *bufPtr
		n := 0

		// [SECURITY 1.38.0] Zero-progress guard.
		//
		// io.Reader is explicitly permitted to return (0, nil), and HTTP/2 and
		// HTTP/3 readers do so in practice while waiting between DATA frames.
		// The previous loop had no term that advanced in that case, so such a
		// peer span this goroutine at 100% CPU with no yield point until the
		// connection died. The limit is generous — legitimate zero reads come in
		// ones and twos, never in the hundreds — so this only ever fires on a
		// body that has genuinely stalled.
		const maxZeroReads = 64
		zeroReads := 0

		for {
			c, readErr := r.Body.Read(buf[n:])
			n += c
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				largeBufPool.Put(bufPtr)
				r.Body.Close()
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}

			if c == 0 {
				zeroReads++
				if zeroReads > maxZeroReads {
					largeBufPool.Put(bufPtr)
					r.Body.Close()
					// A body that yields nothing, repeatedly, without erroring is
					// a slow-read attack in every meaningful sense. Treat it as
					// one: same penalty as an oversized payload.
					host := dohRemoteHost(r)
					var parsedAddr netip.Addr
					if a, err := netip.ParseAddr(host); err == nil {
						parsedAddr = a.Unmap()
					}
					PenalizeClient(host, parsedAddr, -1)
					http.Error(w, "Request body stalled", http.StatusRequestTimeout)
					return
				}
			} else {
				zeroReads = 0
			}
			// Detect infinite stream exhaustion attacks
			// without false-positively dropping perfectly sized 64KB payloads.
			if n == len(buf) {
				var dummy [1]byte
				if extra, _ := r.Body.Read(dummy[:]); extra > 0 {
					largeBufPool.Put(bufPtr)
					r.Body.Close()
					// [SECURITY 1.36.0] dohRemoteHost strips the port instead of
					// falling back to the raw port-bearing RemoteAddr, which then
					// failed netip.ParseAddr and left the offender unpunishable.
					host := dohRemoteHost(r)
					var parsedAddr netip.Addr
					if a, err := netip.ParseAddr(host); err == nil {
						parsedAddr = a.Unmap()
					}
					PenalizeClient(host, parsedAddr, -1) // Instant Blackhole Ban
					http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				break // Payload is exactly 64KB, fully intact
			}
		}
		
		r.Body.Close()
		
		// [SECURITY/FIX] Enforce strict deep copy for the extracted payload array.
		// `miekg/dns` retains memory slices from the unpacked array organically. 
		// Deep copying guarantees that recycling the buffer back to the `largeBufPool` 
		// does not trigger volatile memory corruption across concurrent threads natively.
		payload = make([]byte, n)
		copy(payload, buf[:n])
		largeBufPool.Put(bufPtr)

	case http.MethodGet:
		// No media-type gate here: GET carries its payload in the ?dns= query
		// parameter and has no request body to type. The CSRF exposure the POST
		// gate closes does not exist for GET either — a cross-origin GET cannot
		// read the response without CORS consent, and this endpoint grants none.
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}

		const maxB64Len = 87500
		if len(b64) > maxB64Len {
			host := dohRemoteHost(r)
			var parsedAddr netip.Addr
			if a, err := netip.ParseAddr(host); err == nil {
				parsedAddr = a.Unmap()
			}
			PenalizeClient(host, parsedAddr, -1)
			http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
			return
		}

		b64 = strings.TrimRight(b64, "=")
		payload, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "Invalid base64 payload", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		host := dohRemoteHost(r)
		var parsedAddr netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			parsedAddr = a.Unmap()
		}
		PenalizeClient(host, parsedAddr, -1) 
		http.Error(w, "Malformed DNS payload", http.StatusBadRequest)
		return
	}

	host := dohRemoteHost(r)

	var localIP net.IP
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if localHost, _, err := net.SplitHostPort(la.String()); err == nil {
			localIP = net.ParseIP(localHost)
		}
	}

	proto := "DoH"
	if r.ProtoMajor == 3 || strings.HasPrefix(r.Proto, "HTTP/3") {
		proto = "DoH3"
	}
	
	var sni string
	if r.TLS != nil {
		sni = r.TLS.ServerName
		if r.TLS.ECHAccepted {
			proto += "+ECH"
		}
	}
	path := r.URL.Path

	ProcessDNS(&dohResponseWriter{w: w, remoteIP: host, localIP: localIP}, msg, host, proto, sni, path)
}

func handleDoQConnection(conn *quic.Conn) {
	// [SECURITY 1.36.0] Unified extraction; the old inline SplitHostPort fallback
	// returned a port-bearing string that could not be parsed downstream.
	host := remoteIPFromAddr(conn.RemoteAddr())

	var localIP net.IP
	if localHost, _, err := net.SplitHostPort(conn.LocalAddr().String()); err == nil {
		localIP = net.ParseIP(localHost)
	}
	
	var sni string
	cs := conn.ConnectionState()
	sni = cs.TLS.ServerName
	proto := "DoQ"
	if cs.TLS.ECHAccepted {
		proto += "+ECH"
	}

	// Per-connection stream budget. Scoped to this connection so it dies with
	// it — no cleanup path to forget, no map of live connections to maintain.
	connStreamSem := make(chan struct{}, maxDoQStreamsPerConn)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		// [SECURITY 1.37.0] Reserve capacity BEFORE spawning. Prior to this the
		// goroutine, its stack, the dns.Msg and the payload buffer were all
		// allocated before AcquireQuery could reject anything, which made the
		// adaptive throttler structurally unable to defend this transport.
		if !acquireDoQStream(connStreamSem) {
			// Reset both directions so the peer learns immediately rather than
			// waiting on an idle timeout, then move on. The client retries.
			stream.CancelRead(doqSheddingErrorCode)
			stream.CancelWrite(doqSheddingErrorCode)

			now := time.Now().UnixNano()
			last := doqShedLastLog.Load()
			if now-last > int64(60*time.Second) && doqShedLastLog.CompareAndSwap(last, now) {
				log.Printf("[SECURITY] DoQ stream shed from %s: stream capacity reached "+
					"(per-connection limit %d, global limit %d). Excess streams are reset; clients will retry.",
					host, maxDoQStreamsPerConn, cap(doqStreamSem))
			}
			continue
		}

		go func(s *quic.Stream) {
			defer releaseDoQStream(connStreamSem)
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] Recovered in DoQ stream handler: %v", r)
				}
			}()
			defer s.Close()

			// Enforce strict Read Deadlines on individual DoQ streams natively.
			// Completely neutralizes Slow-Read/Slow-Loris DoS attacks.
			s.SetReadDeadline(time.Now().Add(5 * time.Second))

			var lenBuf [2]byte
			if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf[:])

			// [SECURITY/FIX] Execute O(1) precise array allocations securely organically.
			// Replaces dynamic `largeBufPool` slices. The exact message length is designated 
			// by the structural DoQ envelope, rendering buffer-pooling entirely obsolete and 
			// eradicating active pool-contamination vectors during the unpacked execution cycle.
			payload := make([]byte, length)

			if _, err := io.ReadFull(s, payload); err != nil {
				return
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(payload); err != nil {
				var parsedAddr netip.Addr
				if a, err := netip.ParseAddr(host); err == nil {
					parsedAddr = a.Unmap()
				}
				PenalizeClient(host, parsedAddr, -1) 
				return
			}
			ProcessDNS(&doqResponseWriter{stream: s, remoteIP: host, localIP: localIP}, msg, host, proto, sni, "")
		}(stream)
	}
}

// --- Helpers ---

func buildAltSvc(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "443" 
	}
	return `h3=":` + port + `"; ma=86400`
}

// --- Response Writer Adapters ---

type dohResponseWriter struct {
	w        http.ResponseWriter
	remoteIP string
	localIP  net.IP
}

func (dw *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return err
	}
	dw.w.Header().Set("Content-Type", dohMediaType)
	_, err = dw.w.Write(packed)
	smallBufPool.Put(bufPtr)
	return err
}

func (dw *dohResponseWriter) LocalAddr() net.Addr {
	if dw.localIP == nil {
		return nil
	}
	return &net.IPAddr{IP: dw.localIP}
}
func (dw *dohResponseWriter) RemoteAddr() net.Addr        { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *dohResponseWriter) Write(b []byte) (int, error) { return dw.w.Write(b) }
func (dw *dohResponseWriter) Close() error                { return nil }
func (dw *dohResponseWriter) TsigStatus() error           { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(bool)         {}
func (dw *dohResponseWriter) Hijack()                     {}

type doqResponseWriter struct {
	stream   *quic.Stream 
	remoteIP string
	localIP  net.IP
}

func (dw *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return err
	}

	// ── [SECURITY/FIX 1.39.0] 16-bit length-prefix guard (S-C) ───────────────
	//
	// RFC 9250 frames every DoQ message with a two-octet big-endian length, so
	// the payload has a hard 65.535-byte ceiling. The conversion below used to
	// be an unguarded uint16(len(packed)): a larger payload wrapped modulo
	// 65.536 and announced a length far shorter than the bytes that followed.
	//
	// That is not a dropped answer, it is a DESYNCHRONISED STREAM. The peer
	// reads the announced number of octets, treats the remainder as the start
	// of the next framed message, and every subsequent exchange on that stream
	// is parsed from the wrong offset. On a shared QUIC connection this is
	// indistinguishable from an on-path attacker splicing responses, and a
	// crafted oversized answer is the kind of thing a hostile upstream can
	// deliberately arrange for us to relay.
	//
	// Reaching 64 KB requires a large signed RRset or a fat SVCB/HTTPS answer —
	// unusual, but entirely producible, which is precisely the profile of a bug
	// that never shows up in testing and then shows up in production.
	//
	// The remedy is the one DNS already defines for "this will not fit":
	// re-emit as an empty truncated answer so the client retries over a
	// transport that can carry it. Deliberately NOT a plain error return —
	// that would leave the client with no response at all and no signal about
	// why, which is strictly worse than a correct TC=1.
	if len(packed) > 65535 {
		// Capture the offending size BEFORE packed is reassigned, or the log
		// line reports the size of the replacement rather than of the payload
		// that triggered the guard.
		oversize := len(packed)

		truncated := new(dns.Msg)
		truncated.SetReply(msg)
		truncated.Truncated = true
		truncated.Answer = nil
		truncated.Ns = nil
		truncated.Extra = nil

		tPacked, tErr := truncated.PackBuffer((*bufPtr)[:0])
		if tErr != nil {
			smallBufPool.Put(bufPtr)
			return tErr
		}
		packed = tPacked

		log.Printf("[SECURITY] DoQ response to %s exceeded the RFC 9250 length prefix (%d bytes); replaced with an empty TC=1 answer so the client retries.",
			dw.remoteIP, oversize)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))

	// Enforce explicit Write Deadlines natively to thwart Slow-Read DoS.
	// Prevents malicious clients from stalling the stream and starving goroutine pools.
	dw.stream.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if _, err = dw.stream.Write(lenBuf[:]); err != nil {
		smallBufPool.Put(bufPtr)
		return err
	}
	_, err = dw.stream.Write(packed)
	smallBufPool.Put(bufPtr)
	return err
}

func (dw *doqResponseWriter) LocalAddr() net.Addr {
	if dw.localIP == nil {
		return nil
	}
	return &net.IPAddr{IP: dw.localIP}
}
func (dw *doqResponseWriter) RemoteAddr() net.Addr        { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *doqResponseWriter) Write(b []byte) (int, error) { return dw.stream.Write(b) }
func (dw *doqResponseWriter) Close() error                { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error           { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(bool)         {}
func (dw *doqResponseWriter) Hijack()                     {}
