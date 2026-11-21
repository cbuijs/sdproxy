/*
File:    server.go
Version: 1.45.0 (Split)
Last Updated: 05-Nov-2026 18:10 CET

Description: 
  DNS Request handlers and response writers for TCP, DoT, DoH, and DoQ.
  Listener initialization has been extracted into server_init.go, leaving this
  file purely focused on translating transport protocols into ProcessDNS payloads.

Changes:
  1.45.0  - [SECURITY/FIX] Added standard HTTP security headers (`X-Content-Type-Options`,
            `Cache-Control: no-store`, and `Strict-Transport-Security`) to `dohResponseWriter`
            and rejected zero-length DoQ messages (`length == 0`) before allocation.
  1.44.0  - [SECURITY/FIX] Preserved `dns.ConnectionStater` on `tlsHandshakeConn`
            in `handleDoT` so TLS SNI (`sni:`) and `+ECH` status detection work
            with `tlsHandshakeListener` (`server_init.go` 1.24.0).
  1.43.0  - [FIX] Guarded `[SECURITY]` log lines in `handleDoH` and `handleDoQConnection`
            with `if logSystem` so `logging.log_system: false` is respected consistently.
  1.42.0  - [SECURITY/FIX] Restored `localAddr` propagation natively across DoH and DoQ 
            multiplexers.
  1.41.0  - [SECURITY/FIX] Completely eradicated buffer exhaustion crashes natively 
            within `dohResponseWriter` and `doqResponseWriter`.
  1.40.0  - [SECURITY/FIX] handleDoH accepted a POST body of any media type.
  1.39.0  - [SECURITY/FIX] Guarded the DoQ response length prefix against uint16
            wraparound (audit item S-C).
  1.38.0  - [SECURITY/FIX] Hardened the DoH POST body reader against a spin.
  1.37.0  - [SECURITY/FIX] Bounded DoQ stream fan-out.
  1.36.0  - [SECURITY/FIX] Repaired the source-address extraction that fed the
            fail-open admission hole closed in process_security.go 1.15.0.
*/

package main

import (
	"context"
	"crypto/tls"
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
	maxDoQStreamsPerConn = 64
	doqSheddingErrorCode = 0
)

const dohMediaType = "application/dns-message"

var doqStreamSem chan struct{}

func initDoQStreamBudget(maxConns int) {
	budget := maxConns * 4
	if budget < maxDoQStreamsPerConn {
		budget = maxDoQStreamsPerConn
	}
	doqStreamSem = make(chan struct{}, budget)
}

func acquireDoQStream(connSem chan struct{}) bool {
	select {
	case connSem <- struct{}{}:
	default:
		return false
	}

	if doqStreamSem == nil {
		return true
	}

	select {
	case doqStreamSem <- struct{}{}:
		return true
	default:
		<-connSem
		return false
	}
}

func releaseDoQStream(connSem chan struct{}) {
	if doqStreamSem != nil {
		<-doqStreamSem
	}
	<-connSem
}

var doqShedLastLog atomic.Int64

var dohMediaTypeLastLog atomic.Int64

// ---------------------------------------------------------------------------
// Source address extraction
// ---------------------------------------------------------------------------

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
	return s
}

func dohRemoteHost(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isDoHMediaType(v string) bool {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.EqualFold(strings.TrimSpace(v), dohMediaType)
}

// --- Protocol handlers ---

func handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	ip := remoteIPFromAddr(w.RemoteAddr())
	ProcessDNS(w, r, ip, "TCP", "", "")
}

func handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	ip := remoteIPFromAddr(w.RemoteAddr())
	var sni string
	proto := "DoT"
	var state *tls.ConnectionState
	if cs, ok := w.(dns.ConnectionStater); ok {
		state = cs.ConnectionState()
	}
	if state == nil {
		if rw, ok := w.(interface{ Conn() net.Conn }); ok {
			if tc, ok := rw.Conn().(interface{ ConnectionState() tls.ConnectionState }); ok {
				st := tc.ConnectionState()
				state = &st
			}
		}
	}
	if state != nil {
		sni = state.ServerName
		if state.ECHAccepted {
			proto += "+ECH"
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
		if !isDoHMediaType(r.Header.Get("Content-Type")) {
			r.Body.Close()

			now := time.Now().UnixNano()
			last := dohMediaTypeLastLog.Load()
			if now-last > int64(60*time.Second) && dohMediaTypeLastLog.CompareAndSwap(last, now) {
				if logSystem {
					log.Printf("[SECURITY] Rejected a DoH POST from %s with Content-Type %q; RFC 8484 requires %q. "+
						"Legitimate DoH clients always set it — an unexpected type here is either a misconfigured client "+
						"or an attempt to reach this endpoint from a browser page.",
						dohRemoteHost(r), r.Header.Get("Content-Type"), dohMediaType)
				}
			}

			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		bufPtr := largeBufPool.Get().(*[]byte)
		buf := *bufPtr
		n := 0

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
			if n == len(buf) {
				var dummy [1]byte
				if extra, _ := r.Body.Read(dummy[:]); extra > 0 {
					largeBufPool.Put(bufPtr)
					r.Body.Close()
					host := dohRemoteHost(r)
					var parsedAddr netip.Addr
					if a, err := netip.ParseAddr(host); err == nil {
						parsedAddr = a.Unmap()
					}
					PenalizeClient(host, parsedAddr, -1)
					http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				break
			}
		}

		r.Body.Close()

		payload = make([]byte, n)
		copy(payload, buf[:n])
		largeBufPool.Put(bufPtr)

	case http.MethodGet:
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

	var localAddr net.Addr
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		localAddr = la
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

	ProcessDNS(&dohResponseWriter{w: w, remoteIP: host, localAddr: localAddr}, msg, host, proto, sni, path)
}

func handleDoQConnection(conn *quic.Conn) {
	host := remoteIPFromAddr(conn.RemoteAddr())

	localAddr := conn.LocalAddr()

	var sni string
	cs := conn.ConnectionState()
	sni = cs.TLS.ServerName
	proto := "DoQ"
	if cs.TLS.ECHAccepted {
		proto += "+ECH"
	}

	connStreamSem := make(chan struct{}, maxDoQStreamsPerConn)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		if !acquireDoQStream(connStreamSem) {
			stream.CancelRead(doqSheddingErrorCode)
			stream.CancelWrite(doqSheddingErrorCode)

			now := time.Now().UnixNano()
			last := doqShedLastLog.Load()
			if now-last > int64(60*time.Second) && doqShedLastLog.CompareAndSwap(last, now) {
				if logSystem {
					log.Printf("[SECURITY] DoQ stream shed from %s: stream capacity reached "+
						"(per-connection limit %d, global limit %d). Excess streams are reset; clients will retry.",
						host, maxDoQStreamsPerConn, cap(doqStreamSem))
				}
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

			s.SetReadDeadline(time.Now().Add(5 * time.Second))

			var lenBuf [2]byte
			if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf[:])
			if length == 0 {
				return
			}

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
			ProcessDNS(&doqResponseWriter{stream: s, remoteIP: host, localAddr: localAddr}, msg, host, proto, sni, "")
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
	w         http.ResponseWriter
	remoteIP  string
	localAddr net.Addr
}

func (dw *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := largeBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	if err != nil {
		largeBufPool.Put(bufPtr)
		return err
	}
	hdr := dw.w.Header()
	hdr.Set("Content-Type", dohMediaType)
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	_, err = dw.w.Write(packed)
	largeBufPool.Put(bufPtr)
	return err
}

func (dw *dohResponseWriter) LocalAddr() net.Addr          { return dw.localAddr }
func (dw *dohResponseWriter) RemoteAddr() net.Addr         { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *dohResponseWriter) Write(b []byte) (int, error)  { return dw.w.Write(b) }
func (dw *dohResponseWriter) Close() error                 { return nil }
func (dw *dohResponseWriter) TsigStatus() error            { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(bool)          {}
func (dw *dohResponseWriter) Hijack()                      {}

type doqResponseWriter struct {
	stream    *quic.Stream
	remoteIP  string
	localAddr net.Addr
}

func (dw *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := largeBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	if err != nil {
		largeBufPool.Put(bufPtr)
		return err
	}

	if len(packed) > 65535 {
		oversize := len(packed)

		truncated := new(dns.Msg)
		truncated.SetReply(msg)
		truncated.Truncated = true
		truncated.Answer = nil
		truncated.Ns = nil
		truncated.Extra = nil

		tPacked, tErr := truncated.PackBuffer((*bufPtr)[:0])
		if tErr != nil {
			largeBufPool.Put(bufPtr)
			return tErr
		}
		packed = tPacked

		if logSystem {
			log.Printf("[SECURITY] DoQ response to %s exceeded the RFC 9250 length prefix (%d bytes); replaced with an empty TC=1 answer so the client retries.",
				dw.remoteIP, oversize)
		}
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))

	dw.stream.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if _, err = dw.stream.Write(lenBuf[:]); err != nil {
		largeBufPool.Put(bufPtr)
		return err
	}
	_, err = dw.stream.Write(packed)
	largeBufPool.Put(bufPtr)
	return err
}

func (dw *doqResponseWriter) LocalAddr() net.Addr          { return dw.localAddr }
func (dw *doqResponseWriter) RemoteAddr() net.Addr         { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *doqResponseWriter) Write(b []byte) (int, error)  { return dw.stream.Write(b) }
func (dw *doqResponseWriter) Close() error                 { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error            { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(bool)          {}
func (dw *doqResponseWriter) Hijack()                      {}
