/*
File: server.go
Version: 1.17.0
Last Updated: 2026-03-04 14:00 CET
Description: High-performance listeners for UDP, TCP, DoT, DoH (HTTP/1.1 + HTTP/2),
             DoH3 (QUIC), and DoQ. Aggressive timeouts to conserve memory on embedded
             targets. Supports RFC 8484 GET and POST for DoH.

Changes:
  1.17.0 - [PERF] dohResponseWriter and doqResponseWriter now store localIP as
           net.IP instead of string. Previously LocalAddr() called net.ParseIP on
           every invocation. localIP is set once at connection setup time (per HTTP
           request / per QUIC connection) so the parse cost moves there — one call
           per connection instead of one call per DDR query on that connection.
  1.16.0 - [FIX] dohResponseWriter and doqResponseWriter now implement a working
           LocalAddr() instead of returning nil. This enables process.go's ddrAddrs()
           to fall back to the query's interface address for DDR spoofing when no
           explicit IPs are configured in the DDR config section.
           dohResponseWriter gains a localIP string field populated from the HTTP
           request context key http.LocalAddrContextKey — this is set by net/http
           for every incoming connection and gives the listener address the TLS/HTTP
           handshake arrived on. doqResponseWriter gains the same field, populated
           from conn.LocalAddr() in handleDoQConnection before the stream loop.
  1.15.0 - [PERF] UDP worker pool is now conditional on listen_udp being non-empty.
           When no UDP listeners are configured the goroutine pool and its buffered
           channel are never allocated, saving cfg.Server.UDPWorkers goroutines and
           a (UDPWorkers*10)-deep channel. handleUDP is safe with a nil udpQueue
           because the select default branch fires immediately — queries are dropped
           rather than causing a nil-channel block or panic.
  1.14.0 - [PERF] DoH POST handler: eliminated unnecessary alloc+copy.
  1.13.0 - [FIX]  DoH listener now correctly supports HTTP/1.1 alongside HTTP/2.
           Cloned TLS config with NextProtos restricted to ["h2", "http/1.1"].
  1.12.0 - [FIX]  Separated handleTCP and handleDoT handler functions.
           [FIX]  Added clean graceful shutdown via shutdownCh channel.
           [PERF] Tiered buffer pools: smallBufPool (4KB) and largeBufPool (64KB).
  1.11.0 - Added full HTTP GET and POST support for DoH/DoH3 clients.
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
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type udpJob struct {
	w dns.ResponseWriter
	r *dns.Msg
}

var (
	udpQueue     chan udpJob
	shutdownCh   = make(chan struct{}) // Closed by Shutdown() to signal all workers
	shutdownOnce sync.Once
)

// Shutdown signals all UDP worker goroutines to exit cleanly.
// Safe to call multiple times (sync.Once). Call from main() on SIGTERM.
func Shutdown() {
	shutdownOnce.Do(func() {
		close(shutdownCh)
	})
}

func StartServers(tlsConf *tls.Config) {
	const (
		tcpReadTimeout  = 2 * time.Second
		tcpWriteTimeout = 2 * time.Second
		tcpIdleTimeout  = 10 * time.Second
	)

	// 0. Bounded UDP worker pool — only allocated when UDP listeners are configured.
	// Skipped entirely when listen_udp is empty, saving UDPWorkers goroutines and a
	// (UDPWorkers*10)-slot channel. handleUDP's select default branch makes a nil
	// udpQueue safe: incoming jobs are dropped rather than blocking or panicking.
	if len(cfg.Server.ListenUDP) > 0 {
		udpQueue = make(chan udpJob, cfg.Server.UDPWorkers*10)
		for i := 0; i < cfg.Server.UDPWorkers; i++ {
			go func() {
				for {
					select {
					case job, ok := <-udpQueue:
						if !ok {
							return
						}
						var ip string
						if addr, ok := job.w.RemoteAddr().(*net.UDPAddr); ok {
							ip = addr.IP.String()
						}
						ProcessDNS(job.w, job.r, ip, "UDP")
					case <-shutdownCh:
						return
					}
				}
			}()
		}
		log.Printf("[LISTEN] UDP Worker Pool: %d routines", cfg.Server.UDPWorkers)
	}

	// 1. DNS over UDP
	for _, addr := range cfg.Server.ListenUDP {
		addr := addr
		go func() {
			server := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(handleUDP)}
			log.Printf("[LISTEN] UDP on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] UDP failed on %s: %v", addr, err)
			}
		}()
	}

	// 2. DNS over TCP
	for _, addr := range cfg.Server.ListenTCP {
		addr := addr
		go func() {
			server := &dns.Server{
				Addr:         addr,
				Net:          "tcp",
				Handler:      dns.HandlerFunc(handleTCP),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			log.Printf("[LISTEN] TCP on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] TCP failed on %s: %v", addr, err)
			}
		}()
	}

	// 3. DNS over TLS (DoT)
	for _, addr := range cfg.Server.ListenDoT {
		addr := addr
		go func() {
			server := &dns.Server{
				Addr:         addr,
				Net:          "tcp-tls",
				TLSConfig:    tlsConf,
				Handler:      dns.HandlerFunc(handleDoT),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			log.Printf("[LISTEN] DoT on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] DoT failed on %s: %v", addr, err)
			}
		}()
	}

	// 4. DNS over HTTPS (DoH/HTTP1.1 + HTTP/2) + DNS over HTTP/3 (DoH3/QUIC)
	for _, addr := range cfg.Server.ListenDoH {
		addr := addr
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", handleDoH)

		// Clone the shared TLS config and restrict ALPN to HTTP-only tokens.
		// The shared tlsConf carries "doq" and "dot" which cause strict HTTP/1.1
		// clients to reject the handshake — the HTTP server needs its own clone.
		dohTLS            := tlsConf.Clone()
		dohTLS.NextProtos  = []string{"h2", "http/1.1"}

		h2Server := &http.Server{
			Addr:           addr,
			Handler:        mux,
			TLSConfig:      dohTLS,
			ReadTimeout:    tcpReadTimeout,
			WriteTimeout:   tcpWriteTimeout,
			IdleTimeout:    tcpIdleTimeout,
			MaxHeaderBytes: 8192,
		}
		go func() {
			log.Printf("[LISTEN] DoH (HTTP/1.1 + HTTP/2) on %s", addr)
			if err := h2Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[FATAL] DoH failed on %s: %v", addr, err)
			}
		}()

		h3Server := &http3.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: tlsConf,
			QUICConfig: &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				MaxIncomingStreams: 50,
			},
		}
		go func() {
			log.Printf("[LISTEN] DoH3 (QUIC) on %s", addr)
			if err := h3Server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] DoH3 failed on %s: %v", addr, err)
			}
		}()
	}

	// 5. DNS over QUIC (DoQ) — RFC 9250
	for _, addr := range cfg.Server.ListenDoQ {
		addr := addr
		go func() {
			doqTLS           := tlsConf.Clone()
			doqTLS.NextProtos = []string{"doq"}
			listener, err := quic.ListenAddr(addr, doqTLS, &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				MaxIncomingStreams: 50,
			})
			if err != nil {
				log.Fatalf("[FATAL] DoQ failed on %s: %v", addr, err)
			}
			log.Printf("[LISTEN] DoQ on %s", addr)
			for {
				conn, err := listener.Accept(context.Background())
				if err != nil {
					continue
				}
				go handleDoQConnection(conn)
			}
		}()
	}
}

func handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	// udpQueue is nil when no listen_udp addresses are configured.
	// The default branch drops the query safely without blocking.
	select {
	case udpQueue <- udpJob{w: w, r: r}:
	case <-shutdownCh:
	default:
	}
}

func handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}
	ProcessDNS(w, r, ip, "TCP")
}

func handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}
	ProcessDNS(w, r, ip, "DoT")
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	var (
		payload []byte
		err     error
	)

	switch r.Method {
	case http.MethodPost:
		// largeBufPool: incoming body size is unknown (could be a large DNS request).
		// dns.Msg.Unpack creates independent copies of all fields — it never aliases
		// its input buffer. The pool buffer lives until function return (defer), so
		// unpacking directly from it is safe. No need to alloc+copy out of the pool.
		bufPtr := largeBufPool.Get().(*[]byte)
		buf    := *bufPtr
		defer largeBufPool.Put(bufPtr)

		n  := 0
		lr := io.LimitReader(r.Body, int64(len(buf)))
		for {
			c, readErr := lr.Read(buf[n:])
			n += c
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
		}
		r.Body.Close()
		payload = buf[:n]

	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
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
		http.Error(w, "Malformed DNS payload", http.StatusBadRequest)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Extract and immediately parse the local listener IP from the HTTP request
	// context. net/http sets http.LocalAddrContextKey for every incoming connection.
	// Parsing here (once per request) instead of inside LocalAddr() (once per DDR
	// query on that connection) moves the net.ParseIP cost to where it fires once.
	var localIP net.IP
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if localHost, _, err := net.SplitHostPort(la.String()); err == nil {
			localIP = net.ParseIP(localHost)
		}
	}

	proto := "DoH"
	if r.Proto == "HTTP/3.0" {
		proto = "DoH3"
	}

	ProcessDNS(&dohResponseWriter{w: w, remoteIP: host, localIP: localIP}, msg, host, proto)
}

func handleDoQConnection(conn *quic.Conn) {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Parse the local listener IP once per connection. Stored as net.IP in
	// doqResponseWriter so LocalAddr() can return it directly without parsing.
	var localIP net.IP
	if localHost, _, err := net.SplitHostPort(conn.LocalAddr().String()); err == nil {
		localIP = net.ParseIP(localHost)
	}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(s *quic.Stream) {
			defer s.Close()

			var lenBuf [2]byte
			if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf[:])

			bufPtr := largeBufPool.Get().(*[]byte)
			buf    := *bufPtr
			defer largeBufPool.Put(bufPtr)

			if _, err := io.ReadFull(s, buf[:length]); err != nil {
				return
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:length]); err != nil {
				return
			}
			ProcessDNS(&doqResponseWriter{stream: s, remoteIP: host, localIP: localIP}, msg, host, "DoQ")
		}(stream)
	}
}

// --- Response Writer Adapters ---

// dohResponseWriter wraps http.ResponseWriter as a dns.ResponseWriter for DoH/DoH3.
// localIP holds the listener interface address parsed once at request setup time
// and exposed via LocalAddr() so process.go's ddrAddrs() can use it for the
// DDR interface-IP fallback when no explicit IPs are configured in ddr.ipv4/ipv6.
type dohResponseWriter struct {
	w        http.ResponseWriter
	remoteIP string
	localIP  net.IP // pre-parsed in handleDoH, nil when listener addr is unavailable
}

func (dw *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	smallBufPool.Put(bufPtr)
	if err != nil {
		return err
	}
	dw.w.Header().Set("Content-Type", "application/dns-message")
	_, err = dw.w.Write(packed)
	return err
}
func (dw *dohResponseWriter) LocalAddr() net.Addr {
	if dw.localIP == nil {
		return nil
	}
	return &net.IPAddr{IP: dw.localIP}
}
func (dw *dohResponseWriter) RemoteAddr() net.Addr         { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *dohResponseWriter) Write(b []byte) (int, error)  { return dw.w.Write(b) }
func (dw *dohResponseWriter) Close() error                 { return nil }
func (dw *dohResponseWriter) TsigStatus() error            { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(bool)          {}
func (dw *dohResponseWriter) Hijack()                      {}

// doqResponseWriter wraps a QUIC stream as a dns.ResponseWriter for DoQ.
// localIP holds the listener interface address parsed once per QUIC connection in
// handleDoQConnection and shared across all streams on that connection. Exposed via
// LocalAddr() for the same DDR fallback purpose as dohResponseWriter.
type doqResponseWriter struct {
	stream   *quic.Stream
	remoteIP string
	localIP  net.IP // pre-parsed in handleDoQConnection, nil when unavailable
}

func (dw *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	smallBufPool.Put(bufPtr)
	if err != nil {
		return err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := dw.stream.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = dw.stream.Write(packed)
	return err
}
func (dw *doqResponseWriter) LocalAddr() net.Addr {
	if dw.localIP == nil {
		return nil
	}
	return &net.IPAddr{IP: dw.localIP}
}
func (dw *doqResponseWriter) RemoteAddr() net.Addr         { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *doqResponseWriter) Write(b []byte) (int, error)  { return dw.stream.Write(b) }
func (dw *doqResponseWriter) Close() error                 { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error            { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(bool)          {}
func (dw *doqResponseWriter) Hijack()                      {}

