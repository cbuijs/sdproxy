/*
File: server.go
Version: 1.12.0
Last Updated: 2026-03-01 14:00 CET
Description: High-performance listeners for UDP, TCP, DoT, DoH (HTTP/2),
             DoH3 (QUIC), and DoQ. Aggressive timeouts to conserve memory
             on embedded targets. Supports RFC 8484 GET and POST for DoH.

Changes:
  1.12.0 - [FIX]  Separated handleTCP and handleDoT handler functions. The original
           code registered handleTCP for both plain TCP and DoT, logging "TCP" for
           all TLS connections. DoT connections now correctly log "DoT".
           [FIX]  Replaced the always-false TLS detection branch with a proper
           separate handler registration. miekg/dns doesn't expose TLS state
           through ResponseWriter, so the only reliable fix is a separate handler.
           [FIX]  Added clean graceful shutdown via shutdownCh channel. The previous
           implementation had no way to signal UDP worker goroutines to exit,
           causing goroutine leaks on SIGTERM. Workers now exit cleanly via select.
           [PERF] Uses tiered buffer pools: smallBufPool (4KB) for message packing,
           largeBufPool (64KB) for body reads where message size is unknown.
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
	// 0. Bounded UDP worker pool with clean shutdown support
	udpQueue = make(chan udpJob, cfg.Server.UDPWorkers*10)
	for i := 0; i < cfg.Server.UDPWorkers; i++ {
		go func() {
			for {
				select {
				case job, ok := <-udpQueue:
					if !ok {
						return // Channel closed (shouldn't happen, but defensive)
					}
					var ip string
					if addr, ok := job.w.RemoteAddr().(*net.UDPAddr); ok {
						ip = addr.IP.String()
					}
					ProcessDNS(job.w, job.r, ip, "UDP")
				case <-shutdownCh:
					return // Clean exit on shutdown signal
				}
			}
		}()
	}
	log.Printf("[LISTEN] UDP Worker Pool: %d routines", cfg.Server.UDPWorkers)

	const (
		tcpReadTimeout  = 2 * time.Second
		tcpWriteTimeout = 2 * time.Second
		tcpIdleTimeout  = 10 * time.Second
	)

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
				Addr: addr, Net: "tcp",
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
	// Uses handleDoT (not handleTCP) so the protocol string in logs is accurate.
	// miekg/dns doesn't expose TLS state via ResponseWriter — separate handler
	// registration is the only reliable way to distinguish TCP from DoT in logs.
	for _, addr := range cfg.Server.ListenDoT {
		addr := addr
		go func() {
			server := &dns.Server{
				Addr: addr, Net: "tcp-tls",
				TLSConfig:    tlsConf,
				Handler:      dns.HandlerFunc(handleDoT), // Was handleTCP — now logs "DoT"
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			log.Printf("[LISTEN] DoT on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] DoT failed on %s: %v", addr, err)
			}
		}()
	}

	// 4. DNS over HTTPS (DoH/HTTP2) + DNS over HTTP/3 (DoH3/QUIC)
	for _, addr := range cfg.Server.ListenDoH {
		addr := addr
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", handleDoH)

		h2Server := &http.Server{
			Addr: addr, Handler: mux, TLSConfig: tlsConf,
			ReadTimeout:    tcpReadTimeout,
			WriteTimeout:   tcpWriteTimeout,
			IdleTimeout:    tcpIdleTimeout,
			MaxHeaderBytes: 8192,
		}
		go func() {
			log.Printf("[LISTEN] DoH (HTTP/2) on %s", addr)
			if err := h2Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[FATAL] DoH failed on %s: %v", addr, err)
			}
		}()

		h3Server := &http3.Server{
			Addr: addr, Handler: mux, TLSConfig: tlsConf,
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
			doqTLS             := tlsConf.Clone()
			doqTLS.NextProtos   = []string{"doq"}
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

// handleUDP feeds incoming UDP packets into the bounded worker pool.
// Checks shutdownCh so we don't send to the queue after shutdown is signalled.
// The default case sheds load when the queue is full — correct behaviour for UDP.
func handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	select {
	case udpQueue <- udpJob{w: w, r: r}:
	case <-shutdownCh:
		// Shutting down — drop packet cleanly
	default:
		// Queue full — drop packet (load shedding, same as before)
	}
}

// handleTCP handles plain (unencrypted) DNS-over-TCP. Logs protocol as "TCP".
func handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}
	ProcessDNS(w, r, ip, "TCP")
}

// handleDoT handles DNS-over-TLS connections. Registered separately from handleTCP
// so the protocol string in logs is "DoT" rather than "TCP".
// (miekg/dns does not expose TLS state through ResponseWriter — separate handler
// registration is the only reliable way to distinguish the two.)
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
		// largeBufPool: incoming body size is unknown (could be a large DNS request)
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
		defer r.Body.Close()
		// Copy out of the pool buffer before returning it
		payload = make([]byte, n)
		copy(payload, buf[:n])

	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		// RFC 8484 requires RawURLEncoding (no padding); some clients add "=" anyway
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
	proto       := "DoH"
	if r.Proto == "HTTP/3.0" {
		proto = "DoH3"
	}

	ProcessDNS(&dohResponseWriter{w: w, remoteIP: host}, msg, host, proto)
}

func handleDoQConnection(conn *quic.Conn) {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
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

			// largeBufPool: length from the wire could be up to 65535
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
			ProcessDNS(&doqResponseWriter{stream: s, remoteIP: host}, msg, host, "DoQ")
		}(stream)
	}
}

// --- Response Writer Adapters ---

type dohResponseWriter struct {
	w        http.ResponseWriter
	remoteIP string
}

func (dw *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	// smallBufPool: we're packing an outgoing DNS response — always small
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
func (dw *dohResponseWriter) LocalAddr() net.Addr              { return nil }
func (dw *dohResponseWriter) RemoteAddr() net.Addr             { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *dohResponseWriter) Write(b []byte) (int, error)      { return dw.w.Write(b) }
func (dw *dohResponseWriter) Close() error                     { return nil }
func (dw *dohResponseWriter) TsigStatus() error                { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(bool)              {}
func (dw *dohResponseWriter) Hijack()                          {}

type doqResponseWriter struct {
	stream   *quic.Stream
	remoteIP string
}

func (dw *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	// smallBufPool: packing an outgoing DNS response — always small
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
func (dw *doqResponseWriter) LocalAddr() net.Addr              { return nil }
func (dw *doqResponseWriter) RemoteAddr() net.Addr             { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *doqResponseWriter) Write(b []byte) (int, error)      { return dw.stream.Write(b) }
func (dw *doqResponseWriter) Close() error                     { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error                { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(bool)              {}
func (dw *doqResponseWriter) Hijack()                          {}

