/*
File: server.go
Version: 1.11.0
Last Updated: 2026-02-27 21:00 CET
Description: High-performance Listeners for UDP, TCP, DoT, DoH (HTTP/2), DoH3 (QUIC), and DoQ.
             MEMORY OPTIMIZATION: Applied aggressive Read/Write/Idle timeouts.
             FIXED: Added full support for both HTTP GET and POST for DoH/DoH3 clients.
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
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type udpJob struct {
	w dns.ResponseWriter
	r *dns.Msg
}

// Bounded queue for UDP requests
var udpQueue chan udpJob

func StartServers(tlsConf *tls.Config) {

	// 0. Initialize Bounded UDP Worker Pool
	udpQueue = make(chan udpJob, cfg.Server.UDPWorkers*10)
	for i := 0; i < cfg.Server.UDPWorkers; i++ {
		go func() {
			for job := range udpQueue {
				var ip string
				if udpAddr, ok := job.w.RemoteAddr().(*net.UDPAddr); ok {
					ip = udpAddr.IP.String()
				}
				ProcessDNS(job.w, job.r, ip, "UDP")
			}
		}()
	}
	log.Printf("[LISTEN] UDP Worker Pool initialized with %d routines", cfg.Server.UDPWorkers)

	// TIME-OUTS: Aggressively kill hanging connections to save memory on routers
	const tcpReadTimeout = 2 * time.Second
	const tcpWriteTimeout = 2 * time.Second
	const tcpIdleTimeout = 10 * time.Second

	// 1. DNS over UDP
	for _, addr := range cfg.Server.ListenUDP {
		addr := addr
		go func() {
			server := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(handleUDP)}
			log.Printf("[LISTEN] UDP started on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] UDP Server failed on %s: %v", addr, err)
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
			log.Printf("[LISTEN] TCP started on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] TCP Server failed on %s: %v", addr, err)
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
				Handler:      dns.HandlerFunc(handleTCP),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			log.Printf("[LISTEN] DoT started on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] DoT Server failed on %s: %v", addr, err)
			}
		}()
	}

	// 4. DNS over HTTPS (DoH / HTTP2) & DNS over HTTP/3 (DoH3 / QUIC)
	for _, addr := range cfg.Server.ListenDoH {
		addr := addr
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", handleDoH)

		h2Server := &http.Server{
			Addr:              addr,
			Handler:           mux,
			TLSConfig:         tlsConf,
			ReadTimeout:       tcpReadTimeout,
			WriteTimeout:      tcpWriteTimeout,
			IdleTimeout:       tcpIdleTimeout,
			MaxHeaderBytes:    8192, // Support larger headers for GET requests
		}
		go func() {
			log.Printf("[LISTEN] DoH (TCP) started on %s", addr)
			if err := h2Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[FATAL] DoH Server failed on %s: %v", addr, err)
			}
		}()

		h3Server := &http3.Server{
			Addr:       addr,
			Handler:    mux,
			TLSConfig:  tlsConf,
			QUICConfig: &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				MaxIncomingStreams: 50, // Prevent stream hoarding
			},
		}
		go func() {
			log.Printf("[LISTEN] DoH3 (QUIC) started on %s", addr)
			if err := h3Server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] DoH3 Server failed on %s: %v", addr, err)
			}
		}()
	}

	// 5. DNS over QUIC (DoQ) - RFC 9250
	for _, addr := range cfg.Server.ListenDoQ {
		addr := addr
		go func() {
			log.Printf("[LISTEN] DoQ started on %s", addr)
			
			doqTLS := tlsConf.Clone()
			doqTLS.NextProtos = []string{"doq"}

			listener, err := quic.ListenAddr(addr, doqTLS, &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				MaxIncomingStreams: 50, // Prevent stream hoarding
			})
			if err != nil {
				log.Fatalf("[FATAL] DoQ Listener failed on %s: %v", addr, err)
			}

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
	select {
	case udpQueue <- udpJob{w: w, r: r}:
	default:
		// LOAD SHEDDING: Drop packet if queue is full.
	}
}

func handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if tcpAddr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcpAddr.IP.String()
	}
	proto := "TCP"
	if _, isTLS := w.RemoteAddr().(*net.TCPAddr); isTLS {
		// miekg/dns doesn't easily expose TLS state here, but we generally assume TCP/DoT
	}
	ProcessDNS(w, r, ip, proto)
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	var payload []byte
	var err error

	// RFC 8484 supports both POST and GET methods
	if r.Method == http.MethodPost {
		// MEMORY OPTIMIZATION: Zero-allocation body reading using sync.Pool
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		defer bufPool.Put(bufPtr)

		lr := io.LimitReader(r.Body, 65535)
		n := 0
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
		
		// Copy payload out of buffer before returning it to the pool
		payload = make([]byte, n)
		copy(payload, buf[:n])

	} else if r.Method == http.MethodGet {
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		
		// Some non-compliant clients append padding (=), RFC 8484 demands RawURLEncoding (no padding)
		b64 = strings.TrimRight(b64, "=")
		payload, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "Invalid base64 payload", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		http.Error(w, "Malformed DNS payload", http.StatusBadRequest)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	proto := "DoH"
	if r.Proto == "HTTP/3.0" {
		proto = "DoH3"
	}

	dw := &dohResponseWriter{w: w, remoteIP: host}
	ProcessDNS(dw, msg, host, proto)
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

			// MEMORY OPTIMIZATION: Zero-allocation body reading using sync.Pool
			bufPtr := bufPool.Get().(*[]byte)
			buf := *bufPtr
			defer bufPool.Put(bufPtr)

			if _, err := io.ReadFull(s, buf[:length]); err != nil {
				return
			}

			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:length]); err != nil {
				return
			}

			dw := &doqResponseWriter{stream: s, remoteIP: host}
			ProcessDNS(dw, msg, host, "DoQ")
		}(stream)
	}
}

// --- Response Writer Adapters ---

type dohResponseWriter struct {
	w        http.ResponseWriter
	remoteIP string
}

func (dw *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	// Re-use pool for packing responses too
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	packed, err := msg.PackBuffer(buf[:0])
	if err != nil {
		return err
	}
	dw.w.Header().Set("Content-Type", "application/dns-message")
	_, err = dw.w.Write(packed)
	return err
}
func (dw *dohResponseWriter) LocalAddr() net.Addr  { return nil }
func (dw *dohResponseWriter) RemoteAddr() net.Addr { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *dohResponseWriter) Write(b []byte) (int, error) { return dw.w.Write(b) }
func (dw *dohResponseWriter) Close() error         { return nil }
func (dw *dohResponseWriter) TsigStatus() error    { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(bool)  {}
func (dw *dohResponseWriter) Hijack()              {}

type doqResponseWriter struct {
	stream   *quic.Stream
	remoteIP string
}

func (dw *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	packed, err := msg.PackBuffer(buf[:0])
	if err != nil {
		return err
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	
	if _, err := dw.stream.Write(lenBuf); err != nil {
		return err
	}
	_, err = dw.stream.Write(packed)
	return err
}
func (dw *doqResponseWriter) LocalAddr() net.Addr  { return nil }
func (dw *doqResponseWriter) RemoteAddr() net.Addr { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *doqResponseWriter) Write(b []byte) (int, error) { return dw.stream.Write(b) }
func (dw *doqResponseWriter) Close() error         { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error    { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(bool)  {}
func (dw *doqResponseWriter) Hijack()              {}

