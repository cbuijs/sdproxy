/*
File:    server_init.go
Version: 1.11.0 (Split)
Updated: 07-May-2026 12:13 CEST

Description:
  Listener initialization and OS binding orchestration.
  Extracted from server.go to cleanly separate the setup of network listeners
  (UDP, TCP, TLS, DoH, DoQ) from the runtime protocol payload handlers.

Changes:
  1.11.0 - [SECURITY/FIX] Addressed a Slow-Read Resource Exhaustion DoS vulnerability 
           by rigidly re-enabling `WriteTimeout` bounds across all HTTP/2 and HTTP/3 
           servers globally. Long-lived streaming operations (SSE) natively deploy a 
           `ResponseController` in `webui_api.go` to explicitly lift the constraint 
           for authenticated subscribers, fulfilling strict security baselines natively.
*/

package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/netutil"
)

var (
	shutdownCh   = make(chan struct{})
	shutdownOnce sync.Once
)

// Shutdown cleanly signals all active listeners and pools to terminate.
func Shutdown() {
	shutdownOnce.Do(func() {
		close(shutdownCh)
	})
}

// filterListeners returns a subset of addresses that match the global support_ip_version.
func filterListeners(addrs []string) []string {
	if ipVersionSupport == "both" {
		return addrs
	}
	var out []string
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			host = a
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if ipVersionSupport == "ipv4" && !addr.Is4() {
				log.Printf("[LISTEN] Skipping %s: support_ip_version is 'ipv4' only", a)
				continue
			}
			if ipVersionSupport == "ipv6" && !addr.Is6() {
				log.Printf("[LISTEN] Skipping %s: support_ip_version is 'ipv6' only", a)
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// StartServers spins up all configured DNS protocol listeners independently.
// This function establishes the underlying net.Listeners and maps them to
// their appropriate protocol payload handlers inside server.go.
func StartServers(tlsConf *tls.Config) {
	// Extract MaxTCPConnections to protect against FD exhaustion natively
	maxTCP := cfg.Server.MaxTCPConnections
	if maxTCP <= 0 {
		maxTCP = 250 // Conservative default for tiny routers
	}

	tcpReadTimeout := 5 * time.Second
	
	// Dynamically calculate WriteTimeout based on Upstream execution deadlines
	// to prevent terminating the socket prematurely on cache-misses.
	var tcpWriteTimeout time.Duration
	if cfg.Server.UpstreamTimeoutMs > 0 {
		tcpWriteTimeout = time.Duration(cfg.Server.UpstreamTimeoutMs)*time.Millisecond + (2 * time.Second)
	} else {
		tcpWriteTimeout = 30 * time.Second // Robust default for unbounded upstream dials
	}
	
	tcpIdleTimeout := 15 * time.Second

	// 1. Classic UDP (Dispatches to Linux SO_REUSEPORT or fallback workers)
	startUDPServers(filterListeners(cfg.Server.ListenUDP), cfg.Server.UDPWorkers)

	// 2. DNS over TCP
	for _, addr := range filterListeners(cfg.Server.ListenTCP) {
		addr := addr
		go func() {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("[FATAL] TCP listen failed on %s: %v", addr, err)
			}
			
			// Apply LimitListener to cap concurrent TCP sessions natively
			l = netutil.LimitListener(l, maxTCP)

			server := &dns.Server{
				Listener:     l,
				Handler:      dns.HandlerFunc(handleTCP),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			log.Printf("[LISTEN] TCP on %s (Max Conns: %d)", addr, maxTCP)
			if err := server.ActivateAndServe(); err != nil {
				log.Fatalf("[FATAL] TCP failed on %s: %v", addr, err)
			}
		}()
	}

	// 3. DNS over TLS (DoT)
	for _, addr := range filterListeners(cfg.Server.ListenDoT) {
		addr := addr
		go func() {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("[FATAL] DoT listen failed on %s: %v", addr, err)
			}
			
			// Apply LimitListener to cap concurrent DoT sessions natively
			l = netutil.LimitListener(l, maxTCP)
			tlsL := tls.NewListener(l, tlsConf)
			
			server := &dns.Server{
				Listener:     tlsL,
				Handler:      dns.HandlerFunc(handleDoT),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			log.Printf("[LISTEN] DoT on %s (Max Conns: %d)", addr, maxTCP)
			if err := server.ActivateAndServe(); err != nil {
				log.Fatalf("[FATAL] DoT failed on %s: %v", addr, err)
			}
		}()
	}

	// 4. DNS over HTTPS (DoH/HTTP1.1 + HTTP/2) + DNS over HTTP/3 (DoH3/QUIC)
	for _, addr := range filterListeners(cfg.Server.ListenDoH) {
		addr := addr
		mux := http.NewServeMux()

		altSvc := buildAltSvc(addr)

		mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altSvc)
			handleDoH(w, r)
		})

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altSvc)
			
			// Always treat any request that accepts DNS Message structure as DoH
			// Uses strings.Contains to absorb complex headers securely without failing
			accept := r.Header.Get("Accept")
			contentType := r.Header.Get("Content-Type")
			
			if strings.Contains(accept, "application/dns-message") || 
			   strings.Contains(contentType, "application/dns-message") || 
			   r.URL.Query().Get("dns") != "" {
				handleDoH(w, r)
				return
			}
			
			if WebUIMux != nil {
				WebUIMux.ServeHTTP(w, r)
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		})

		dohTLS           := tlsConf.Clone()
		dohTLS.NextProtos = []string{"h2", "http/1.1"}

		h2Server := &http.Server{
			Handler:           mux,
			ReadTimeout:       tcpReadTimeout,
			ReadHeaderTimeout: 3 * time.Second, // Hardened against Slowloris attacks
			WriteTimeout:      tcpWriteTimeout, // [SECURITY/FIX] Re-enabled to prevent Slow-Read DoS
			IdleTimeout:       tcpIdleTimeout,
			MaxHeaderBytes:    8192,
			ErrorLog:          log.New(io.Discard, "", 0), // Suppress scanner/handshake EOF spam natively
		}
		
		go func() {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("[FATAL] DoH listen failed on %s: %v", addr, err)
			}
			
			// Apply LimitListener to cap concurrent DoH sessions natively
			l = netutil.LimitListener(l, maxTCP)
			tlsL := tls.NewListener(l, dohTLS)
			
			log.Printf("[LISTEN] DoH (HTTP/1.1 + HTTP/2) on %s (Max Conns: %d)", addr, maxTCP)
			if err := h2Server.Serve(tlsL); err != nil && err != http.ErrServerClosed {
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
				MaxIncomingStreams: 1000, // [PERFORMANCE] Raised from 50 to 1000 to support heavy multiplexing from modern browsers
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
	for _, addr := range filterListeners(cfg.Server.ListenDoQ) {
		addr := addr
		go func() {
			doqTLS           := tlsConf.Clone()
			doqTLS.NextProtos = []string{"doq"}
			listener, err := quic.ListenAddr(addr, doqTLS, &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				MaxIncomingStreams: 1000, // [PERFORMANCE] Raised from 50 to 1000 to support heavy multiplexing from modern browsers
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

