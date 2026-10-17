/*
File:    server_init.go
Version: 1.22.0 (Split)
Last Updated: 17-Oct-2026 19:54 CEST

Description:
  Listener initialization and OS binding orchestration.
  Extracted from server.go to cleanly separate the setup of network listeners
  (UDP, TCP, TLS, DoH, DoQ) from the runtime protocol payload handlers.

Changes:
  1.22.0 - [SECURITY/FIX] Bound graceful shutdown hooks (`shutdownCh`) to TCP, DoT,
           DoH (HTTP/2), and DoH3 (HTTP/3) listeners so active sockets close cleanly
           upon `SIGTERM`/`SIGINT`.
         - [SECURITY/FIX] Moved `activeDoQConns` outside the `superviseListener` closure
           so a DoQ listener restart does not reset the connection counter while
           existing connections are still draining.
         - [SECURITY/FIX] Cloned `tlsConf` for `http3.Server` and explicitly set
           `NextProtos = []string{"h3"}` to avoid mutating the shared `tls.Config`
           across concurrent listeners.
  1.21.0 - [SECURITY/FIX] Injected `http.LocalAddrContextKey` via `ConnContext` on
           `http3.Server` (DoH3). Unlike standard `net/http.Server`, `quic-go/http3`
           does not populate `http.LocalAddrContextKey` by default, which caused
           `r.Context().Value(http.LocalAddrContextKey)` in `handleDoH` to return nil
           and broke `port:` routing and DDR local-IP fallback on DoH3 requests.
  1.20.0 - [BUG/FIX] Correctly populated the required third return parameter natively within 
           the DoQ/HTTP3 QUIC Connection execution loop (`return conn, nil, nil`). 
           Solves severe compilation errors when utilizing updated versions of `quic-go`.
  1.19.0 - [SECURITY/FIX] Retuned QUIC stream ceilings and wired the global DoQ
           stream budget (see server.go 1.37.0 for the handler-side bounds).
         - [SECURITY/FIX] Removed log.Fatalf from every listener SERVE loop.
  1.18.0 - [FEAT] Registered `/.well-known/origin-svcb` L7 discovery endpoint natively 
           for DoH and DoH3 listeners to comply with `draft-ietf-tls-wkech-11`. 
           Seamlessly generates compliant JSON payloads mapping active ECH configurations organically.
  1.17.0 - [FEAT] Registered `/.well-known/ech` L7 discovery endpoint natively 
           for DoH and DoH3 encrypted listeners. Allows clients to bypass DNS 
           tampering and fetch the router's `ECHConfigList` directly over HTTPS.
  1.16.0 - [SECURITY/FIX] Resolved a severe concurrency discrepancy dynamically. 
           Shifted the atomic `activeDoQConns` counter inherently inside the 
           Listener iteration loop natively.
  1.15.0 - [BUG/FIX] Resolved a compilation error natively within the DoQ listener loop.
  1.14.0 - [SECURITY/FIX] Addressed a severe Resource Exhaustion (DoS) vulnerability 
           within the DoQ (DNS-over-QUIC) listener loop natively.
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

// ---------------------------------------------------------------------------
// Listener supervision
// ---------------------------------------------------------------------------

// isShuttingDown reports whether Shutdown() has been called.
//
// Non-blocking, so it is safe to poll from a serve loop without perturbing it.
func isShuttingDown() bool {
	select {
	case <-shutdownCh:
		return true
	default:
		return false
	}
}

// listenerBackoff returns the delay before restart attempt n (1-based).
func listenerBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 5 {
		shift = 5 // 2^5 = 32s, clamped to 30s below
	}
	d := time.Duration(1<<uint(shift)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// superviseListener owns the full lifecycle of one protocol listener on one
// address: it runs serve, and if serve returns unexpectedly it rebinds and
// retries with backoff instead of killing the process.
func superviseListener(proto, addr string, serve func(attempt int) error) {
	const maxRestarts = 10

	for attempt := 0; ; attempt++ {
		err := serve(attempt)

		// Orderly teardown — Shutdown() closed the socket underneath us.
		if isShuttingDown() {
			if logSystem {
				log.Printf("[LISTEN] %s listener on %s stopped (shutdown).", proto, addr)
			}
			return
		}

		// A clean, expected close that did not originate from Shutdown(). Nothing
		// to recover from and nothing to complain about.
		if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			if logSystem {
				log.Printf("[LISTEN] %s listener on %s closed.", proto, addr)
			}
			return
		}

		if attempt >= maxRestarts {
			log.Printf("[LISTEN] CRITICAL: %s listener on %s failed %d consecutive times and has been retired: %v. "+
				"Remaining transports continue serving. Restart sdproxy once the underlying fault is resolved.",
				proto, addr, attempt+1, err)
			return
		}

		delay := listenerBackoff(attempt + 1)
		log.Printf("[LISTEN] WARNING: %s listener on %s terminated: %v. Restarting in %s (attempt %d/%d).",
			proto, addr, err, delay, attempt+1, maxRestarts)

		select {
		case <-time.After(delay):
		case <-shutdownCh:
			return
		}
	}
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
				if logSystem {
					log.Printf("[LISTEN] Skipping %s: support_ip_version is 'ipv4' only", a)
				}
				continue
			}
			if ipVersionSupport == "ipv6" && !addr.Is6() {
				if logSystem {
					log.Printf("[LISTEN] Skipping %s: support_ip_version is 'ipv6' only", a)
				}
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// StartServers spins up all configured DNS protocol listeners independently.
func StartServers(tlsConf *tls.Config) {
	maxTCP := cfg.Server.MaxTCPConnections
	if maxTCP <= 0 {
		maxTCP = 250 // Conservative default for tiny routers
	}

	initDoQStreamBudget(maxTCP)

	tcpReadTimeout := 5 * time.Second

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
		go superviseListener("TCP", addr, func(attempt int) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				if attempt == 0 {
					log.Fatalf("[FATAL] TCP listen failed on %s: %v", addr, err)
				}
				return fmt.Errorf("rebind: %w", err)
			}

			l = netutil.LimitListener(l, maxTCP)

			server := &dns.Server{
				Listener:     l,
				Handler:      dns.HandlerFunc(handleTCP),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			if logSystem {
				log.Printf("[LISTEN] TCP on %s (Max Conns: %d)", addr, maxTCP)
			}

			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					_ = server.Shutdown()
				case <-served:
				}
			}()

			return server.ActivateAndServe()
		})
	}

	// 3. DNS over TLS (DoT)
	for _, addr := range filterListeners(cfg.Server.ListenDoT) {
		addr := addr
		go superviseListener("DoT", addr, func(attempt int) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				if attempt == 0 {
					log.Fatalf("[FATAL] DoT listen failed on %s: %v", addr, err)
				}
				return fmt.Errorf("rebind: %w", err)
			}

			l = netutil.LimitListener(l, maxTCP)
			dotTLS := tlsConf.Clone()
			dotTLS.NextProtos = []string{"dot"}
			tlsL := tls.NewListener(l, dotTLS)

			server := &dns.Server{
				Listener:     tlsL,
				Handler:      dns.HandlerFunc(handleDoT),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			if logSystem {
				log.Printf("[LISTEN] DoT on %s (Max Conns: %d)", addr, maxTCP)
			}

			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					_ = server.Shutdown()
				case <-served:
				}
			}()

			return server.ActivateAndServe()
		})
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

		mux.HandleFunc("/.well-known/origin-svcb", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altSvc)

			if len(ddrECHConfig) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "public, max-age=86400")

				b64Ech := base64.StdEncoding.EncodeToString(ddrECHConfig)
				jsonPayload := fmt.Sprintf(`{"endpoints":[{"ech":"%s"}]}`, b64Ech)
				w.Write([]byte(jsonPayload))
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		})

		mux.HandleFunc("/.well-known/ech", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altSvc)

			if len(ddrECHConfig) > 0 {
				w.Header().Set("Content-Type", "application/echconfig-list")
				w.Header().Set("Cache-Control", "public, max-age=86400")
				w.Write(ddrECHConfig)
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		})

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altSvc)

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

		dohTLS := tlsConf.Clone()
		dohTLS.NextProtos = []string{"h2", "http/1.1"}

		go superviseListener("DoH", addr, func(attempt int) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				if attempt == 0 {
					log.Fatalf("[FATAL] DoH listen failed on %s: %v", addr, err)
				}
				return fmt.Errorf("rebind: %w", err)
			}

			l = netutil.LimitListener(l, maxTCP)
			tlsL := tls.NewListener(l, dohTLS)

			h2Server := &http.Server{
				Handler:           mux,
				ReadTimeout:       tcpReadTimeout,
				ReadHeaderTimeout: 3 * time.Second,
				WriteTimeout:      tcpWriteTimeout,
				IdleTimeout:       tcpIdleTimeout,
				MaxHeaderBytes:    8192,
				ErrorLog:          log.New(io.Discard, "", 0),
			}

			if logSystem {
				log.Printf("[LISTEN] DoH (HTTP/1.1 + HTTP/2) on %s (Max Conns: %d)", addr, maxTCP)
				if len(ddrECHConfig) > 0 {
					log.Printf("[LISTEN] Registered /.well-known/origin-svcb & /.well-known/ech L7 discovery endpoints natively on %s", addr)
				}
			}

			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					_ = h2Server.Close()
				case <-served:
				}
			}()

			return h2Server.Serve(tlsL)
		})

		doh3TLS := tlsConf.Clone()
		doh3TLS.NextProtos = []string{"h3"}

		go superviseListener("DoH3", addr, func(attempt int) error {
			h3Server := &http3.Server{
				Addr:      addr,
				Handler:   mux,
				TLSConfig: doh3TLS,
				// [SECURITY/FIX 1.21.0] Populate http.LocalAddrContextKey on HTTP/3 requests
				// so handleDoH can extract the bound local IP and port identically to HTTP/1.1 & HTTP/2.
				ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
					return context.WithValue(ctx, http.LocalAddrContextKey, c.LocalAddr())
				},
				QUICConfig: &quic.Config{
					Allow0RTT:          true,
					MaxIdleTimeout:     tcpIdleTimeout,
					KeepAlivePeriod:    15 * time.Second,
					MaxIncomingStreams: 256,
				},
			}

			if logSystem {
				log.Printf("[LISTEN] DoH3 (QUIC) on %s", addr)
			}

			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					_ = h3Server.Close()
				case <-served:
				}
			}()

			return h3Server.ListenAndServe()
		})
	}

	// 5. DNS over QUIC (DoQ) — RFC 9250
	for _, addr := range filterListeners(cfg.Server.ListenDoQ) {
		addr := addr
		var activeDoQConns atomic.Int32
		go superviseListener("DoQ", addr, func(attempt int) error {
			doqTLS := tlsConf.Clone()
			doqTLS.NextProtos = []string{"doq"}
			listener, err := quic.ListenAddr(addr, doqTLS, &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				KeepAlivePeriod:    15 * time.Second,
				MaxIncomingStreams: maxDoQStreamsPerConn,
			})
			if err != nil {
				if attempt == 0 {
					log.Fatalf("[FATAL] DoQ failed on %s: %v", addr, err)
				}
				return fmt.Errorf("rebind: %w", err)
			}
			if logSystem {
				log.Printf("[LISTEN] DoQ on %s (Max Conns: %d, Streams: %d/conn, %d global)",
					addr, maxTCP, maxDoQStreamsPerConn, cap(doqStreamSem))
			}

			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					listener.Close()
				case <-served:
				}
			}()
			defer listener.Close()

			consecutiveAcceptErrs := 0
			const maxConsecutiveAcceptErrs = 20

			for {
				conn, err := listener.Accept(context.Background())
				if err != nil {
					if isShuttingDown() {
						return nil
					}

					if logSystem {
						log.Printf("[DOQ] Accept error on %s: %v", addr, err)
					}

					consecutiveAcceptErrs++
					if consecutiveAcceptErrs >= maxConsecutiveAcceptErrs {
						return fmt.Errorf("accept failed %d consecutive times: %w", consecutiveAcceptErrs, err)
					}

					time.Sleep(250 * time.Millisecond)
					continue
				}
				consecutiveAcceptErrs = 0

				if activeDoQConns.Add(1) > int32(maxTCP) {
					activeDoQConns.Add(-1)
					conn.CloseWithError(0x0, "server busy")
					if logSystem {
						log.Printf("[SECURITY] DoQ connection rejected on %s: Max Connections (%d) reached", addr, maxTCP)
					}
					continue
				}

				currentConn := conn
				go func() {
					defer activeDoQConns.Add(-1)
					handleDoQConnection(currentConn)
				}()
			}
		})
	}
}

