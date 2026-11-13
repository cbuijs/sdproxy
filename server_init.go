/*
File:    server_init.go
Version: 1.32.0 (Split)
Last Updated: 05-Nov-2026 18:45 CET

Description:
  Listener initialization and OS binding orchestration.
  Extracted from server.go to cleanly separate the setup of network listeners
  (UDP, TCP, TLS, DoH, DoQ) from the runtime protocol payload handlers.

Changes:
  1.32.0 - [CRITICAL/FIX] Separated `handshakeTimeout` (5s) from `idleTimeout` (15s)
           on `tlsHandshakeListener` and `tlsHandshakeConn`, and fixed a mutex/atomic
           ordering race in `ensureHandshake`: `SetReadDeadline` and `SetWriteDeadline`
           are now applied to the underlying `tc.Conn` while `tc.mu` is held and
           before `tc.hsDone.Store(true)`, preventing concurrent `SetReadDeadline`
           calls from `dns.Server` or `http.Server` from being overwritten with a
           stale deadline.
  1.31.0 - [CRITICAL/FIX] Fixed idle connection timeout regression in
           `tlsHandshakeConn.ensureHandshake` and added HTTP security headers to
           the DoH mux's `.well-known` endpoints.
  1.30.0 - [CRITICAL/FIX] Set a 5-second initial read deadline on newly accepted
           TCP sockets directly in `keepAliveListener.Accept`.
  1.29.0 - [CRITICAL/FIX] Removed `initialDeadlineConn` from `keepAliveListener`.
  1.28.0 - [CRITICAL/FIX] Added `initialDeadlineConn` in `keepAliveListener`.
  1.27.0 - [CRITICAL/FIX] Fixed idle connection timeout regression in
           `tlsHandshakeConn.ensureHandshake`.
  1.26.0 - [CRITICAL/FIX] Fixed an infinite loop in `tlsHandshakeConn`:
           `ConnectionState` triggers `ensureHandshake` safely before querying
           `tc.Conn.ConnectionState()`.
  1.25.0 - [CRITICAL/FIX] Fixed socket deadline lifecycle in `keepAliveListener`
           and `tlsHandshakeConn`.
  1.24.0 - [CRITICAL/FIX] Replaced `tls.NewListener` with `tlsHandshakeListener`
           on DoT, DoH, and WebUI-HTTPS listeners, and injected
           `http.LocalAddrContextKey` via `ConnContext` on `h2Server`.
  1.23.0 - [CRITICAL/FIX] Replaced `netutil.LimitListener` on TCP and DoT `dns.Server`
           listeners with an explicit TLS handshake timeout and TCP keepalive wrapper.
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
// Hardened TCP / TLS Listener Wrappers
// ---------------------------------------------------------------------------

// keepAliveListener sets TCP keepalives and an initial 5-second read deadline on
// newly accepted raw TCP sockets so silent/half-open connections cannot hold
// slots in netutil.LimitListener indefinitely before the first Read or TLS handshake.
type keepAliveListener struct {
	net.Listener
}

func (kl *keepAliveListener) Accept() (net.Conn, error) {
	c, err := kl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return c, nil
}

// tlsHandshakeConn wraps a *tls.Conn so the TLS handshake is bounded by a
// strict deadline on the first Read/Write/ConnectionState (which happens inside
// the per-conn worker goroutine in both net/http and miekg/dns, never blocking
// the Accept loop), and restores the caller's read/write deadlines (or falls
// back to idleTimeout if none was set yet) atomically under tc.mu.
type tlsHandshakeConn struct {
	*tls.Conn
	timeout       time.Duration
	idleTimeout   time.Duration
	hsOnce        sync.Once
	hsDone        atomic.Bool
	hsErr         error
	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func (tc *tlsHandshakeConn) ensureHandshake() error {
	tc.hsOnce.Do(func() {
		_ = tc.Conn.SetDeadline(time.Now().Add(tc.timeout))
		ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
		defer cancel()
		tc.hsErr = tc.Conn.HandshakeContext(ctx)
		if tc.hsErr == nil {
			tc.mu.Lock()
			rd := tc.readDeadline
			wd := tc.writeDeadline
			if rd.IsZero() {
				idle := tc.idleTimeout
				if idle <= 0 {
					idle = tc.timeout
				}
				rd = time.Now().Add(idle)
			}
			_ = tc.Conn.SetReadDeadline(rd)
			_ = tc.Conn.SetWriteDeadline(wd)
			tc.hsDone.Store(true)
			tc.mu.Unlock()
		}
	})
	return tc.hsErr
}

func (tc *tlsHandshakeConn) Read(b []byte) (int, error) {
	if !tc.hsDone.Load() {
		if err := tc.ensureHandshake(); err != nil {
			return 0, err
		}
	}
	return tc.Conn.Read(b)
}

func (tc *tlsHandshakeConn) Write(b []byte) (int, error) {
	if !tc.hsDone.Load() {
		if err := tc.ensureHandshake(); err != nil {
			return 0, err
		}
	}
	return tc.Conn.Write(b)
}

func (tc *tlsHandshakeConn) SetDeadline(t time.Time) error {
	tc.mu.Lock()
	tc.readDeadline = t
	tc.writeDeadline = t
	done := tc.hsDone.Load()
	var err error
	if done {
		err = tc.Conn.SetDeadline(t)
	}
	tc.mu.Unlock()
	return err
}

func (tc *tlsHandshakeConn) SetReadDeadline(t time.Time) error {
	tc.mu.Lock()
	tc.readDeadline = t
	done := tc.hsDone.Load()
	var err error
	if done {
		err = tc.Conn.SetReadDeadline(t)
	}
	tc.mu.Unlock()
	return err
}

func (tc *tlsHandshakeConn) SetWriteDeadline(t time.Time) error {
	tc.mu.Lock()
	tc.writeDeadline = t
	done := tc.hsDone.Load()
	var err error
	if done {
		err = tc.Conn.SetWriteDeadline(t)
	}
	tc.mu.Unlock()
	return err
}

func (tc *tlsHandshakeConn) ConnectionState() tls.ConnectionState {
	if !tc.hsDone.Load() {
		_ = tc.ensureHandshake()
	}
	return tc.Conn.ConnectionState()
}

type tlsHandshakeListener struct {
	net.Listener
	tlsConfig   *tls.Config
	timeout     time.Duration
	idleTimeout time.Duration
}

func (tl *tlsHandshakeListener) Accept() (net.Conn, error) {
	c, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Server(c, tl.tlsConfig)
	return &tlsHandshakeConn{
		Conn:        tlsConn,
		timeout:     tl.timeout,
		idleTimeout: tl.idleTimeout,
	}, nil
}

func isShuttingDown() bool {
	select {
	case <-shutdownCh:
		return true
	default:
		return false
	}
}

func listenerBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 5 {
		shift = 5
	}
	d := time.Duration(1<<uint(shift)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func superviseListener(proto, addr string, serve func(attempt int) error) {
	const maxRestarts = 10

	for attempt := 0; ; attempt++ {
		err := serve(attempt)

		if isShuttingDown() {
			if logSystem {
				log.Printf("[LISTEN] %s listener on %s stopped (shutdown).", proto, addr)
			}
			return
		}

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
		maxTCP = 250
	}

	initDoQStreamBudget(maxTCP)

	tcpReadTimeout := 5 * time.Second

	var tcpWriteTimeout time.Duration
	if cfg.Server.UpstreamTimeoutMs > 0 {
		tcpWriteTimeout = time.Duration(cfg.Server.UpstreamTimeoutMs)*time.Millisecond + (2 * time.Second)
	} else {
		tcpWriteTimeout = 30 * time.Second
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

			l = &keepAliveListener{Listener: netutil.LimitListener(l, maxTCP)}

			server := &dns.Server{
				Listener:     l,
				Handler:      dns.HandlerFunc(handleTCP),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
				IdleTimeout:  func() time.Duration { return tcpIdleTimeout },
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

			l = &keepAliveListener{Listener: netutil.LimitListener(l, maxTCP)}
			dotTLS := tlsConf.Clone()
			dotTLS.NextProtos = []string{"dot"}
			tlsL := &tlsHandshakeListener{
				Listener:    l,
				tlsConfig:   dotTLS,
				timeout:     tcpReadTimeout,
				idleTimeout: tcpIdleTimeout,
			}

			server := &dns.Server{
				Listener:     tlsL,
				Handler:      dns.HandlerFunc(handleDoT),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
				IdleTimeout:  func() time.Duration { return tcpIdleTimeout },
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
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

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
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

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

			l = &keepAliveListener{Listener: netutil.LimitListener(l, maxTCP)}
			tlsL := &tlsHandshakeListener{
				Listener:    l,
				tlsConfig:   dohTLS,
				timeout:     tcpReadTimeout,
				idleTimeout: tcpIdleTimeout,
			}

			h2Server := &http.Server{
				Handler:           mux,
				ReadTimeout:       tcpReadTimeout,
				ReadHeaderTimeout: 3 * time.Second,
				WriteTimeout:      tcpWriteTimeout,
				IdleTimeout:       tcpIdleTimeout,
				MaxHeaderBytes:    8192,
				ConnContext: func(ctx context.Context, c net.Conn) context.Context {
					return context.WithValue(ctx, http.LocalAddrContextKey, c.LocalAddr())
				},
				ErrorLog: log.New(io.Discard, "", 0),
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
