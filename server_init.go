/*
File:    server_init.go
Version: 1.19.0 (Split)
Last Updated: 05-Aug-2026 18:40 CEST

Description:
  Listener initialization and OS binding orchestration.
  Extracted from server.go to cleanly separate the setup of network listeners
  (UDP, TCP, TLS, DoH, DoQ) from the runtime protocol payload handlers.

Changes:
  1.19.0 - [SECURITY/FIX] Retuned QUIC stream ceilings and wired the global DoQ
           stream budget (see server.go 1.37.0 for the handler-side bounds).

           DoQ: MaxIncomingStreams dropped from 1000 to maxDoQStreamsPerConn
           (64). RFC 9250 mandates one query per stream and a handler lives only
           for that single exchange, so 1000 was never a DNS-shaped number — it
           was inherited wholesale from the DoH3 listener below, where browser
           multiplexing genuinely justifies it. Aligning the transport limit with
           the handler-side per-connection semaphore means well-behaved peers hit
           clean QUIC flow-control backpressure and never reach the shedding path
           at all; the semaphore remains as defence-in-depth for the window where
           a stream has completed at the transport layer while its handler
           goroutine is still draining.

           DoH3: reduced 1000 -> 256. This listener also fronts the Web UI mux,
           so it does need real multiplexing headroom — but 1000 concurrent
           streams per connection is far beyond what any browser opens, and the
           surplus is pure attack surface.

           Added initDoQStreamBudget(maxTCP), which sizes the process-wide DoQ
           stream semaphore before any listener binds. Called unconditionally so
           the budget exists even when DoQ is configured later via reload.
         - [SECURITY/FIX] Removed log.Fatalf from every listener SERVE loop.
           Eight call sites treated any post-bind serve return as fatal, so a
           single transient failure on one DoH listener terminated the entire
           process — taking UDP, TCP, DoT and DoQ down with it. On a device whose
           whole purpose is answering DNS, losing every transport because one
           HTTPS socket hiccupped is a self-inflicted outage.
           All listeners now run under superviseListener(), which restarts the
           bind-and-serve cycle with exponential backoff (1s doubling to a 30s
           ceiling, 10 attempts) and then retires that single listener with a
           loud, unmissable log while the others keep serving.
           Bind failures on the FIRST attempt remain fatal by design: a port
           already in use or a missing CAP_NET_BIND_SERVICE is an operator
           configuration error, and failing fast at boot is the correct and
           expected behaviour there. Only failures AFTER a listener has
           successfully served are treated as recoverable.
           Note: server_udp_linux.go retains its log.Fatalf deliberately. UDP is
           the primary DNS transport; if it cannot bind, the daemon has no
           useful function to degrade into, so fatal remains the honest outcome.
  1.18.0 - [FEAT] Registered `/.well-known/origin-svcb` L7 discovery endpoint natively 
           for DoH and DoH3 listeners to comply with `draft-ietf-tls-wkech-11`. 
           Seamlessly generates compliant JSON payloads mapping active ECH configurations organically.
  1.17.0 - [FEAT] Registered `/.well-known/ech` L7 discovery endpoint natively 
           for DoH and DoH3 encrypted listeners. Allows clients to bypass DNS 
           tampering and fetch the router's `ECHConfigList` directly over HTTPS.
  1.16.0 - [SECURITY/FIX] Resolved a severe concurrency discrepancy dynamically. 
           Shifted the atomic `activeDoQConns` counter inherently inside the 
           Listener iteration loop natively. Ensures that DoQ protocol bounds 
           safely respect precise per-listener connection limits exactly like 
           their `netutil.LimitListener` TCP/DoT equivalents.
  1.15.0 - [BUG/FIX] Resolved a compilation error natively within the DoQ listener loop. 
           Eliminated an invalid interface type assertion since `quic.Conn` is inherently 
           a concrete pointer structure, bypassing the assertion bounds seamlessly.
  1.14.0 - [SECURITY/FIX] Addressed a severe Resource Exhaustion (DoS) vulnerability 
           within the DoQ (DNS-over-QUIC) listener loop natively. Deployed a strict 
           atomic admission gate to enforce `MaxTCPConnections` limits against QUIC 
           transports, matching TCP/DoT/DoH parity. Prevents malicious actors from 
           spamming unfulfilled handshakes to permanently exhaust the router's 
           file descriptors and memory capacity.
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
//
// Doubling from one second to a thirty-second ceiling. The early attempts are
// short because the overwhelmingly common cause is transient — a TIME_WAIT
// socket from a previous instance, a momentary FD shortage — and recovering in
// a second beats recovering in thirty. The ceiling exists so a genuinely
// persistent fault does not degenerate into a hot restart loop burning CPU on
// the low-power hardware this project targets.
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
//
// [SECURITY/FIX 1.19.0] Replaces eight separate `log.Fatalf` calls that sat
// inside long-lived listener goroutines. Those made every transport's fate
// shared: an error on any one of them terminated all of them. A DNS resolver
// should degrade to "DoH is down, everything else still answers", not to
// "nothing answers".
//
// serve receives the attempt index so it can distinguish the initial boot from
// a restart. Attempt 0 is boot: a bind failure there is a configuration error
// (wrong port, port in use, insufficient privilege) and callers deliberately
// keep log.Fatalf for it, preserving fail-fast startup semantics. Every later
// attempt is a recovery, where the same failure is merely logged and retried.
//
// serve is expected to block for the listener's entire lifetime and return only
// on termination.
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
			// Deliberately NOT gated behind logSystem. A permanently dead
			// listener is a silent partial outage — the operator believes DoH is
			// running and it is not. This line must always be emitted.
			log.Printf("[LISTEN] CRITICAL: %s listener on %s failed %d consecutive times and has been retired: %v. "+
				"Remaining transports continue serving. Restart sdproxy once the underlying fault is resolved.",
				proto, addr, attempt+1, err)
			return
		}

		delay := listenerBackoff(attempt + 1)
		log.Printf("[LISTEN] WARNING: %s listener on %s terminated: %v. Restarting in %s (attempt %d/%d).",
			proto, addr, err, delay, attempt+1, maxRestarts)

		// Interruptible sleep so a shutdown during backoff exits promptly rather
		// than idling for up to thirty seconds.
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
// This function establishes the underlying net.Listeners and maps them to
// their appropriate protocol payload handlers inside server.go.
func StartServers(tlsConf *tls.Config) {
	// Extract MaxTCPConnections to protect against FD exhaustion natively
	maxTCP := cfg.Server.MaxTCPConnections
	if maxTCP <= 0 {
		maxTCP = 250 // Conservative default for tiny routers
	}

	// [SECURITY 1.19.0] Size the process-wide DoQ stream budget before anything
	// binds. Done unconditionally rather than inside the DoQ listener loop: the
	// semaphore must exist before the first connection is ever accepted, and a
	// nil budget silently degrades handleDoQConnection to per-connection bounds
	// only. Costs one channel allocation when DoQ is not configured.
	initDoQStreamBudget(maxTCP)

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
		go superviseListener("TCP", addr, func(attempt int) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				// Attempt 0 is boot: an unbindable port is a configuration error,
				// so fail fast and loudly rather than silently serving nothing.
				if attempt == 0 {
					log.Fatalf("[FATAL] TCP listen failed on %s: %v", addr, err)
				}
				return fmt.Errorf("rebind: %w", err)
			}

			// Apply LimitListener to cap concurrent TCP sessions natively
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
			// [SECURITY/FIX 1.19.0] Was log.Fatalf — a serve-loop return here used
			// to terminate the whole daemon, UDP and DoT included.
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

			// Apply LimitListener to cap concurrent DoT sessions natively
			l = netutil.LimitListener(l, maxTCP)
			tlsL := tls.NewListener(l, tlsConf)

			server := &dns.Server{
				Listener:     tlsL,
				Handler:      dns.HandlerFunc(handleDoT),
				ReadTimeout:  tcpReadTimeout,
				WriteTimeout: tcpWriteTimeout,
			}
			if logSystem {
				log.Printf("[LISTEN] DoT on %s (Max Conns: %d)", addr, maxTCP)
			}
			// [SECURITY/FIX 1.19.0] Was log.Fatalf — see the TCP listener above.
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

		// [FEAT] Serve ECHConfigList via Well-Known URI natively (L7 Discovery - draft-ietf-tls-wkech-11)
		// Provides the standard JSON format containing Encrypted Client Hello keys dynamically.
		mux.HandleFunc("/.well-known/origin-svcb", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Alt-Svc", altSvc)
			
			if len(ddrECHConfig) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "public, max-age=86400")
				
				// Encode ECH config to base64 for the JSON response
				b64Ech := base64.StdEncoding.EncodeToString(ddrECHConfig)
				jsonPayload := fmt.Sprintf(`{"endpoints":[{"ech":"%s"}]}`, b64Ech)
				w.Write([]byte(jsonPayload))
			} else {
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		})

		// [FEAT] Serve ECHConfigList via Well-Known URI natively (Legacy L7 Discovery)
		// Protects ECH parameter distribution from DNS-layer manipulation natively.
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
		
		go superviseListener("DoH", addr, func(attempt int) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				if attempt == 0 {
					log.Fatalf("[FATAL] DoH listen failed on %s: %v", addr, err)
				}
				return fmt.Errorf("rebind: %w", err)
			}

			// Apply LimitListener to cap concurrent DoH sessions natively
			l = netutil.LimitListener(l, maxTCP)
			tlsL := tls.NewListener(l, dohTLS)

			if logSystem {
				log.Printf("[LISTEN] DoH (HTTP/1.1 + HTTP/2) on %s (Max Conns: %d)", addr, maxTCP)
				if len(ddrECHConfig) > 0 {
					log.Printf("[LISTEN] Registered /.well-known/origin-svcb & /.well-known/ech L7 discovery endpoints natively on %s", addr)
				}
			}

			// [SECURITY/FIX 1.19.0] Was log.Fatalf. This was the single worst
			// instance: http.Server.Serve returns on a broad range of accept-layer
			// faults, and taking the entire resolver down because one TLS socket
			// failed is a far larger outage than the fault itself.
			// http.ErrServerClosed is classified as a clean stop by
			// superviseListener, so it is returned unwrapped here.
			return h2Server.Serve(tlsL)
		})

		h3Server := &http3.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: tlsConf,
			QUICConfig: &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     tcpIdleTimeout,
				KeepAlivePeriod:    15 * time.Second, // [PERF/FIX] Prevent strict NAT timeouts natively
				// [SECURITY 1.19.0] 1000 -> 256. This listener fronts the Web UI
				// mux as well as /dns-query, so genuine browser multiplexing needs
				// headroom — but no browser opens anything close to 256 concurrent
				// streams on one connection, and the surplus was pure attack surface.
				MaxIncomingStreams: 256,
			},
		}
		go superviseListener("DoH3", addr, func(attempt int) error {
			if logSystem {
				log.Printf("[LISTEN] DoH3 (QUIC) on %s", addr)
			}
			// [SECURITY/FIX 1.19.0] Was log.Fatalf.
			//
			// http3.Server.ListenAndServe fuses bind and serve into one call, so
			// unlike the listeners above there is no way to distinguish a boot
			// misconfiguration from a runtime fault by inspecting the error. The
			// tie is broken in favour of availability: DoH3 is an optional upgrade
			// path that every client can fall back from to DoH over TCP, so a
			// broken QUIC socket must never be able to take the daemon down.
			// A genuine misconfiguration still surfaces — as the CRITICAL
			// retirement line after the restart budget is exhausted.
			return h3Server.ListenAndServe()
		})
	}

	// 5. DNS over QUIC (DoQ) — RFC 9250
	
	for _, addr := range filterListeners(cfg.Server.ListenDoQ) {
		addr := addr
		go superviseListener("DoQ", addr, func(attempt int) error {
			var activeDoQConns atomic.Int32
			doqTLS := tlsConf.Clone()
			doqTLS.NextProtos = []string{"doq"}
			listener, err := quic.ListenAddr(addr, doqTLS, &quic.Config{
				Allow0RTT:       true,
				MaxIdleTimeout:  tcpIdleTimeout,
				KeepAlivePeriod: 15 * time.Second,
				// [SECURITY 1.19.0] Matched to maxDoQStreamsPerConn (server.go).
				// RFC 9250 is one query per stream and each handler lives for a
				// single exchange, so the previous 1000 — copied from the DoH3
				// browser-multiplexing case — bore no relation to DoQ traffic.
				// Aligning the transport limit with the handler semaphore means
				// honest peers receive clean QUIC flow-control backpressure and
				// never reach the shedding path at all.
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

			// [SECURITY/FIX] Close the listener when Shutdown() fires so Accept()
			// unblocks with a clean, expected error instead of this goroutine
			// running forever and blocking process termination.
			//
			// [1.19.0] `served` bounds the watcher to THIS supervision attempt.
			// Without it, every restart would leak another watcher goroutine still
			// holding a reference to a listener that no longer exists — each one
			// parked on shutdownCh for the lifetime of the process.
			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					listener.Close()
				case <-served:
					// This attempt ended on its own; the deferred Close below owns
					// the socket. Nothing to do.
				}
			}()
			defer listener.Close()

			// consecutiveAcceptErrs distinguishes a transient accept blip from a
			// listener that has genuinely died. Isolated errors are absorbed by the
			// backoff below exactly as before; a sustained run of them now escalates
			// to superviseListener, which rebinds the socket outright rather than
			// spinning here forever against a dead file descriptor.
			consecutiveAcceptErrs := 0
			const maxConsecutiveAcceptErrs = 20

			for {
				conn, err := listener.Accept(context.Background())
				if err != nil {
					if isShuttingDown() {
						// Expected: listener was closed intentionally during shutdown.
						return nil
					}

					// [SECURITY/FIX] Persistent Accept() errors (e.g. FD exhaustion, a
					// listener killed out-of-band) previously caused an unbounded
					// busy-loop pinning a full CPU core at 100% — especially bad on
					// the low-power routers this project targets. Back off instead.
					if logSystem {
						log.Printf("[DOQ] Accept error on %s: %v", addr, err)
					}

					consecutiveAcceptErrs++
					if consecutiveAcceptErrs >= maxConsecutiveAcceptErrs {
						// Roughly 5 seconds of uninterrupted failure. Escalate so the
						// listener is rebuilt instead of looping against a socket that
						// is never going to recover on its own.
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

