/*
File:    webui.go
Version: 1.62.0 (Split)
Last Updated: 15-Oct-2026 17:38 CEST

Description:
  Password-protected single-page web admin interface for sdproxy.
  This file handles the HTTP server initialization, session authentication,
  and embedded static assets. 

Changes:
  1.62.0 - [SECURITY/FIX] Hardened `webUIMiddleware` source IP normalization and ACL
           enforcement. Previously, `ipStr` was not unmapped before checking
           `loginStates`, allowing IPv4-in-IPv6 (`::ffff:x.x.x.x`) connections to
           bypass brute-force lockouts at connect time. Additionally, the ACL check
           was gated on `err == nil` from `net.SplitHostPort` and failed open on
           unparseable addresses; it now evaluates unconditionally and fails closed.
  1.61.0 - [SECURITY/FIX] isAuthed compared both credentials with `==`.
         - [SECURITY/FIX] Scoped the API token to SAFE methods.
         - [SECURITY] Documented, and warned once at startup about, the
           `?token=` query-parameter form.
         - [SECURITY/FIX] Added WriteTimeout to both admin servers.
  1.60.0 - [FEAT] Orchestrated routing multiplexer bindings natively for the 
           `/api/clients/bulk_block` endpoint to allow atomic, multi-client modifications.
  1.59.0 - [FEAT] Orchestrated routing multiplexer bindings natively for the 
           `/api/clients` and `/api/clients/block` endpoints.
  1.58.0 - [SECURITY/FIX] Eradicated a severe Memory Exhaustion (OOM) vulnerability 
           against the Web UI natively.
*/

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	_ "embed"
)

// ---------------------------------------------------------------------------
// Embedded Static Assets
// ---------------------------------------------------------------------------

// uiScript is the minimal inline JS for the admin page.
// Compiled directly into the binary via go:embed for zero-I/O runtime performance.
//go:embed web/static/script.js
var uiScript string

// css is the complete inline stylesheet for every page the web UI renders.
// Compiled directly into the binary via go:embed.
//go:embed web/static/style.css
var css string

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

const cookieName = "sdp_sess"

var (
	sessToken string
	sessExp   time.Time
	sessMu    sync.Mutex
)

// newSession generates a fresh random 32-byte hex session token with an
// 8-hour expiry. One active session at a time — previous token is invalidated.
func newSession() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	sessMu.Lock()
	sessToken = tok
	sessExp   = time.Now().Add(8 * time.Hour)
	sessMu.Unlock()
	return tok
}

// secretsEqual compares two secrets without leaking their contents through the
// comparison's execution time.
func secretsEqual(given, want string) bool {
	if want == "" || given == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// isSafeMethod reports whether a request only reads state.
func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// isAuthed checks the request cookie against the current session token.
// Also allows stateless token-based authentication for read-only API access.
func isAuthed(r *http.Request) bool {
	// ── API Token (READ-ONLY) ────────────────────────────────────────────
	if cfg.WebUI.APIToken != "" && isSafeMethod(r.Method) {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			if secretsEqual(authHdr[7:], cfg.WebUI.APIToken) {
				return true
			}
		}
		if secretsEqual(r.URL.Query().Get("token"), cfg.WebUI.APIToken) {
			return true
		}
	}

	// ── Session cookie ───────────────────────────────────────────────────
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	sessMu.Lock()
	tok := sessToken
	exp := sessExp
	sessMu.Unlock()

	if !time.Now().Before(exp) {
		return false
	}
	return secretsEqual(c.Value, tok)
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

// webUIMiddleware enforces HTTP Security Headers, HTTPS Redirection, and 
// IP/Subnet-based ACLs. It also enforces Brute-Force mitigation, seamlessly 
// blackholing locked-out IPs.
func webUIMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ---------------------------------------------------------------------------
		// Security Response Headers
		// ---------------------------------------------------------------------------
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")

		// HSTS (Strict-Transport-Security)
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// ---------------------------------------------------------------------------
		// IP Identification for ACL and Brute-Force Lockout
		// ---------------------------------------------------------------------------
		ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ipStr = r.RemoteAddr // fallback to raw string if no port is present
		}

		// [SECURITY/FIX 1.62.0] Normalize IPv4-in-IPv6 addresses immediately so
		// loginStates lookup and ACL evaluation match handleLogin's unmapped key.
		var parsedAddr netip.Addr
		if a, parseErr := netip.ParseAddr(ipStr); parseErr == nil {
			parsedAddr = a.Unmap().WithZone("")
			ipStr = parsedAddr.String()
		}

		// ---------------------------------------------------------------------------
		// Brute-Force Lockout Check (Public Resolver Hardening)
		// ---------------------------------------------------------------------------
		loginStatesMu.Lock()
		if state, exists := loginStates[ipStr]; exists && cfg.WebUI.LoginRatelimit.Enabled && state.attempts >= cfg.WebUI.LoginRatelimit.MaxAttempts {
			if time.Now().After(state.lockoutExpires) {
				state.attempts = 0
				if logWebUI {
					log.Printf("[WEBUI] SECURITY: IP %s lockout expired. Access restored.", ipStr)
				}
			} else {
				if time.Since(state.lastDropLog) > 10*time.Second {
					state.lastDropLog = time.Now()
					if logWebUI {
						log.Printf("[WEBUI] SECURITY: Silently dropping connection from %s (IP is locked out until %s)", ipStr, state.lockoutExpires.Format("15:04:05"))
					}
				}
				loginStatesMu.Unlock()
				panic(http.ErrAbortHandler)
			}
		}
		loginStatesMu.Unlock()

		// ---------------------------------------------------------------------------
		// HTTPS Redirection
		// ---------------------------------------------------------------------------
		if cfg.WebUI.ForceHTTPS && r.TLS == nil {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}

			httpsPort := "443"
			filteredHTTPS := filterListeners(cfg.WebUI.ListenHTTPS)
			if len(filteredHTTPS) > 0 {
				_, p, _ := net.SplitHostPort(filteredHTTPS[0])
				if p != "" {
					httpsPort = p
				}
			} else {
				filteredDoH := filterListeners(cfg.Server.ListenDoH)
				if len(filteredDoH) > 0 {
					_, p, _ := net.SplitHostPort(filteredDoH[0])
					if p != "" {
						httpsPort = p
					}
				}
			}

			targetHost := host
			if httpsPort != "443" {
				targetHost = net.JoinHostPort(host, httpsPort)
			}

			targetURL := "https://" + targetHost + r.URL.RequestURI()
			http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
			return
		}

		// ---------------------------------------------------------------------------
		// Access Control List (ACL) Check
		// ---------------------------------------------------------------------------
		// [SECURITY/FIX 1.62.0] Evaluate ACL unconditionally when enabled, failing
		// closed if the remote address could not be parsed.
		if hasWebUIACL {
			if !parsedAddr.IsValid() {
				http.Error(w, "Forbidden - Invalid Source IP", http.StatusForbidden)
				return
			}

			// Deny rules take precedence over allow lists
			for _, p := range webUIACLDeny {
				if p.Contains(parsedAddr) {
					http.Error(w, "Forbidden - ACL Deny", http.StatusForbidden)
					return
				}
			}

			// Allow rules verify boundary
			if len(webUIACLAllow) > 0 {
				allowed := false
				for _, p := range webUIACLAllow {
					if p.Contains(parsedAddr) {
						allowed = true
						break
					}
				}
				if !allowed {
					http.Error(w, "Forbidden - ACL Block", http.StatusForbidden)
					return
				}
			}
		}

		next(w, r)
	}
}

// WebUIMux is exported so server.go can safely multiplex Web UI routes onto DoH listeners.
var WebUIMux *http.ServeMux

// webUIWriteTimeout bounds how long a single admin response may take to write.
const webUIWriteTimeout = 30 * time.Second

// StartWebUI starts the admin HTTP/HTTPS servers. No-op when cfg.WebUI.Enabled is false.
func StartWebUI(tlsConf *tls.Config) {
	if !cfg.WebUI.Enabled {
		if logWebUI {
			log.Println("[WEBUI] Disabled via config (webui.enabled: false).")
		}
		return
	}
	if cfg.WebUI.Password == "" {
		if logWebUI {
			log.Println("[WEBUI] No password configured — web UI disabled.")
		}
		return
	}

	if cfg.WebUI.APIToken != "" && logWebUI {
		log.Println("[WEBUI] API token configured: grants READ-ONLY access (GET/HEAD/OPTIONS). " +
			"State-changing requests require an interactive session. " +
			"Prefer the 'Authorization: Bearer <token>' header over the ?token= query parameter — " +
			"a secret in a URL is recorded in proxy logs, browser history and Referer headers.")
	}

	WebUIMux = http.NewServeMux()
	WebUIMux.HandleFunc("/",              webUIMiddleware(handleRoot))
	WebUIMux.HandleFunc("/login",         webUIMiddleware(handleLogin))
	WebUIMux.HandleFunc("/logout",        webUIMiddleware(handleLogout))
	WebUIMux.HandleFunc("/set",           webUIMiddleware(handleSet))
	WebUIMux.HandleFunc("/api/set",       webUIMiddleware(handleApiSet))
	WebUIMux.HandleFunc("/api/stats",     webUIMiddleware(handleApiStats))
	WebUIMux.HandleFunc("/api/reset",     webUIMiddleware(handleApiReset))
	WebUIMux.HandleFunc("/api/logs",      webUIMiddleware(handleApiLogs))
	WebUIMux.HandleFunc("/api/rules/get", webUIMiddleware(handleApiRulesGet))
	WebUIMux.HandleFunc("/api/rules/set", webUIMiddleware(handleApiRulesSet))
	WebUIMux.HandleFunc("/api/cache/get", webUIMiddleware(handleApiCacheGet))
	WebUIMux.HandleFunc("/api/groups",    webUIMiddleware(handleApiGroups))
	WebUIMux.HandleFunc("/api/clients",   webUIMiddleware(handleApiClients))
	WebUIMux.HandleFunc("/api/clients/block", webUIMiddleware(handleApiClientBlock))
	WebUIMux.HandleFunc("/api/clients/bulk_block", webUIMiddleware(handleApiClientsBulkBlock))

	// Resolve HTTP listeners
	httpAddrs := cfg.WebUI.ListenHTTP
	if len(httpAddrs) == 0 && cfg.WebUI.Listen != "" {
		httpAddrs = []string{cfg.WebUI.Listen}
	}
	if len(httpAddrs) == 0 && len(cfg.WebUI.ListenHTTPS) == 0 {
		httpAddrs = []string{"127.0.0.1:8080"}
	}
	
	httpAddrs = filterListeners(httpAddrs)

	// Dedicated HTTP servers
	for _, addr := range httpAddrs {
		addr := addr
		go func() {
			srv := &http.Server{
				Addr:              addr,
				Handler:           WebUIMux,
				ReadTimeout:       10 * time.Second,
				ReadHeaderTimeout: 5 * time.Second,  // Hardened
				WriteTimeout:      webUIWriteTimeout, // [SECURITY 1.61.0] Slow-read bound
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    4096,
				ErrorLog:          log.New(io.Discard, "", 0), // Suppress generic scanner noise natively
			}
			if logWebUI {
				log.Printf("[WEBUI] Admin UI (HTTP) at http://%s", addr)
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				if logWebUI {
					log.Printf("[WEBUI] HTTP Server error on %s: %v", addr, err)
				}
			}
		}()
	}

	filteredDoH := filterListeners(cfg.Server.ListenDoH)

	// Dedicated HTTPS servers
	for _, addr := range filterListeners(cfg.WebUI.ListenHTTPS) {
		addr := addr
		
		// Check if DoH is already listening on this exact address
		isDoH := false
		for _, dAddr := range filteredDoH {
			if dAddr == addr {
				isDoH = true
				break
			}
		}
		if isDoH {
			if logWebUI {
				log.Printf("[WEBUI] Admin UI (HTTPS) multiplexed natively on DoH listener at https://%s", addr)
			}
			continue
		}

		go func() {
			// Restrict ALPN to HTTP-only tokens to avoid DoT/DoQ conflicts if reused
			uiTLS := tlsConf.Clone()
			uiTLS.NextProtos = []string{"h2", "http/1.1"}

			srv := &http.Server{
				Addr:              addr,
				Handler:           WebUIMux,
				TLSConfig:         uiTLS,
				ReadTimeout:       10 * time.Second,
				ReadHeaderTimeout: 5 * time.Second,  // Hardened
				WriteTimeout:      webUIWriteTimeout, // [SECURITY 1.61.0] Slow-read bound
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    4096,
				ErrorLog:          log.New(io.Discard, "", 0), // Suppress handshake EOF noise natively
			}
			if logWebUI {
				log.Printf("[WEBUI] Admin UI (HTTPS) at https://%s", addr)
			}
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				if logWebUI {
					log.Printf("[WEBUI] HTTPS Server error on %s: %v", addr, err)
				}
			}
		}()
	}
}

