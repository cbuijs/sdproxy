/*
File:    webui.go
Version: 1.55.0 (Split)
Updated: 06-May-2026 13:32 CEST

Description:
  Password-protected single-page web admin interface for sdproxy.
  This file handles the HTTP server initialization, session authentication,
  and embedded static assets. 

Changes:
  1.55.0 - [FEAT] Registered `/api/cache/get` JSON endpoint natively to route 
           internal memory-shard structures safely to the new Web UI Cache modal.
  1.54.0 - [FEAT] Added explicit endpoints for `api/rules/get` and `api/rules/set`
           to serve the Custom Rules Engine UI modals.
*/

package main

import (
	"crypto/rand"
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

// isAuthed checks the request cookie against the current session token.
// Also allows stateless token-based authentication for robust /api/stats access.
func isAuthed(r *http.Request) bool {
	// API Token Check (for /api/stats robust access)
	if cfg.WebUI.APIToken != "" {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			if authHdr[7:] == cfg.WebUI.APIToken {
				return true
			}
		}
		if r.URL.Query().Get("token") == cfg.WebUI.APIToken {
			return true
		}
	}

	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	sessMu.Lock()
	ok := c.Value == sessToken && sessToken != "" && time.Now().Before(sessExp)
	sessMu.Unlock()
	return ok
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
		// Protects the admin interface against Clickjacking, MIME-sniffing, XSS, and Data Exfiltration.
		// Note: CSP 'unsafe-inline' is structurally required here because all UI components, 
		// stylesheets, and scripts are embedded natively within the Go binary templates.
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

		// ---------------------------------------------------------------------------
		// Brute-Force Lockout Check (Public Resolver Hardening)
		// ---------------------------------------------------------------------------
		// If an IP is currently locked out due to too many failed login attempts, we
		// drop the connection entirely without interacting. By panicking with
		// http.ErrAbortHandler, we instruct the underlying Go net/http server to
		// abruptly sever the TCP connection without returning any HTTP headers or body.
		loginStatesMu.Lock()
		if state, exists := loginStates[ipStr]; exists && cfg.WebUI.LoginRatelimit.Enabled && state.attempts >= cfg.WebUI.LoginRatelimit.MaxAttempts {
			if time.Now().After(state.lockoutExpires) {
				// Lockout period has naturally expired; reset the attempts counter.
				state.attempts = 0
				log.Printf("[WEBUI] SECURITY: IP %s lockout expired. Access restored.", ipStr)
			} else {
				// Debounce the silent-drop log to once every 10 seconds per IP to prevent log floods.
				if time.Since(state.lastDropLog) > 10*time.Second {
					state.lastDropLog = time.Now()
					log.Printf("[WEBUI] SECURITY: Silently dropping connection from %s (IP is locked out until %s)", ipStr, state.lockoutExpires.Format("15:04:05"))
				}
				loginStatesMu.Unlock()
				
				// Silently drop the connection. This satisfies the requirement to "just drop
				// the connection all together at connect-time, do not interact at all".
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
		if err == nil && hasWebUIACL {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				addr = addr.Unmap()
				
				// Deny rules take precedence over allow lists
				for _, p := range webUIACLDeny {
					if p.Contains(addr) {
						http.Error(w, "Forbidden - ACL Deny", http.StatusForbidden)
						return
					}
				}
				
				// Allow rules verify boundary
				if len(webUIACLAllow) > 0 {
					allowed := false
					for _, p := range webUIACLAllow {
						if p.Contains(addr) {
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
		}

		next(w, r)
	}
}

// WebUIMux is exported so server.go can safely multiplex Web UI routes onto DoH listeners.
var WebUIMux *http.ServeMux

// StartWebUI starts the admin HTTP/HTTPS servers. No-op when cfg.WebUI.Enabled is false.
func StartWebUI(tlsConf *tls.Config) {
	if !cfg.WebUI.Enabled {
		log.Println("[WEBUI] Disabled via config (webui.enabled: false).")
		return
	}
	if cfg.WebUI.Password == "" {
		log.Println("[WEBUI] No password configured — web UI disabled.")
		return
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
				ReadHeaderTimeout: 5 * time.Second, // Hardened
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    4096,
				ErrorLog:          log.New(io.Discard, "", 0), // Suppress generic scanner noise natively
			}
			log.Printf("[WEBUI] Admin UI (HTTP) at http://%s", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[WEBUI] HTTP Server error on %s: %v", addr, err)
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
			log.Printf("[WEBUI] Admin UI (HTTPS) multiplexed natively on DoH listener at https://%s", addr)
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
				ReadHeaderTimeout: 5 * time.Second, // Hardened
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    4096,
				ErrorLog:          log.New(io.Discard, "", 0), // Suppress handshake EOF noise natively
			}
			log.Printf("[WEBUI] Admin UI (HTTPS) at https://%s", addr)
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[WEBUI] HTTPS Server error on %s: %v", addr, err)
			}
		}()
	}
}

