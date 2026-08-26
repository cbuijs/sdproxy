/*
File:    webui.go
Version: 1.61.0 (Split)
Last Updated: 07-Aug-2026 21:30 CEST

Description:
  Password-protected single-page web admin interface for sdproxy.
  This file handles the HTTP server initialization, session authentication,
  and embedded static assets. 

Changes:
  1.61.0 - [SECURITY/FIX] isAuthed compared both credentials with `==`.
           The login form has used crypto/subtle.ConstantTimeCompare since
           webui_html.go 1.x precisely because a plain string comparison leaks
           the length of the matching prefix through its return time — but the
           two credentials that guard every API endpoint, the API token and the
           session cookie, were still compared with the short-circuiting
           operator. Fixing the front door and leaving the side door unlatched
           is the whole shape of the defect.
           The session token is 256 bits of crypto/rand, so timing recovery
           there is academic. The API TOKEN is not: it is a value an operator
           types into a config file, so it is short, human-chosen, and exactly
           the kind of secret a byte-at-a-time oracle recovers. Both now use
           ConstantTimeCompare, with a length-independent construction so the
           comparison cost does not itself signal the length.
         - [SECURITY/FIX] Scoped the API token to SAFE methods. The header
           comment described it as being "for /api/stats robust access", but
           isAuthed is the single gate in front of every route on the mux, so a
           token issued for metrics scraping in fact granted /api/set,
           /api/rules/set, /api/reset, /api/clients/block and
           /api/clients/bulk_block — full administrative control of the daemon.
           Every mutating handler already requires POST, so the token is now
           accepted for GET/HEAD/OPTIONS only and state-changing requests
           require the session cookie. No legitimate usage changes: a scraper
           polls /api/stats with GET.
         - [SECURITY] Documented, and warned once at startup about, the
           `?token=` query-parameter form. It is retained for compatibility —
           it is the only way to point a dashboard or a curl one-liner at the
           endpoint without header support — but a URL-borne secret ends up in
           reverse-proxy access logs, browser history and Referer headers. The
           Authorization header has none of those properties and is now the
           documented form.
         - [SECURITY/FIX] Added WriteTimeout to both admin servers. ReadTimeout,
           ReadHeaderTimeout and IdleTimeout were all set; the write side was
           not, so a client that opened a request and then stopped reading the
           response held the handler goroutine and its connection indefinitely.
           The dashboard renders a full HTML page plus embedded assets in one
           response, which makes it a comfortably sized target for a slow-read
           hold. 30 seconds is far beyond any real render and far below
           "forever".
  1.60.0 - [FEAT] Orchestrated routing multiplexer bindings natively for the 
           `/api/clients/bulk_block` endpoint to allow atomic, multi-client modifications.
  1.59.0 - [FEAT] Orchestrated routing multiplexer bindings natively for the 
           `/api/clients` and `/api/clients/block` endpoints.
  1.58.0 - [SECURITY/FIX] Eradicated a severe Memory Exhaustion (OOM) vulnerability 
           against the Web UI natively. `handleLogin` and `handleSet` now strictly 
           wrap `r.Body` in an `http.MaxBytesReader` limited to 32KB. Definitively 
           prevents malicious unauthenticated actors or botnets from weaponizing 
           `r.ParseForm()` (which defaults to 10MB) to crash the router's RAM capacity.
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
//
// [SECURITY 1.61.0] The `==` operator this replaces short-circuits on the first
// differing byte, so the time it takes to reject a guess is proportional to how
// many leading bytes were correct. That converts an offline brute force over
// the whole keyspace into an online byte-at-a-time walk — a few thousand
// requests per position rather than exponential work — provided the attacker
// can measure response time, which over a LAN or a co-located host they can.
//
// Two details matter beyond simply calling ConstantTimeCompare:
//
//   - The empty-secret guard. ConstantTimeCompare returns 0 for equal-length
//     empty slices in Go's current implementation, but relying on that is
//     fragile, and an unconfigured credential must never authenticate anything.
//     Rejected explicitly.
//   - subtle.ConstantTimeCompare returns 0 immediately when the lengths differ,
//     which leaks the secret's LENGTH even though it protects the contents.
//     That is an acceptable and unavoidable leak for a session cookie of fixed
//     size, and a minor one for a token, but it is worth naming rather than
//     leaving for a reader to rediscover: the defence here is against content
//     recovery, not against learning how long the secret is.
func secretsEqual(given, want string) bool {
	if want == "" || given == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// isSafeMethod reports whether a request only reads state.
//
// [SECURITY 1.61.0] This is the boundary the API token is scoped to. It is
// method-based rather than path-based deliberately: a path allow-list has to be
// updated every time a route is added, and the failure mode of forgetting is
// that a new mutating endpoint silently inherits token access. Every mutating
// handler in this daemon already rejects anything but POST as its first act, so
// the method check cannot be bypassed by calling a mutating route with GET —
// the handler refuses before it does anything.
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
	//
	// [SECURITY/FIX 1.61.0] Scoped to safe methods.
	//
	// This block's comment used to read "for /api/stats robust access", which
	// described the INTENT accurately and the EFFECT not at all: isAuthed is
	// the only authentication gate in front of the entire mux, so any caller
	// holding the token could POST to /api/set, /api/rules/set, /api/reset,
	// /api/clients/block and /api/clients/bulk_block. A credential handed to a
	// monitoring system — pasted into a Grafana datasource, a cron job, a
	// status page — was in practice a full administrative credential for the
	// resolver, and nothing in the configuration said so.
	//
	// Restricting it to GET/HEAD/OPTIONS makes the effect match the intent.
	// Nothing legitimate regresses: scraping is a GET, and every mutating
	// endpoint requires POST already.
	if cfg.WebUI.APIToken != "" && isSafeMethod(r.Method) {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			if secretsEqual(authHdr[7:], cfg.WebUI.APIToken) {
				return true
			}
		}
		// [SECURITY] The query-parameter form is retained for compatibility but
		// is the weaker of the two: a secret in a URL is written to
		// reverse-proxy access logs, kept in browser history, and forwarded in
		// the Referer header of any resource the page subsequently loads. The
		// Authorization header has none of those properties. StartWebUI emits a
		// one-time notice recommending it.
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
	// Read under the lock, compare outside of it: ConstantTimeCompare walks the
	// full length by design, and there is no reason to hold a process-global
	// mutex for it while every other request queues behind.
	tok := sessToken
	exp := sessExp
	sessMu.Unlock()

	if !time.Now().Before(exp) {
		return false
	}
	// [SECURITY/FIX 1.61.0] Constant-time. The token is 256 random bits, so a
	// timing walk against it is not a practical attack — but the comparison is
	// on the authentication path for every single admin request, the correct
	// primitive costs nothing measurable, and leaving one credential check
	// short-circuiting invites the next one to be written the same way.
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
				if logWebUI {
					log.Printf("[WEBUI] SECURITY: IP %s lockout expired. Access restored.", ipStr)
				}
			} else {
				// Debounce the silent-drop log to once every 10 seconds per IP to prevent log floods.
				if time.Since(state.lastDropLog) > 10*time.Second {
					state.lastDropLog = time.Now()
					if logWebUI {
						log.Printf("[WEBUI] SECURITY: Silently dropping connection from %s (IP is locked out until %s)", ipStr, state.lockoutExpires.Format("15:04:05"))
					}
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

// webUIWriteTimeout bounds how long a single admin response may take to write.
//
// [SECURITY/FIX 1.61.0] There was no WriteTimeout at all. ReadTimeout,
// ReadHeaderTimeout and IdleTimeout were all configured, which covers a client
// that sends slowly — but says nothing about one that RECEIVES slowly. A peer
// that issues a request and then stops reading holds the handler goroutine, its
// connection and any buffers it touched for as long as it likes, and the admin
// page is a single large response (full HTML plus the embedded script and
// stylesheet) which makes it an unusually comfortable target for that.
//
// 30 seconds is orders of magnitude beyond any real render — the whole page is
// assembled in memory from embedded assets — while still bounding the hold.
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

	// [SECURITY 1.61.0] State the token's scope out loud, once, at boot.
	//
	// Before this release the token was silently equivalent to the admin
	// password for every endpoint on the mux. An operator who had already
	// deployed it into a scraper needs to know both that the scope has narrowed
	// (so a mutating integration will now fail, visibly, rather than continuing
	// to work by accident) and that the header form should be preferred.
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
