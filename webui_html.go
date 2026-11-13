/*
File:    webui_html.go
Version: 1.30.0
Last Updated: 04-Nov-2026 20:25 CET

Description:
  HTTP Request Handlers and authentication logic for the sdproxy web UI.

Changes:
  1.30.0 - [SECURITY/FIX] Zeroed `sessExp` alongside `sessToken` in `handleLogout`,
           and ensured failed login and lockout security logs are emitted when
           `logWebUI` or `logSystem` is active.
  1.29.0 - [CLEANUP] Suppressed routine successful-login log lines when `logSimple`
           is enabled unless preceded by failed login attempts (`state.attempts > 0`),
           while keeping all failed login and lockout security warnings active.
  1.28.0 - [SECURITY/FIX] Validated that `key` exists in `cfg.Groups` in `handleSet`
           before calling `SetGroupOverride`.
  1.27.0 - [FIX] Delegated `Group overrides` HTML rendering in `handleRoot` to
           `buildGroupsSectionHTML()` so empty group configurations completely
           omit the Group overrides tables and headers on initial load.
  1.26.0 - [SECURITY/FIX] Replaced blind random map eviction in `loginStates` with a
           2-tier sampled eviction policy (`evictLoginStateLocked`).
  1.25.0 - [SECURITY/FIX] Re-applied `http.MaxBytesReader` (32KB limit) inside
           `handleLogin` and `handleSet`, and enforced `POST`-only method checks
           on `/set` and `/logout`.
  1.24.0 - [SECURITY/FIX] Leveraged the centralized `secretsEqual` primitive for password verification.
  1.23.0 - [FEAT] Injected the `clientBlockPanel` natively into the `handleRoot` HTML layout.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	groupsSection := buildGroupsSectionHTML()
	clientBlockPanel := buildClientsHTML()

	var statsPanel string
	if cfg.WebUI.StatsEnabled {
		refreshSec := cfg.WebUI.StatsRefreshSec
		if refreshSec < 5 {
			refreshSec = 30
		}
		topN := cfg.WebUI.StatsTopN
		if topN < 5 {
			topN = 10
		}
		if topN > 100 {
			topN = 100
		}

		snap := GetStats()

		tSince := time.Unix(snap.SinceUnix, 0).Local()
		sinceParts := tSince.Format("02-Jan-2006") + "<br>" + tSince.Format("15:04:05")

		scrollStyle := ""
		if topN > 10 {
			scrollStyle = ` style="max-height:300px;overflow-y:auto"`
		}

		cacheFill := "—"
		if snap.CacheCapacity > 0 {
			cacheFill = fmt.Sprintf("%d / %d", snap.CacheEntries, snap.CacheCapacity)
		}

		statsPanel = `<div class="section-divider"></div>` +
			fmt.Sprintf(`<div id="sdp-stats" class="stats-section" data-refresh="%d" data-topn="%d" data-graphs="%v">`, refreshSec, topN, cfg.WebUI.StatsGraphsEnabled) +
			`<div class="stats-hdr">` +
			`<span class="stats-title">&#9685; Statistics</span>` +
			fmt.Sprintf(`<span class="stats-age" id="st-age">refreshes every `+
				`<button id="st-ref-minus" class="ref-btn" title="Decrease interval (min 5s)">&minus;</button>`+
				`<input type="number" id="st-ref-val" class="ref-input" value="%d" min="5" max="300" step="5">`+
				`<button id="st-ref-plus" class="ref-btn" title="Increase interval (max 300s)">&#43;</button> secs`+
				`<button id="st-ref-now" class="ref-btn" title="Refresh Now" style="margin-left:6px; width:22px; display:flex; align-items:center; justify-content:center;">`+
				`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path></svg>`+
				`</button>`+
				`<button id="st-reset-now" class="ref-btn" title="Reset Statistics" style="margin-left:6px; width:22px; display:flex; align-items:center; justify-content:center; color: var(--block-text);">`+
				`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`+
				`</button></span>`, refreshSec) +
			`</div>` +
			`<div class="stats-grid">` +
			buildStatCardSub("st-uptime", snap.Uptime, "st-since", sinceParts, "Uptime", "Running since") +
			buildStatCardSub("st-qps-cur", fmt.Sprintf("%.1f", snap.QPSCurrent), "st-qps-sub", fmt.Sprintf("L: %.1f | A: %.1f | H: %.1f", snap.QPSLow, snap.QPSAverage, snap.QPSHigh), "QPS (Current)", "Low / Avg / High") +
			buildStatCardSub("st-queries", fmt.Sprintf("%d", snap.TotalQueries), "st-queries-sub", fmt.Sprintf("Fwd: %d | Blk: %d", snap.Forwarded, snap.Blocked), "Queries (Total)", "Forwarded / Blocked") +
			buildStatCardSub("st-cache", snap.CacheHitRate, "st-cache-sub", fmt.Sprintf("Hits: %d | Fill: %s", snap.CacheHits, cacheFill), "Cache Performance", "Hits / Fill") +
			`</div>` +
			`</div>` +
			buildHourlyGraph() +
			`<div class="section-divider"></div>` +
			`<div class="section-label" style="text-align:center">Top Queries</div>` +
			`<div class="top10-wrap-2col">` +
			buildTopNTable("Queried Domains", "top-domains", snap.TopDomains, topN, scrollStyle) +
			buildTopNTable("Blocked Domains", "top-blocked", snap.TopBlocked, topN, scrollStyle) +
			buildTopNTable("Top NXDOMAIN", "top-nxdomain", snap.TopNXDomain, topN, scrollStyle) +
			buildTopNTable("Top Talkers", "top-talkers", snap.TopTalkers, topN, scrollStyle) +
			buildTopNTable("Top Filtered IPs", "top-filtered-ips", snap.TopFilteredIPs, topN, scrollStyle) +
			`</div>` +
			`<div class="top10-wrap-3col">` +
			buildTopNTable("Top Categories", "top-categories", snap.TopCategories, topN, scrollStyle) +
			buildTopNTable("Top TLDs/eTLDs", "top-tlds", snap.TopTLDs, topN, scrollStyle) +
			buildTopNTable("Top Vendors", "top-vendors", snap.TopVendors, topN, scrollStyle) +
			buildTopNTable("Top Groups", "top-groups", snap.TopGroups, topN, scrollStyle) +
			buildTopNTable("Top Block Reasons", "top-block-reasons", snap.TopBlockReasons, topN, scrollStyle) +
			buildTopNTable("Top Upstream Groups", "top-upstreams", snap.TopUpstreams, topN, scrollStyle) +
			buildTopNTable("Top Upstream Hosts", "top-upstream-hosts", snap.TopUpstreamHosts, topN, scrollStyle) +
			buildTopNTable("Top Return Codes", "top-return-codes", snap.TopReturnCodes, topN, scrollStyle) +
			`</div>` +
			`<div class="section-divider"></div>`
	}

	body := `<div class="header" style="flex-wrap: wrap; gap: 12px;">` +
		`<div>` +
		`<h2 style="margin:0;line-height:1.2;">sdproxy <span class="sub">admin</span></h2>` +
		`<div style="font-size:.75em;opacity:.7;color:var(--text-muted);margin-top:2px;">` + esc(BuildVersion) + `</div>` +
		`</div>` +
		`<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">` +
		`<div class="theme-toggle">` +
		`<button id="theme-light" title="Light Theme">&#x2600;</button>` +
		`<button id="theme-auto" title="Auto Theme">&#x25D0;</button>` +
		`<button id="theme-dark" title="Dark Theme">&#x263D;</button>` +
		`</div>` +
		`<a href="#" id="btn-cache" class="logout">Cache</a>` +
		`<a href="#" id="btn-custom-rules" class="logout">Custom Rules</a>` +
		`<a href="#" id="btn-qlog" class="logout">Query Log</a>` +
		`<form method="POST" action="/logout" style="display:inline;margin:0;"><button type="submit" class="logout" style="background:none;cursor:pointer;font-family:inherit;">logout</button></form>` +
		`</div>` +
		`</div>` +

		groupsSection +
		clientBlockPanel +
		statsPanel

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(mainPage("sdproxy — admin", body)))
}

type loginState struct {
	attempts       int
	lockoutExpires time.Time
	lastDropLog    time.Time
}

var (
	loginStates   = make(map[string]*loginState)
	loginStatesMu sync.Mutex
)

func evictLoginStateLocked(now time.Time) {
	var (
		bestKey      string
		bestAttempts int
		bestFound    bool
		bestUnpunish bool
		scanned      int
	)
	for k, st := range loginStates {
		unpunished := st.attempts == 0 || (!st.lockoutExpires.IsZero() && now.After(st.lockoutExpires))
		better := !bestFound ||
			(unpunished && !bestUnpunish) ||
			(unpunished == bestUnpunish && st.attempts < bestAttempts)
		if better {
			bestKey, bestAttempts, bestUnpunish, bestFound = k, st.attempts, unpunished, true
		}
		scanned++
		if scanned >= 32 {
			break
		}
	}
	if bestFound {
		delete(loginStates, bestKey)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if isAuthed(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ipStr = r.RemoteAddr
	}

	if parsedAddr, err := netip.ParseAddr(ipStr); err == nil {
		ipStr = parsedAddr.Unmap().WithZone("").String()
	}

	var errHTML string

	loginStatesMu.Lock()
	state, exists := loginStates[ipStr]
	if !exists {
		if len(loginStates) >= 10000 {
			evictLoginStateLocked(time.Now())
		}
		state = &loginState{}
		loginStates[ipStr] = state
	}
	loginStatesMu.Unlock()

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if secretsEqual(r.FormValue("password"), cfg.WebUI.Password) {
			loginStatesMu.Lock()
			if logWebUI || logSystem {
				if state.attempts > 0 {
					log.Printf("[WEBUI] Successful login from %s after %d failed attempt(s).", ipStr, state.attempts)
				} else if !logSimple && logWebUI {
					log.Printf("[WEBUI] Successful login from %s.", ipStr)
				}
			}
			state.attempts = 0
			loginStatesMu.Unlock()

			tok := newSession()
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    tok,
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   8 * 3600,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		loginStatesMu.Lock()
		if cfg.WebUI.LoginRatelimit.Enabled {
			state.attempts++
			if state.attempts >= cfg.WebUI.LoginRatelimit.MaxAttempts {
				mins := cfg.WebUI.LoginRatelimit.LockoutMinutes
				if mins <= 0 {
					mins = 15
				}
				state.lockoutExpires = time.Now().Add(time.Duration(mins) * time.Minute)
				if logWebUI || logSystem {
					log.Printf("[WEBUI] SECURITY: IP %s locked out for %d minutes due to %d consecutive failed login attempts.", ipStr, mins, state.attempts)
				}
				loginStatesMu.Unlock()
				panic(http.ErrAbortHandler)
			} else {
				if logWebUI || logSystem {
					log.Printf("[WEBUI] WARNING: Failed login attempt from %s (%d/%d before lockout).", ipStr, state.attempts, cfg.WebUI.LoginRatelimit.MaxAttempts)
				}
				errHTML = `<p class="err">Wrong password.</p>`
			}
		} else {
			if logWebUI || logSystem {
				log.Printf("[WEBUI] WARNING: Failed login attempt from %s (Rate limiting disabled).", ipStr)
			}
			errHTML = `<p class="err">Wrong password.</p>`
		}
		loginStatesMu.Unlock()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(mainPage("sdproxy — login",
		`<div class="login-wrap"><div class="login-box">`+
			`<h2 style="margin-bottom:2px; text-align:center;">sdproxy admin</h2>`+
			`<div style="font-size:.75em;font-weight:400;color:var(--text-muted);margin-bottom:22px;text-align:center;">`+esc(BuildVersion)+`</div>`+
			`<form method="POST" action="/login">`+
			`<label>Password</label>`+
			`<input type="password" name="password" autofocus autocomplete="current-password">`+
			`<button type="submit">Login</button>`+
			`</form>`+errHTML+
			`</div></div>`)))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sessMu.Lock()
	sessToken = ""
	sessExp = time.Time{}
	sessMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleSet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	valid := map[string]bool{"DEFAULT": true, "LOG": true, "ALLOW": true, "FREE": true, "BLOCK": true, "CANCEL_TIMER": true}
	for key, vals := range r.Form {
		gKey := strings.ToLower(strings.TrimSpace(key))
		if _, exists := cfg.Groups[gKey]; !exists {
			continue
		}
		if len(vals) > 0 {
			if m := strings.ToUpper(strings.TrimSpace(vals[0])); valid[m] {
				durStr := r.FormValue("duration_" + key)
				dur, _ := strconv.Atoi(durStr)
				SetGroupOverride(gKey, m, dur)
			}
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
