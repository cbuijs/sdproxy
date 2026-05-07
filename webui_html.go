/*
File:    webui_html.go
Version: 1.15.1
Updated: 06-May-2026 13:51 CEST

Description:
  HTTP Request Handlers and authentication logic for the sdproxy web UI.

Changes:
  1.15.1 - [UI] Added `Cache` button to the top navigation bar to open the Cache Inspector.
  1.15.0 - [UI] Supported the new Custom Rules clone button logic.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
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

	names := make([]string, 0, len(cfg.Groups))
	for n := range cfg.Groups {
		names = append(names, n)
	}
	sort.Strings(names)

	// Dynamically map exact client counts loaded from both inline routes AND external routes_files
	clientCount := make(map[string]int, len(cfg.Groups))
	parentalStateMu.RLock()
	for k, v := range ParentalGroupClients {
		clientCount[k] = v
	}
	parentalStateMu.RUnlock()

	var tableRows   strings.Builder
	var mobileCards strings.Builder

	if len(names) == 0 {
		tableRows.WriteString(`<tr><td colspan="7" class="empty">No groups configured in config.yaml.</td></tr>`)
		mobileCards.WriteString(`<div class="empty">No groups configured in config.yaml.</div>`)
	}

	for _, name := range names {
		grp := cfg.Groups[name]

		groupOverrideMu.RLock()
		ovState := groupOverride[name]
		groupOverrideMu.RUnlock()

		cur := ovState.Mode
		if cur == "" {
			// No manual override. Base the default UI state on the total budget configuration.
			tot := strings.ToUpper(grp.Budget["total"])
			if tot == "FREE" || tot == "LOG" || tot == "ALLOW" || tot == "BLOCK" {
				cur = tot
			} else {
				cur = "DEFAULT"
			}
		}

		detail := buildGroupDetail(name, grp, clientCount[name], cur)

		// Common Duration Selector
		durSel := `<select name="duration_` + esc(name) + `" class="dur-sel" data-group="` + esc(name) + `">` +
			`<option value="0">Forever</option>` +
			`<option value="15">15 min</option>` +
			`<option value="30">30 min</option>` +
			`<option value="60">1 hour</option>` +
			`<option value="120">2 hours</option>` +
			`<option value="1440">24 hours</option>` +
			`</select>`

		// Desktop row: one radio per mode in five columns.
		var radios strings.Builder
		for _, mode := range []string{"DEFAULT", "LOG", "ALLOW", "FREE", "BLOCK"} {
			chk := ""
			if cur == mode {
				chk = " checked"
			}
			radios.WriteString(
				`<td><label class="mode-` + strings.ToLower(mode) + `">` +
					`<input type="radio" name="` + esc(name) +
					`" value="` + mode + `"` + chk + `> ` + mode +
					`</label></td>`)
		}
		tableRows.WriteString(
			`<tr class="group-row" data-group="` + esc(name) + `">` +
				`<td class="name-cell">` +
				`<details>` +
				`<summary class="group-name">` + esc(name) +
				` <span id="timer_` + esc(name) + `" class="timer-badge hidden" data-group="` + esc(name) + `" title="Cancel timer"></span>` +
				`</summary>` +
				detail + `</details>` +
				`</td>` + radios.String() + `<td>` + durSel + `</td></tr>`)

		mobileCards.WriteString(buildMobileCard(name, cur, grp, clientCount[name], detail, durSel))
	}

	// Stats panel — only rendered when stats_enabled: true.
	var statsPanel string
	if cfg.WebUI.StatsEnabled {
		refreshSec := cfg.WebUI.StatsRefreshSec
		if refreshSec < 5 {
			refreshSec = 30
		}
		topN := cfg.WebUI.StatsTopN
		if topN < 5  { topN = 10 }
		if topN > 100 { topN = 100 }

		snap := GetStats()

		// "Since" rendered as two lines: date and time separated by <br>.
		tSince := time.Unix(snap.SinceUnix, 0).Local()
		sinceParts := tSince.Format("02-Jan-2006") + "<br>" + tSince.Format("15:04:05")

		// Scrollable wrapper style is pre-computed server-side so it matches
		// the configured topN on first render (JS updates it live on refresh).
		scrollStyle := ""
		if topN > 10 {
			scrollStyle = ` style="max-height:300px;overflow-y:auto"`
		}

		statsPanel = `<div class="section-divider"></div>` +
			fmt.Sprintf(`<div id="sdp-stats" class="stats-section" data-refresh="%d" data-topn="%d" data-graphs="%v">`, refreshSec, topN, cfg.WebUI.StatsGraphsEnabled) +
			`<div class="stats-hdr">` +
			`<span class="stats-title">&#9685; Statistics</span>` +
			fmt.Sprintf(`<span class="stats-age" id="st-age">refreshes every `+
				`<button id="st-ref-minus" class="ref-btn" title="Decrease interval (min 5s)">&minus;</button>`+
				`<input type="number" id="st-ref-val" class="ref-input" value="%d" min="5" max="300" step="5">`+
				`<button id="st-ref-plus" class="ref-btn" title="Increase interval (max 300s)">&#43;</button> secs`+
				// Refresh Button
				`<button id="st-ref-now" class="ref-btn" title="Refresh Now" style="margin-left:6px; width:22px; display:flex; align-items:center; justify-content:center;">`+
				`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path></svg>`+
				`</button>`+
				// Reset Button
				`<button id="st-reset-now" class="ref-btn" title="Reset Statistics" style="margin-left:6px; width:22px; display:flex; align-items:center; justify-content:center; color: var(--block-text);">`+
				`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`+
				`</button></span>`, refreshSec) +
			`</div>` +
			`<div class="stats-grid">` +
			buildStatCardSub("st-uptime", snap.Uptime, "st-since", sinceParts, "Uptime", "Running since") +
			buildStatCardSub("st-qps-cur", fmt.Sprintf("%.1f", snap.QPSCurrent), "st-qps-sub", fmt.Sprintf("L: %.1f | A: %.1f | H: %.1f", snap.QPSLow, snap.QPSAverage, snap.QPSHigh), "QPS (Current)", "Low / Avg / High") +
			buildStatCard("st-total", fmt.Sprintf("%d", snap.TotalQueries), "Total Queries") +
			buildStatCardPct("st-hits", fmt.Sprintf("%d", snap.CacheHits), "st-hits-sub", snap.CacheHitsPct, "Cache Hits") +
			buildStatCard("st-hitrate", snap.CacheHitRate, "Hit Rate") +
			buildStatCardPct("st-fwd", fmt.Sprintf("%d", snap.Forwarded), "st-fwd-sub", snap.ForwardedPct, "Forwarded") +
			buildStatCardPct("st-blocked", fmt.Sprintf("%d", snap.Blocked), "st-blocked-sub", snap.BlockedPct, "Blocked") +
			`</div>` +
			buildStatsCacheRow(snap) +
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
		`<a href="/logout" class="logout">logout</a>` +
		`</div>` +
		`</div>` +

		// Desktop table (hidden at <640px via media query).
		`<div id="desk-form">` +
		`<div class="section-label">Group overrides</div>` +
		`<div class="table-wrap">` +
		`<table>` +
		`<thead><tr>` +
		`<th>Group <span class="th-hint">(click to expand)</span></th>` +
		`<th>DEFAULT</th><th>LOG</th><th>ALLOW</th><th>FREE</th><th>BLOCK</th>` +
		`<th>Duration <span style="display:block; font-size:0.85em; font-weight:400; color:var(--text-hint); text-transform:none; letter-spacing:0; margin-top:2px;">(Set duration first, then select mode)</span></th>` +
		`</tr></thead>` +
		`<tbody>` + tableRows.String() + `</tbody>` +
		`</table></div>` +
		`<div class="legend-bar">` +
		`<b>DEFAULT</b> normal &nbsp;·&nbsp; ` +
		`<b class="c-log">LOG</b> log-only &nbsp;·&nbsp; ` +
		`<b class="c-allow">ALLOW</b> bypass all &nbsp;·&nbsp; ` +
		`<b class="c-free">FREE</b> suspend limits &nbsp;·&nbsp; ` +
		`<b class="c-block">BLOCK</b> cut internet` +
		`</div></div>` +

		// Mobile card stack (shown at <640px via media query).
		`<div id="mob-form">` +
		`<div class="section-label">Group overrides</div>` +
		`<div class="cards">` + mobileCards.String() + `</div>` +
		`</div>` +

		statsPanel

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(mainPage("sdproxy — admin", body)))
}

// loginState tracks consecutive failed attempts to thwart brute-force cracking.
type loginState struct {
	attempts       int
	lockoutExpires time.Time
	lastDropLog    time.Time // Added to debounce silent-drop logs across connection floods
}

var (
	loginStates   = make(map[string]*loginState)
	loginStatesMu sync.Mutex
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if isAuthed(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	var errHTML string

	loginStatesMu.Lock()
	
	// Boundary Eviction: Preemptively safeguard the node from Memory Exhaustion 
	// by arbitrarily dropping an old entry if capacity thresholds are exceeded.
	if len(loginStates) >= 10000 {
		for k := range loginStates {
			delete(loginStates, k)
			break
		}
	}
	
	state, exists := loginStates[ip]
	if !exists {
		state = &loginState{}
		loginStates[ip] = state
	}
	// Initial brute-force limit checks are verified upstream in webUIMiddleware
	// to universally drop the connection without wasting memory/goroutines on rendering.
	loginStatesMu.Unlock()

	if r.Method == http.MethodPost {
		r.ParseForm()
		if r.FormValue("password") == cfg.WebUI.Password {
			loginStatesMu.Lock()
			if state.attempts > 0 {
				log.Printf("[WEBUI] Successful login from %s after %d failed attempt(s).", ip, state.attempts)
			} else {
				log.Printf("[WEBUI] Successful login from %s.", ip)
			}
			state.attempts = 0 // Reset on successful auth
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
				log.Printf("[WEBUI] SECURITY: IP %s locked out for %d minutes due to %d consecutive failed login attempts.", ip, mins, state.attempts)
				loginStatesMu.Unlock()
				
				// The threshold was just reached on this exact failed attempt.
				// Drop the connection immediately without sending an error page.
				// By panicking with http.ErrAbortHandler, we instruct the net/http server
				// to abort the TCP connection without sending any response.
				panic(http.ErrAbortHandler)
			} else {
				log.Printf("[WEBUI] Failed login attempt from %s (%d/%d before lockout).", ip, state.attempts, cfg.WebUI.LoginRatelimit.MaxAttempts)
				errHTML = `<p class="err">Wrong password.</p>`
			}
		} else {
			log.Printf("[WEBUI] Failed login attempt from %s (Rate limiting disabled).", ip)
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
	sessMu.Lock()
	sessToken = ""
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

// handleSet is a legacy form-POST fallback for non-JS environments.
func handleSet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	valid := map[string]bool{"DEFAULT": true, "LOG": true, "ALLOW": true, "FREE": true, "BLOCK": true, "CANCEL_TIMER": true}
	for key, vals := range r.Form {
		if len(vals) > 0 {
			if m := strings.ToUpper(vals[0]); valid[m] {
				// Try to find matching duration
				durStr := r.FormValue("duration_" + key)
				dur, _ := strconv.Atoi(durStr)
				SetGroupOverride(key, m, dur)
			}
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

