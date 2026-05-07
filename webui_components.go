/*
File:    webui_components.go
Version: 1.16.0
Updated: 06-May-2026 14:35 CEST

Description:
  HTML String builders, template injection, and UI logic for the sdproxy web UI.

Changes:
  1.16.0 - [UI] Injected `<label class="filter-invert">` wrapper containing the 
           invert checkbox into the Modal HTML templates natively to support 
           inverse (NOT) grepping.
  1.15.0 - [UI] Migrated `.modal-body` and `.table-wrap` layouts within the Data Tables
           to enforce strict `flex-direction: column` scrolling contexts. This guarantees
           `position: sticky` securely pins column headers organically during vertical scrolls.
  1.14.0 - [UI] Refined Cache Inspector modal column widths and alignments. 
           Integrated live filter/grep input box for cache entries natively.
  1.13.3 - [UI] Added `sortable-th` classes and `data-sort` properties to the 
           Cache Inspector table headers to natively support client-side sorting.
  1.13.2 - [UI] Standardized `Cache Inspector` modal dimensions to match `Query Log` 
           and enforced strict table column layouts to prevent horizontal scrolling.
  1.13.1 - [FIX] Hardened string concatenation boundaries in `mainPage` to prevent 
           build failures during compilation natively.
  1.13.0 - [FEAT] Added the `Cache` inspection modal builder logic natively. 
           Securely bridges dynamic memory array structures into a tabular HTML 
           dashboard format.
  1.12.0 - [UI] Implemented quick-add "+" button in Top-N lists to rapidly insert
           domains into the Custom Rules Editor.
  1.11.0 - [UI] Added `Custom Rules` modal string injection handlers securely.
*/

package main

import (
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Stat card builders
// ---------------------------------------------------------------------------

// buildStatCard renders one stat tile with a label above and value below.
func buildStatCard(id, val, label string) string {
	return `<div class="stat-card">` +
		`<div class="stat-lbl">` + esc(label) + `</div>` +
		`<div class="stat-val" id="` + id + `">` + esc(val) + `</div>` +
		`</div>`
}

// buildStatCardSub renders a stat tile with an extra sub-line below the value.
func buildStatCardSub(id, val, subID, sub, label, subLabel string) string {
	return `<div class="stat-card">` +
		`<div class="stat-lbl">` + esc(label) + `</div>` +
		`<div class="stat-val" id="` + id + `">` + esc(val) + `</div>` +
		`<div class="stat-lbl stat-lbl-since">` + esc(subLabel) + `</div>` +
		`<div class="stat-sub" id="` + subID + `">` + sub + `</div>` +
		`</div>`
}

// buildStatCardPct renders a stat tile with an extra sub-line for percentage stats.
func buildStatCardPct(id, val, subID, sub, label string) string {
	return `<div class="stat-card">` +
		`<div class="stat-lbl">` + esc(label) + `</div>` +
		`<div class="stat-val" id="` + id + `">` + esc(val) + `</div>` +
		`<div class="stat-sub" id="` + subID + `">` + esc(sub) + `</div>` +
		`</div>`
}

func buildHourlyGraph() string {
	if !cfg.WebUI.StatsGraphsEnabled {
		return ""
	}
	return `<div class="hchart-section">` +
		`<div class="section-label">&#9201; Activity &mdash; Retention Window</div>` +
		`<div class="hchart-outer">` +
		`<div class="hchart-layout">` +
		`<div class="hchart-y" id="hchart-y">` +
		`<span>0</span><span>0</span><span>0</span>` +
		`</div>` +
		`<div id="hourly-chart" class="hchart">` +
		`<span class="top10-none">Collecting data&hellip;</span>` +
		`</div>` +
		`</div>` +
		`<div class="hchart-legend">` +
		`<span class="hchart-dot hchart-fwd"></span>Forwarded` +
		`&nbsp;&nbsp;<span class="hchart-dot hchart-blk"></span>Blocked` +
		`</div></div></div>`
}

func buildStatsCacheRow(snap StatsSnapshot) string {
	if !cfg.Cache.Enabled {
		return ""
	}
	fill := "—"
	if snap.CacheCapacity > 0 {
		fill = fmt.Sprintf("%d / %d", snap.CacheEntries, snap.CacheCapacity)
	}
	return `<div class="stats-grid stats-grid-extra">` +
		buildStatCard("st-cache",   fill,                             "Cache Fill") +
		buildStatCardPct("st-dropped", fmt.Sprintf("%d", snap.Dropped), "st-dropped-sub", snap.DroppedPct, "Dropped") +
		buildStatCardPct("st-dropped-up", fmt.Sprintf("%d", snap.DroppedUpstream), "st-dropped-up-sub", snap.DroppedUpstreamPct, "Dropped Upstream") +
		`</div>`
}

func buildTopNTable(title, tbodyID string, rows []TopEntry, topN int, scrollStyle string) string {
	var b strings.Builder
	b.WriteString(`<div class="top10-panel">`)
	b.WriteString(`<div class="top10-title">` + esc(title) + `</div>`)
	b.WriteString(`<div class="top10-tbl-wrap"` + scrollStyle + `>`)
	b.WriteString(`<table class="top10-tbl"><tbody id="` + tbodyID + `">`)
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="3"><span class="top10-none">No data yet</span></td></tr>`)
	} else {
		for i, row := range rows {
			rawName := row.Name
			filterStr := rawName
			if tbodyID == "top-domains" || tbodyID == "top-blocked" || tbodyID == "top-nxdomain" {
				filterStr = "-> " + rawName + "."
			} else if tbodyID == "top-tlds" {
				if !strings.HasPrefix(filterStr, ".") {
					filterStr = "." + filterStr
				}
				filterStr = filterStr + "."
			} else if tbodyID == "top-groups" {
				filterStr = "(" + rawName + ")"
			} else if tbodyID == "top-upstreams" {
				filterStr = "ROUTE: " + rawName + " ("
			} else if tbodyID == "top-upstream-hosts" {
				filterStr = "UPSTREAM: " + rawName
			}

			fTerm := strings.ReplaceAll(filterStr, "&", "&amp;")
			fTerm = strings.ReplaceAll(fTerm, "<", "&lt;")
			fTerm = strings.ReplaceAll(fTerm, "\"", "&quot;")
			n := esc(rawName)

			var hintHtml string
			if row.Hint != "" {
				if tbodyID == "top-talkers" {
					n = esc(row.Hint) + " (" + n + ")"
				} else if tbodyID == "top-blocked" || tbodyID == "top-tlds" || tbodyID == "top-block-reasons" || tbodyID == "top-filtered-ips" {
					hintHtml = `<span class="reason-badge">` + esc(row.Hint) + `</span>`
				}
			}
			
			linkedName := `<a href="#" class="qlog-link" data-filter="` + fTerm + `" title="View in Query Log">` + n + `</a>`

			var addRuleBtn string
			if tbodyID == "top-domains" || tbodyID == "top-blocked" || tbodyID == "top-nxdomain" {
				addRuleBtn = `<button class="top10-add-rule" data-domain="` + esc(rawName) + `" title="Add to Custom Rules">+</button>`
			}

			b.WriteString(`<tr>` +
				`<td class="top10-rank">` + fmt.Sprintf("%d", i+1) + `</td>` +
				`<td class="top10-name">` + linkedName + hintHtml + `</td>` +
				`<td class="top10-cnt">` + fmt.Sprintf("%d", row.Count) + addRuleBtn + `</td>` +
				`</tr>`)
		}
	}
	b.WriteString(`</tbody></table></div>`) 
	b.WriteString(`</div>`)                 
	return b.String()
}

// ---------------------------------------------------------------------------
// Group status helpers
// ---------------------------------------------------------------------------

type statusResult struct {
	text string
	cls  string
}

func computeStatus(name, sk string, _ GroupConfig) statusResult {
	if sk == "" {
		sk = name
	}
	parentalStateMu.RLock()
	gs, ok := groupStates[sk]
	parentalStateMu.RUnlock()
	if !ok {
		return statusResult{"No data yet", "st-muted"}
	}
	gs.mu.Lock()
	defer gs.mu.Unlock()

	if gs.hardBlocked["total"] {
		return statusResult{"Blocked: total (config)", "st-block"}
	}
	if rem, limited := gs.remaining["total"]; limited && rem <= 0 {
		return statusResult{"Blocked: total budget exhausted", "st-block"}
	}

	seen := make(map[string]bool)
	var cats []string
	for c := range gs.remaining {
		if c != "total" && !seen[c] {
			seen[c] = true
			cats = append(cats, c)
		}
	}
	for c := range gs.hardBlocked {
		if c != "total" && !seen[c] {
			seen[c] = true
			cats = append(cats, c)
		}
	}
	sort.Strings(cats)

	for _, cat := range cats {
		if gs.hardBlocked[cat] {
			return statusResult{"Blocked: " + esc(cat) + " (config)", "st-block"}
		}
		if rem, ok := gs.remaining[cat]; ok && rem <= 0 {
			return statusResult{"Blocked: " + esc(cat) + " budget exhausted", "st-block"}
		}
	}
	return statusResult{"Allowed", "st-ok"}
}

func renderBadge(sr statusResult, extraClass ...string) string {
	if sr.text == "" {
		return ""
	}
	cls := "sbadge"
	if len(extraClass) > 0 && extraClass[0] != "" {
		cls += " " + extraClass[0]
	}
	return `<span class="` + cls + ` ` + sr.cls + `">` + sr.text + `</span>`
}

func buildGroupDetail(name string, grp GroupConfig, clients int, curMode string) string {
	var b strings.Builder
	b.WriteString(`<div class="detail">`)

	isDeviceTracking := strings.ToLower(grp.BudgetTracking) == "device"
	sk := ""
	if !isDeviceTracking {
		sk = name
	}
	status := computeStatus(name, sk, grp)

	upstream := grp.Upstream
	if upstream == "" {
		upstream = `<span class="muted">inherited</span>`
	} else {
		upstream = esc(upstream)
	}
	tracking := grp.BudgetTracking
	if tracking == "" {
		tracking = "group"
	}

	b.WriteString(`<div class="meta">`)
	b.WriteString(`<span>Upstream: <b>` + upstream + `</b></span>`)
	b.WriteString(`<span>Tracking: <b>` + esc(tracking) + `</b></span>`)
	b.WriteString(fmt.Sprintf(`<span>Devices/IPs: <b>%d</b></span>`, clients))
	b.WriteString(renderBadge(status, "group-badge"))
	b.WriteString(`</div>`)

	// Override Banner Context Injection
	if curMode != "DEFAULT" {
		var cls, desc string
		switch curMode {
		case "ALLOW":
			cls = "st-allow"
			desc = "All time limits, schedules, and explicit blocks are currently <b>bypassed</b>."
		case "FREE":
			cls = "st-free"
			desc = "Time limits and schedules are <b>suspended</b>. Explicit category blocks still apply natively."
		case "BLOCK":
			cls = "st-block"
			desc = "Internet access is <b>completely cut</b> for this group."
		case "LOG":
			cls = "st-log"
			desc = "Log-only mode. All restrictions are bypassed, but categorical queries are heavily logged."
		}
		if cls != "" {
			b.WriteString(`<div class="override-banner ` + cls + `">`)
			b.WriteString(`&#9888; <strong>OVERRIDE (` + curMode + `):</strong> ` + desc)
			b.WriteString(`</div>`)
		}
	}

	if len(grp.Schedule) > 0 {
		b.WriteString(`<div class="sched-pills">`)
		for _, s := range grp.Schedule {
			b.WriteString(`<span class="pill">` + esc(s) + `</span>`)
		}
		b.WriteString(`</div>`)
	}

	if isDeviceTracking {
		parentalStateMu.RLock()
		var deviceKeys []string
		for k := range groupStates {
			if stateToGroup[k] == name {
				deviceKeys = append(deviceKeys, k)
			}
		}
		parentalStateMu.RUnlock()
		sort.Strings(deviceKeys)

		if len(deviceKeys) == 0 {
			b.WriteString(`<div class="muted-line" style="margin-top: 10px;">No device activity yet. Budgets will populate when a client makes a query.</div>`)
		} else {
			for _, dk := range deviceKeys {
				parentalStateMu.RLock()
				gs, ok := groupStates[dk]
				parentalStateMu.RUnlock()
				if !ok {
					continue
				}
				
				live := make(map[string]int64)
				isRed := false
				isOrange := false

				gs.mu.Lock()
				for k, v := range gs.remaining { live[k] = v }
				lastIP   := gs.lastClientIP
				lastName := gs.lastClientName

				// Compute Dynamic Header Color Code (True State Only)
				if curMode != "ALLOW" && curMode != "LOG" {
					if len(grp.Schedule) > 0 && !inAnyScheduleWindow(grp.Schedule) && curMode != "FREE" {
						isRed = true // Global Schedule is blocked
					} else if gs.hardBlocked["total"] {
						isRed = true // The entire group is configured to block by default
					} else if rem, limited := gs.remaining["total"]; limited && rem <= 0 && curMode != "FREE" {
						isRed = true // Total umbrella time is exhausted
					} else if curMode != "FREE" {
						for key, rem := range gs.remaining {
							if key != "total" && rem <= 0 {
								isOrange = true // A specific category is exhausted
								break
							}
						}
					}
				}
				gs.mu.Unlock()

				hdrClass := ""
				if curMode == "BLOCK" {
					hdrClass = " dev-hdr-block" // Mode Override (Red)
				} else if curMode == "ALLOW" {
					hdrClass = " dev-hdr-allow" // Mode Override (Green)
				} else if curMode == "FREE" {
					hdrClass = " dev-hdr-free"  // Mode Override (Yellow)
				} else if curMode == "LOG" {
					hdrClass = " dev-hdr-log"   // Mode Override (Blue)
				} else if isRed {
					hdrClass = " dev-hdr-block" // True State Restricted (Red)
				} else if isOrange {
					hdrClass = " dev-hdr-warn"  // True State Category Exhausted (Yellow)
				}

				deviceID := dk
				if parts := strings.SplitN(dk, "/", 2); len(parts) == 2 {
					deviceID = parts[1]
				}

				label := deviceID
				if lastName != "" && lastName != deviceID {
					if lastIP != "" && lastIP != deviceID {
						label = fmt.Sprintf("%s (%s, %s)", lastName, deviceID, lastIP)
					} else {
						label = fmt.Sprintf("%s (%s)", lastName, deviceID)
					}
				} else if lastIP != "" && lastIP != deviceID {
					label = fmt.Sprintf("%s (%s)", deviceID, lastIP)
				}
				
				// Collapsible details card for Device Tracking
				b.WriteString(`<details class="dev-section">`)
				b.WriteString(`<summary class="dev-hdr` + hdrClass + `">`)
				b.WriteString(`<div style="display:flex; align-items:center;">`)
				b.WriteString(`<span class="dev-name">` + esc(label) + `</span>`)
				b.WriteString(`</div>`)
				b.WriteString(`</summary>`)
				b.WriteString(`<div class="dev-table-wrap">`)
				b.WriteString(renderBudgetTable(collectBudgetRows(grp, live), curMode))
				b.WriteString(`</div>`)
				b.WriteString(`</details>`)
			}
		}
	} else {
		// Group Tracking Mode
		parentalStateMu.RLock()
		gs, ok := groupStates[name]
		parentalStateMu.RUnlock()

		live := make(map[string]int64)
		isRed := false
		isOrange := false

		if ok {
			gs.mu.Lock()
			for k, v := range gs.remaining { live[k] = v }

			// Compute Dynamic Header Color Code (True State Only)
			if curMode != "ALLOW" && curMode != "LOG" {
				if len(grp.Schedule) > 0 && !inAnyScheduleWindow(grp.Schedule) && curMode != "FREE" {
					isRed = true // Global Schedule is blocked
				} else if gs.hardBlocked["total"] {
					isRed = true // The entire group is configured to block by default
				} else if rem, limited := gs.remaining["total"]; limited && rem <= 0 && curMode != "FREE" {
					isRed = true // Total umbrella time is exhausted
				} else if curMode != "FREE" {
					for key, rem := range gs.remaining {
						if key != "total" && rem <= 0 {
							isOrange = true // A specific category is exhausted
							break
						}
					}
				}
			}
			gs.mu.Unlock()
		}

		hdrClass := ""
		if curMode == "BLOCK" {
			hdrClass = " dev-hdr-block" // Mode Override (Red)
		} else if curMode == "ALLOW" {
			hdrClass = " dev-hdr-allow" // Mode Override (Green)
		} else if curMode == "FREE" {
			hdrClass = " dev-hdr-free"  // Mode Override (Yellow)
		} else if curMode == "LOG" {
			hdrClass = " dev-hdr-log"   // Mode Override (Blue)
		} else if isRed {
			hdrClass = " dev-hdr-block" // True State Restricted (Red)
		} else if isOrange {
			hdrClass = " dev-hdr-warn"  // True State Category Exhausted (Yellow)
		}

		// Static styled card for Group Tracking
		b.WriteString(`<div class="dev-section" style="margin-top: 10px;">`)
		b.WriteString(`<div class="dev-hdr` + hdrClass + `">`)
		b.WriteString(`<div style="display:flex; align-items:center;">`)
		b.WriteString(`<span class="dev-name">Group Budget</span>`)
		b.WriteString(`</div>`)
		b.WriteString(`</div>`)
		b.WriteString(`<div class="dev-table-wrap">`)
		b.WriteString(renderBudgetTable(collectBudgetRows(grp, live), curMode))
		b.WriteString(`</div>`)
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div>`)
	return b.String()
}

func buildMobileCard(name, cur string, grp GroupConfig, clients int, detail, durSel string) string {
	modeClass := map[string]string{
		"DEFAULT": "st-ok", "LOG": "st-log", "ALLOW": "st-allow", "FREE": "st-free", "BLOCK": "st-block",
	}
	modeLabel := map[string]string{
		"DEFAULT": "Default (normal)",
		"LOG":     "Override: LOG \u2014 log-only bypass",
		"ALLOW":   "Override: ALLOW \u2014 bypass all restrictions",
		"FREE":    "Override: FREE \u2014 suspend time/sched limits",
		"BLOCK":   "Override: BLOCK \u2014 internet cut",
	}

	bc := modeClass[cur]
	if bc == "" {
		bc = "st-ok"
	}
	bl := modeLabel[cur]
	if bl == "" {
		bl = "Default (normal)"
	}

	var b strings.Builder
	b.WriteString(`<div class="card" data-group="` + esc(name) + `">`)
	b.WriteString(`<div class="card-header">`)
	b.WriteString(`<span class="card-name">` + esc(name) + `</span>`)
	b.WriteString(`<span id="timer_m_` + esc(name) + `" class="timer-badge hidden" data-group="` + esc(name) + `" title="Cancel timer"></span>`)
	b.WriteString(`<span class="sbadge group-badge ` + bc + `">` + bl + `</span>`)
	b.WriteString(`</div>`)

	b.WriteString(`<div style="padding: 8px 14px; border-bottom: 1px solid var(--border-light); display: flex; flex-direction: column; gap: 4px;">`)
	b.WriteString(`<div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.85em;"><span>Override Duration:</span>` + durSel + `</div>`)
	b.WriteString(`<div style="font-size: 0.75em; color: var(--text-hint); text-align: right;">(Set duration first, then select mode)</div>`)
	b.WriteString(`</div>`)

	b.WriteString(`<div class="radio-grid">`)
	for _, mode := range []string{"DEFAULT", "LOG", "ALLOW", "FREE", "BLOCK"} {
		chk := ""
		if cur == mode {
			chk = " checked"
		}
		b.WriteString(`<label class="radio-btn mode-` + strings.ToLower(mode) + `">` +
			`<input type="radio" name="m_` + esc(name) + `" value="` + mode + `"` + chk + `> ` +
			mode + `</label>`)
	}
	b.WriteString(`</div>`)

	b.WriteString(`<details><summary class="detail-toggle">Details</summary>`)
	b.WriteString(detail)
	b.WriteString(`</details>`)
	b.WriteString(`</div>`)
	return b.String()
}

type budgetRow struct {
	key        string
	configured string
	remaining  string
	exhausted  bool
	isAllow    bool
	isBlock    bool
	isFree     bool
	isLog      bool
}

func collectBudgetRows(grp GroupConfig, liveRemaining map[string]int64) []budgetRow {
	if len(grp.Budget) == 0 {
		return nil
	}
	keys := make([]string, 0, len(grp.Budget))
	for k := range grp.Budget {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := make([]budgetRow, 0, len(keys))
	for _, k := range keys {
		raw := grp.Budget[k]
		row := budgetRow{key: k, configured: raw}
		switch strings.ToUpper(raw) {
		case "ALLOW":
			row.isAllow   = true
			row.remaining = "—"
		case "BLOCK":
			row.isBlock   = true
			row.remaining = "—"
		case "FREE":
			row.isFree    = true
			row.remaining = "—"
		case "LOG":
			row.isLog     = true
			row.remaining = "—"
		default:
			if liveRemaining != nil {
				if rem, ok := liveRemaining[k]; ok {
					if rem <= 0 {
						row.exhausted  = true
						row.remaining  = "exhausted"
					} else {
						row.remaining = fmtSeconds(rem)
					}
				} else {
					row.remaining = "—"
				}
			} else {
				row.remaining = "—"
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func renderBudgetTable(rows []budgetRow, curMode string) string {
	if len(rows) == 0 {
		return `<div class="muted-line">no budget entries</div>`
	}
	var b strings.Builder
	b.WriteString(`<table class="btable"><thead><tr>` +
		`<th>Category</th><th>Limit</th><th>Remaining</th>` +
		`</tr></thead><tbody>`)
	for _, r := range rows {
		remCls, cfgCls := "", ""
		remStr := r.remaining

		// Apply dynamic state text if the current mode intercepts the physical budget constraints
		if !r.isAllow && !r.isBlock && !r.isFree && !r.isLog { // Standard time limit
			if curMode == "ALLOW" || curMode == "FREE" || curMode == "LOG" {
				remStr = `<span class="muted">suspended (` + curMode + `)</span>`
				r.exhausted = false // Remove red highlight
			} else if curMode == "BLOCK" {
				remStr = `<span class="muted">blocked (` + curMode + `)</span>`
				r.exhausted = false
			}
		} else if r.isBlock && (curMode == "ALLOW" || curMode == "LOG") { // Bypass explicit block
			remStr = `<span class="muted">bypassed (` + curMode + `)</span>`
		} else if r.isAllow && curMode == "BLOCK" { // Hard-block an explicit allow
			remStr = `<span class="muted">blocked (` + curMode + `)</span>`
		}

		switch {
		case r.exhausted: remCls = ` class="rem-exhausted"`
		case r.isAllow:   remCls = ` class="rem-allow"`
		case r.isBlock:   remCls = ` class="rem-block"`
		case r.isFree:    remCls = ` class="rem-free"`
		case r.isLog:     remCls = ` class="rem-log"`
		}
		switch {
		case r.isAllow: cfgCls = ` class="cfg-allow"`
		case r.isBlock: cfgCls = ` class="cfg-block"`
		case r.isFree:  cfgCls = ` class="cfg-free"`
		case r.isLog:   cfgCls = ` class="cfg-log"`
		}
		b.WriteString(`<tr>`)
		b.WriteString(`<td class="bkey">` + esc(r.key) + `</td>`)
		b.WriteString(`<td` + cfgCls + `>` + esc(r.configured) + `</td>`)
		b.WriteString(`<td` + remCls + `>` + remStr + `</td>`)
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	return s
}

func mainPage(title, body string) string {
	return `<!doctype html><html lang="en"><head>` +
		`<meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + esc(title) + `</title>` +
		`<script>` +
		`(function(){var t=localStorage.getItem('sdp_theme')||'auto';` +
		`if(t!=='auto')document.documentElement.setAttribute('data-theme',t);})();` +
		`</script>` +
		`<style>` + css + `</style>` +
		`</head><body>` +
		`<div class="wrap">` + body + `</div>` +
		`<div class="toast" id="sdp-toast"></div>` +
		
		// ---------------------------------------------------------------------------
		// Query Log Modal
		// ---------------------------------------------------------------------------
		`<div id="qlog-modal" class="modal">` +
		`<div class="modal-content" id="qlog-modal-content">` +
		`<!-- 8-way custom resize handles -->` +
		`<div class="resizer n"></div><div class="resizer e"></div><div class="resizer s"></div><div class="resizer w"></div>` +
		`<div class="resizer nw"></div><div class="resizer ne"></div><div class="resizer sw"></div><div class="resizer se"></div>` +
		`<div class="modal-header" id="qlog-modal-header" title="Drag to move, double-click to maximize">` +
		`<div class="modal-header-top">` +
		`<h3>Live Query Log</h3>` +
		`<button id="qlog-close">&times;</button>` +
		`</div>` +
		`<div class="modal-header-bot">` +
		`<div style="display:flex; align-items:center; gap:8px; flex:1; min-width:200px; max-width:450px;">` +
		`<div class="filter-box" style="flex:1; min-width:0; max-width:none;">` +
		`<input type="text" id="qlog-filter" placeholder="Filter (grep)...">` +
		`<button id="qlog-clear" class="hidden" title="Clear filter">&times;</button>` +
		`</div>` +
		`<label class="filter-invert" title="Show entries NOT matching the filter"><input type="checkbox" id="qlog-invert"> Invert</label>` +
		`</div>` +
		`<div class="log-meta">` +
		`<span>Last</span>` +
		`<button id="qlog-limit-minus" class="limit-btn" title="Decrease limit">&minus;</button>` +
		`<input type="number" id="qlog-limit" value="500" min="10" max="5000" step="50" class="limit-input" title="Number of lines to keep">` +
		`<button id="qlog-limit-plus" class="limit-btn" title="Increase limit">&#43;</button>` +
		`<span>messages</span>` +
		`<span id="qlog-time-range" class="time-range-txt"></span>` +
		`</div>` +
		`<button id="qlog-tail" class="hidden">Live &#x2193;</button>` +
		`<div class="zoom-controls">` +
		`<button id="qlog-zoom-out" title="Decrease font size (Zoom Out)">&minus;</button>` +
		`<button id="qlog-zoom-reset" title="Default font size (Reset)">=</button>` +
		`<button id="qlog-zoom-in" title="Increase font size (Zoom In)">&#43;</button>` +
		`</div>` +
		`</div>` +
		`</div>` +
		`<div class="modal-body" id="qlog-lines"></div>` +
		`</div>` +
		`</div>` +

		// ---------------------------------------------------------------------------
		// Custom Rules Editor Modal
		// ---------------------------------------------------------------------------
		`<div id="rules-modal" class="modal">` +
		`<div class="modal-content" style="max-width: 650px; left: 50%; top: 5vh; transform: translateX(-50%); height: 85vh;">` +
		`<div class="modal-header">` +
		`<div class="modal-header-top">` +
		`<h3>Custom Rules</h3>` +
		`<button id="rules-close" style="background:none;border:none;font-size:1.6em;cursor:pointer;color:var(--text-muted);">&times;</button>` +
		`</div>` +
		`<p style="font-size:0.85em; color:var(--text-dim); margin-top:6px;">Allowlist or blocklist specific domains (including subdomains) per-group or globally.</p>` +
		`</div>` +
		`<div class="modal-body" style="background:var(--bg-body); color:var(--text-main); font-family:inherit; font-size: 0.9em; padding: 0; display: flex; flex-direction: column; overflow: hidden;">` +
		`<div class="table-wrap" style="border-radius:0; box-shadow:none; border:none; flex: 1; overflow-y: auto;">` +
		`<table class="rules-table" style="border-radius:0; border:none; width: 100%;">` +
		`<thead class="sticky-th"><tr>` +
		`<th style="text-align:left;">Domain</th>` +
		`<th>Group</th>` +
		`<th>Action</th>` +
		`<th>Active</th>` +
		`<th></th>` +
		`</tr></thead>` +
		`<tbody id="rules-tbody"></tbody>` +
		`</table>` +
		`</div>` +
		`<div style="padding:16px;">` +
		`<button id="btn-add-rule" class="pill" style="cursor:pointer; padding:6px 12px;">+ Add Rule</button>` +
		`</div>` +
		`</div>` +
		`<div style="padding:14px 16px; border-top:1px solid var(--border-light); background:var(--bg-alt); display:flex; justify-content:flex-end; gap:10px;">` +
		`<button id="rules-cancel" class="btn-cancel" style="padding:8px 16px;">Cancel</button>` +
		`<button id="rules-save" class="btn-clear" style="padding:8px 16px; background:var(--accent); color:#fff;">Save Changes</button>` +
		`</div>` +
		`</div>` +
		`</div>` +

		// ---------------------------------------------------------------------------
		// Cache Inspector Modal
		// ---------------------------------------------------------------------------
		`<div id="cache-modal" class="modal">` +
		`<div class="modal-content" id="cache-modal-content">` +
		`<div class="modal-header" id="cache-modal-header">` +
		`<div class="modal-header-top">` +
		`<h3>Cache Inspector</h3>` +
		`<div style="display:flex; gap: 12px; align-items: center;">` +
		`<button id="btn-cache-refresh" class="pill" style="cursor:pointer; padding:4px 10px;">Refresh</button>` +
		`<button id="cache-close" style="background:none;border:none;font-size:1.6em;cursor:pointer;color:var(--text-muted); line-height: 1;">&times;</button>` +
		`</div>` +
		`</div>` +
		`<div class="modal-header-bot">` +
		`<div style="display:flex; align-items:center; gap:8px; flex:1; min-width:200px; max-width:450px;">` +
		`<div class="filter-box" style="flex:1; min-width:0; max-width:none;">` +
		`<input type="text" id="cache-filter" placeholder="Filter cache (grep)...">` +
		`<button id="cache-clear" class="hidden" title="Clear filter">&times;</button>` +
		`</div>` +
		`<label class="filter-invert" title="Show entries NOT matching the filter"><input type="checkbox" id="cache-invert"> Invert</label>` +
		`</div>` +
		`</div>` +
		`</div>` +
		`<div class="modal-body" style="background:var(--bg-body); color:var(--text-main); font-family:inherit; font-size: 0.9em; padding: 0; display: flex; flex-direction: column; overflow: hidden;">` +
		`<div class="table-wrap" style="border-radius:0; box-shadow:none; border:none; flex: 1; overflow-y: auto;">` +
		`<table class="rules-table" style="border-radius:0; border:none; width: 100%; table-layout: fixed;">` +
		`<thead class="sticky-th"><tr>` +
		`<th class="sortable-th" data-sort="qname" style="text-align:left; width: 28%;">Domain (QNAME)<span class="sort-icon"></span></th>` +
		`<th class="sortable-th" data-sort="qtype" style="text-align:center; width: 5%;">Type<span class="sort-icon"></span></th>` +
		`<th class="sortable-th" data-sort="route" style="text-align:center; width: 12%;">Upstream<span class="sort-icon"></span></th>` +
		`<th class="sortable-th" data-sort="response" style="text-align:left; width: 32%;">Response<span class="sort-icon"></span></th>` +
		`<th class="sortable-th" data-sort="hits" style="text-align:center; width: 5%;">Hits<span class="sort-icon"></span></th>` +
		`<th class="sortable-th" data-sort="cachedat" style="text-align:center; width: 10%;">Cached At<span class="sort-icon"></span></th>` +
		`<th class="sortable-th" data-sort="ttl" style="text-align:center; width: 5%;">TTL<span class="sort-icon"></span></th>` +
		`<th style="text-align:center; width: 3%;"></th>` +
		`</tr></thead>` +
		`<tbody id="cache-tbody"></tbody>` +
		`</table>` +
		`</div>` +
		`</div>` +
		`</div>` +
		`</div>` +

		// ---------------------------------------------------------------------------
		// Reset Confirm Modal
		// ---------------------------------------------------------------------------
		`<div id="reset-modal" class="modal">` +
		`<div class="confirm-modal-content">` +
		`<h3>Reset Statistics</h3>` +
		`<p>Are you sure you want to reset all statistics, historic data, query logs, and top lists?</p>` +
		`<p style="color: var(--block-text); font-weight: 600; margin-top: 8px;">This action cannot be undone.</p>` +
		`<div class="confirm-btns">` +
		`<button id="reset-cancel" class="btn-cancel">CANCEL</button>` +
		`<button id="reset-confirm" class="btn-clear">CLEAR</button>` +
		`</div>` +
		`</div>` +
		`</div>` +

		`<script>` + uiScript + `</script>` +
		`</body></html>`
}

