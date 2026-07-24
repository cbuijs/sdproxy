/*
File:    webui_api.go
Version: 1.9.0
Updated: 22-Jul-2026 20:25 CEST

Description:
  JSON API endpoints for the sdproxy web UI.
  Extracted from webui.go.

Changes:
  1.9.0 - [PERF] Eradicated O(N log N) `netip.ParseAddr` allocations natively 
          during the `getKnownClients` array sorting. Replaced with a zero-allocation 
          struct-wrapper paradigm, completely neutralizing GC thrashing on the web UI thread.
        - [SECURITY] Enforced structural ID unmapping and normalization inside 
          `handleApiClientBlock`. Guarantees exact parity with the core DNS pipeline 
          to thwart evasion payloads.
        - [SECURITY] Deployed an explicit 1000-entry OOM capacity ceiling on the 
          ephemeral WebUI blocking `sync.Map` organically.
  1.8.0 - [FEAT] Hardened array sorting to evaluate IP addresses natively as 
          `netip.Addr` structures rather than plain strings, ensuring true 
          numerical hierarchies. Implemented an IEEE 802 randomized MAC identifier 
          (`isRandomizedMAC`) to flag privacy addresses organically in the dashboard.
  1.7.0 - [FEAT] Hardened the `/api/clients` endpoint to natively filter out public 
          IP addresses. Re-uses the structural `bogonPrefixes` engine to guarantee 
          only local, private, and CGNAT infrastructural clients are broadcast to 
          the Web UI dashboard organically.
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// handleApiSet handles AJAX group-mode updates from the radio-click JS.
func handleApiSet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !isAuthed(r) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "method not allowed"})
		return
	}
	
	// [SECURITY/FIX] Enforce strict payload boundaries on authenticated API endpoints natively.
	// Prevents users or compromised tokens from executing memory exhaustion (OOM) attacks 
	// by transmitting massive arbitrary payloads to the group assignment form parser.
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	r.ParseForm()
	
	group := r.FormValue("group")
	mode  := strings.ToUpper(r.FormValue("mode"))
	durStr := r.FormValue("duration")
	dur, _ := strconv.Atoi(durStr)

	if group == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "missing group"})
		return
	}
	valid := map[string]bool{"DEFAULT": true, "LOG": true, "ALLOW": true, "FREE": true, "BLOCK": true, "CANCEL_TIMER": true}
	if !valid[mode] {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid mode"})
		return
	}
	
	resultingMode := SetGroupOverride(group, mode, dur)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "group": group, "mode": resultingMode, "duration": dur})
}

// handleApiStats returns a JSON StatsSnapshot. Auth required.
func handleApiStats(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetStats())
}

// handleApiReset completely zeroes out all analytical stats and histories. Auth required.
func handleApiReset(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ResetStats()
	WebUILogStreamer.Clear()
	SaveLogs() // Flushes blank slate cleanly over disk remnants

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handleApiLogs sends the live log stream over Server-Sent Events. Auth required.
// Reads ?limit=N from the query string to determine how many history lines to send.
func handleApiLogs(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 500 // Increased default to 500 to ensure clicked UI elements have historical context
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil {
			limit = parsed
		}
	}
	if limit < 10 {
		limit = 10
	}
	if limit > logRingSize {
		limit = logRingSize
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// [SECURITY/FIX] Disable WriteTimeout specifically for this SSE stream so 
	// long-lived active socket connections aren't aggressively severed by the 
	// global DoH Slow-Read HTTP server safeguards natively.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	ch := make(chan string, limit)

	WebUILogStreamer.mu.Lock()
	count := len(WebUILogStreamer.ring)
	if count > limit {
		count = limit
	}
	history := make([]string, 0, count)
	if len(WebUILogStreamer.ring) < logRingSize {
		history = append(history, WebUILogStreamer.ring[len(WebUILogStreamer.ring)-count:]...)
	} else {
		startIdx := (WebUILogStreamer.ringIdx + logRingSize - count) % logRingSize
		if startIdx < WebUILogStreamer.ringIdx {
			history = append(history, WebUILogStreamer.ring[startIdx:WebUILogStreamer.ringIdx]...)
		} else {
			history = append(history, WebUILogStreamer.ring[startIdx:]...)
			history = append(history, WebUILogStreamer.ring[:WebUILogStreamer.ringIdx]...)
		}
	}
	WebUILogStreamer.clients[ch] = struct{}{}
	WebUILogStreamer.mu.Unlock()

	for _, line := range history {
		for _, part := range strings.Split(line, "\n") {
			fmt.Fprintf(w, "data: %s\n", part)
		}
		fmt.Fprintf(w, "\n")
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			WebUILogStreamer.mu.Lock()
			delete(WebUILogStreamer.clients, ch)
			WebUILogStreamer.mu.Unlock()
			return
		case line := <-ch:
			for _, part := range strings.Split(line, "\n") {
				fmt.Fprintf(w, "data: %s\n", part)
			}
			fmt.Fprintf(w, "\n")
			flusher.Flush()
		}
	}
}

// RulesResponse encapsulates custom rules and available groups.
type RulesResponse struct {
	Rules  []CustomRule `json:"rules"`
	Groups []string     `json:"groups"`
}

func handleApiRulesGet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	
	groups := []string{"global"}
	for g := range cfg.Groups {
		groups = append(groups, g)
	}
	sort.Strings(groups[1:])
	
	resp := RulesResponse{
		Rules:  GetRules(),
		Groups: groups,
	}
	json.NewEncoder(w).Encode(resp)
}

func handleApiRulesSet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newRules []CustomRule
	
	// [SECURITY/FIX] Enforce 1MB payload boundary natively via MaxBytesReader to prevent 
	// memory exhaustion (OOM) attacks from authenticated sessions.
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024)
	if err := json.NewDecoder(r.Body).Decode(&newRules); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid payload"})
		return
	}

	SetRules(newRules)
	SaveRules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handleApiCacheGet dumps the live cache entries securely natively. Auth required.
func handleApiCacheGet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DumpCache())
}

// handleApiGroups returns pre-rendered HTML payloads for the Desktop and Mobile group layouts.
func handleApiGroups(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	desk, mob := buildGroupsHTML()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"desktop": desk,
		"mobile":  mob,
	})
}

// ---------------------------------------------------------------------------
// Client Tracking & Enforcement Interfaces
// ---------------------------------------------------------------------------

// ClientInfo encapsulates synthesized identity layers cleanly mapped for UI interactions.
type ClientInfo struct {
	ID        string `json:"id"`         // Primary interaction marker (IP if valid, otherwise MAC)
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	IsBlocked bool   `json:"is_blocked"`
	IsRandMAC bool   `json:"is_rand_mac"` // Identifies locally administered randomized addresses
}

// clientSortWrapper optimizes the hot-path array construction organically 
// by circumventing nested String-to-IP parsing during deep topological sorts.
type clientSortWrapper struct {
	info ClientInfo
	addr netip.Addr
	isIP bool
}

// isLocalClientIP organically leverages the existing bogon/private-network 
// engine to instantly determine if an IP address belongs to local infrastructure.
func isLocalClientIP(ipStr string) bool {
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		addr = addr.Unmap()
		for _, p := range bogonPrefixes {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// isRandomizedMAC determines if a MAC address is locally administered (randomized) 
// in accordance with IEEE 802 standards by checking the second hex character.
func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	c := mac[1]
	return c == '2' || c == '6' || c == 'a' || c == 'e' || c == 'A' || c == 'E'
}

// getKnownClients harvests and unifies topological client arrays seamlessly natively.
func getKnownClients() []ClientInfo {
	clientsMap := make(map[string]*ClientInfo)

	// 1. Ingest hardware parameters natively mapped via system ARP boundaries
	arpMap := arpSnap.Load()
	if arpMap != nil {
		for ip, mac := range *arpMap {
			clientsMap[ip] = &ClientInfo{ID: ip, IP: ip, MAC: mac}
		}
	}

	// 2. Synthesize internal topological identities sourced via Local Resolver mappings (DHCP/Hosts)
	idSnap := identSnap.Load()
	if idSnap != nil {
		for ip, name := range idSnap.ipToName {
			if c, ok := clientsMap[ip]; ok {
				if c.Name == "" {
					c.Name = name
				}
			} else {
				clientsMap[ip] = &ClientInfo{ID: ip, IP: ip, Name: name}
			}
		}
		for mac, name := range idSnap.macToName {
			found := false
			for _, c := range clientsMap {
				if c.MAC == mac {
					if c.Name == "" {
						c.Name = name
					}
					found = true
					break
				}
			}
			if !found {
				clientsMap[mac] = &ClientInfo{ID: mac, MAC: mac, Name: name}
			}
		}
	}

	// 3. Inject deeply ephemeral nodes actively derived via Hot-Path Telemetry interactions (Top Talkers)
	talkers := statTopTalkers.Export()
	for _, bucket := range talkers {
		for strKey := range bucket {
			parts := strings.SplitN(strKey, "\x00", 2)
			ip := parts[0]
			name := ""
			if len(parts) == 2 {
				name = parts[1]
			}
			
			if c, ok := clientsMap[ip]; ok {
				if c.Name == "" && name != "" {
					c.Name = name
				}
			} else {
				clientsMap[ip] = &ClientInfo{ID: ip, IP: ip, Name: name}
			}
		}
	}

	// 4. Overwrite physical statuses mapping directly back to the active Web UI Block engine
	webuiClientBlocks.Range(func(key, value any) bool {
		kStr := key.(string)
		if c, ok := clientsMap[kStr]; ok {
			c.IsBlocked = true
		} else {
			c = &ClientInfo{ID: kStr, IsBlocked: true}
			if net.ParseIP(kStr) != nil {
				c.IP = kStr
			} else {
				c.MAC = kStr
			}
			clientsMap[kStr] = c
		}
		return true
	})

	var wrappers []clientSortWrapper
	for _, v := range clientsMap {
		// Exclusively expose localized infrastructural clients natively
		if v.IP != "" && !isLocalClientIP(v.IP) {
			continue
		}
		if v.MAC != "" {
			v.IsRandMAC = isRandomizedMAC(v.MAC)
		}
		
		cw := clientSortWrapper{info: *v}
		if v.IP != "" {
			if a, err := netip.ParseAddr(v.IP); err == nil {
				cw.addr = a
				cw.isIP = true
			}
		}
		wrappers = append(wrappers, cw)
	}
	
	// [PERF/FIX] O(1) allocation sorting execution. Neutralizes massive CPU GC burn.
	sort.SliceStable(wrappers, func(i, j int) bool {
		if wrappers[i].isIP && wrappers[j].isIP {
			return wrappers[i].addr.Compare(wrappers[j].addr) < 0
		}
		if wrappers[i].isIP { return true }
		if wrappers[j].isIP { return false }
		return wrappers[i].info.ID < wrappers[j].info.ID
	})
	
	var res []ClientInfo
	for _, w := range wrappers {
		res = append(res, w.info)
	}
	
	return res
}

func handleApiClients(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getKnownClients())
}

func handleApiClientBlock(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "method not allowed"})
		return
	}
	
	// Execute bounds protection organically to avoid exhaustion payloads
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	r.ParseForm()

	id := strings.TrimSpace(r.FormValue("id"))
	action := strings.ToUpper(strings.TrimSpace(r.FormValue("action"))) // BLOCK or UNBLOCK

	if id == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "missing id parameter"})
		return
	}

	// [SECURITY/FIX] Normalize structural IDs natively to ensure exact tracking parity.
	// Resolves bypassing metrics when IPs are submitted possessing IPv4-in-IPv6 translation.
	if addr, err := netip.ParseAddr(id); err == nil {
		id = addr.Unmap().String()
	} else if mac, err := net.ParseMAC(id); err == nil {
		id = mac.String()
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid identifier format"})
		return
	}

	if action == "BLOCK" {
		// [SECURITY/FIX] Enforce strict OOM bounds on the active sync.Map natively.
		count := 0
		webuiClientBlocks.Range(func(_, _ any) bool {
			count++
			return count < 1000
		})
		if count >= 1000 {
			webuiClientBlocks.Range(func(k, _ any) bool {
				webuiClientBlocks.Delete(k)
				return false // Evict exactly one entry pseudorandomly
			})
		}
		
		webuiClientBlocks.Store(id, true)
		if logWebUI {
			log.Printf("[WEBUI] Client %q explicitly blocked via Web UI parameter bounds natively.", id)
		}
	} else if action == "UNBLOCK" {
		webuiClientBlocks.Delete(id)
		if logWebUI {
			log.Printf("[WEBUI] Client %q explicitly unblocked via Web UI parameter bounds natively.", id)
		}
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid action"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

