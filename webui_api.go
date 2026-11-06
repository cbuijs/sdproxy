/*
File:    webui_api.go
Version: 1.20.0
Last Updated: 05-Nov-2026 15:15 CET

Description:
  JSON API endpoints for the sdproxy web UI.
  Extracted from webui.go.

Changes:
  1.20.0 - [CRITICAL/FIX] Enforced a per-write deadline (`rc.SetWriteDeadline(time.Now().Add(10 * time.Second))`)
           and error check on every SSE write/flush in `handleApiLogs`. Previously,
           `rc.SetWriteDeadline(time.Time{})` disabled write timeouts completely;
           a half-dead browser tab whose TCP receive window filled up caused
           `fmt.Fprintf` / `flusher.Flush()` to block forever, leaking the SSE
           goroutine and holding a TCP connection slot from `netutil.LimitListener`
           permanently until `max_tcp_connections` exhausted and the listener stalled.
  1.19.0 - [CLEANUP] Guarded routine runtime client block/unblock notices with
           `logWebUI && !logSimple`.
  1.18.0 - [SECURITY/FIX] Validated that `group` exists in `cfg.Groups` in
           `handleApiSet` before calling `SetGroupOverride`.
  1.17.0 - [FEAT/FIX] Included MAC addresses observed via `statClientSeen` in `getKnownClients`.
  1.16.0 - [SECURITY/FIX] Validated `Action` ("ALLOW" or "BLOCK") and stripped
           invalid or empty domains in `handleApiRulesSet`.
  1.15.0 - [SECURITY/FIX] Resolved an issue utilizing `sync.Map` in `webuiClientBlocks`.
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

func sendAPIError(w http.ResponseWriter, errStr string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": errStr})
}

func sendAPISuccess(w http.ResponseWriter, extra map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	res := map[string]interface{}{"ok": true}
	for k, v := range extra {
		res[k] = v
	}
	json.NewEncoder(w).Encode(res)
}

func handleApiSet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		sendAPIError(w, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		sendAPIError(w, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	r.ParseForm()

	group := strings.ToLower(strings.TrimSpace(r.FormValue("group")))
	mode := strings.ToUpper(strings.TrimSpace(r.FormValue("mode")))
	durStr := r.FormValue("duration")
	dur, _ := strconv.Atoi(durStr)

	if group == "" {
		sendAPIError(w, "missing group")
		return
	}
	if _, exists := cfg.Groups[group]; !exists {
		sendAPIError(w, "unknown group")
		return
	}
	valid := map[string]bool{"DEFAULT": true, "LOG": true, "ALLOW": true, "FREE": true, "BLOCK": true, "CANCEL_TIMER": true}
	if !valid[mode] {
		sendAPIError(w, "invalid mode")
		return
	}

	resultingMode := SetGroupOverride(group, mode, dur)
	sendAPISuccess(w, map[string]interface{}{"group": group, "mode": resultingMode, "duration": dur})
}

func handleApiStats(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetStats())
}

func handleApiReset(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		sendAPIError(w, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		sendAPIError(w, "method not allowed")
		return
	}

	ResetStats()
	WebUILogStreamer.Clear()
	SaveLogs()

	sendAPISuccess(w, nil)
}

func handleApiLogs(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 500
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

	rc := http.NewResponseController(w)

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

	defer func() {
		WebUILogStreamer.mu.Lock()
		delete(WebUILogStreamer.clients, ch)
		WebUILogStreamer.mu.Unlock()
	}()

	_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
	for _, line := range history {
		for _, part := range strings.Split(line, "\n") {
			if _, err := fmt.Fprintf(w, "data: %s\n", part); err != nil {
				return
			}
		}
		if _, err := fmt.Fprintf(w, "\n"); err != nil {
			return
		}
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-shutdownCh:
			return
		case line := <-ch:
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			for _, part := range strings.Split(line, "\n") {
				if _, err := fmt.Fprintf(w, "data: %s\n", part); err != nil {
					return
				}
			}
			if _, err := fmt.Fprintf(w, "\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

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
		sendAPIError(w, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		sendAPIError(w, "method not allowed")
		return
	}

	var newRules []CustomRule

	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024)
	if err := json.NewDecoder(r.Body).Decode(&newRules); err != nil {
		sendAPIError(w, "invalid payload")
		return
	}

	sanitized := make([]CustomRule, 0, len(newRules))
	for _, rule := range newRules {
		dom := normalizeDomain(rule.Domain)
		if dom == "" {
			continue
		}
		act := strings.ToUpper(strings.TrimSpace(rule.Action))
		if act != "ALLOW" && act != "BLOCK" {
			sendAPIError(w, "invalid rule action: "+rule.Action)
			return
		}
		grp := strings.ToLower(strings.TrimSpace(rule.Group))
		if grp == "" {
			grp = "global"
		}
		sanitized = append(sanitized, CustomRule{
			Domain:  dom,
			Action:  act,
			Group:   grp,
			Enabled: rule.Enabled,
		})
	}

	SetRules(sanitized)
	SaveRules()

	sendAPISuccess(w, nil)
}

func handleApiCacheGet(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DumpCache())
}

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

type ClientInfo struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Name      string `json:"name"`
	IsBlocked bool   `json:"is_blocked"`
	IsRandMAC bool   `json:"is_rand_mac"`
	LastSeen  int64  `json:"last_seen"`
}

type clientSortWrapper struct {
	info ClientInfo
	addr netip.Addr
	isIP bool
}

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

func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	c := mac[1]
	return c == '2' || c == '6' || c == 'a' || c == 'e' || c == 'A' || c == 'E'
}

func getKnownClients() []ClientInfo {
	clientsMap := make(map[string]*ClientInfo)

	arpMap := arpSnap.Load()
	if arpMap != nil {
		for ip, mac := range *arpMap {
			clientsMap[ip] = &ClientInfo{ID: ip, IP: ip, MAC: mac}
		}
	}

	byMAC := make(map[string]*ClientInfo, len(clientsMap))
	for _, c := range clientsMap {
		if c.MAC != "" {
			if _, seen := byMAC[c.MAC]; !seen {
				byMAC[c.MAC] = c
			}
		}
	}

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
			if c, found := byMAC[mac]; found {
				if c.Name == "" {
					c.Name = name
				}
				continue
			}
			entry := &ClientInfo{ID: mac, MAC: mac, Name: name}
			clientsMap[mac] = entry
			byMAC[mac] = entry
		}
	}

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

	seenSnap := statClientSeen.Snapshot()
	for k := range seenSnap {
		if _, exists := clientsMap[k]; exists {
			continue
		}
		if _, exists := byMAC[k]; exists {
			continue
		}
		if mac, err := net.ParseMAC(k); err == nil && len(mac) == 6 {
			macStr := mac.String()
			if _, exists := byMAC[macStr]; !exists {
				entry := &ClientInfo{ID: macStr, MAC: macStr}
				clientsMap[macStr] = entry
				byMAC[macStr] = entry
			}
		}
	}

	webuiClientBlocks.Range(func(key, value any) bool {
		kStr := key.(string)
		if c, ok := clientsMap[kStr]; ok {
			c.IsBlocked = true
		} else if c, ok := byMAC[kStr]; ok {
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
		if v.IP != "" && !isLocalClientIP(v.IP) {
			continue
		}
		if v.MAC != "" {
			v.IsRandMAC = isRandomizedMAC(v.MAC)
		}

		if v.IP != "" {
			if ts, ok := seenSnap[v.IP]; ok && ts > v.LastSeen {
				v.LastSeen = ts
			}
		}
		if v.MAC != "" {
			if ts, ok := seenSnap[v.MAC]; ok && ts > v.LastSeen {
				v.LastSeen = ts
			}
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

	sort.SliceStable(wrappers, func(i, j int) bool {
		if wrappers[i].isIP && wrappers[j].isIP {
			return wrappers[i].addr.Compare(wrappers[j].addr) < 0
		}
		if wrappers[i].isIP {
			return true
		}
		if wrappers[j].isIP {
			return false
		}
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
		sendAPIError(w, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		sendAPIError(w, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	r.ParseForm()

	id := strings.TrimSpace(r.FormValue("id"))
	action := strings.ToUpper(strings.TrimSpace(r.FormValue("action")))

	if id == "" {
		sendAPIError(w, "missing id parameter")
		return
	}

	if addr, err := netip.ParseAddr(id); err == nil {
		id = addr.Unmap().String()
	} else if mac, err := net.ParseMAC(id); err == nil {
		id = mac.String()
	} else {
		sendAPIError(w, "invalid identifier format")
		return
	}

	if action == "BLOCK" {
		count := 0
		webuiClientBlocks.Range(func(_, _ any) bool {
			count++
			return true
		})
		if count >= 1000 {
			webuiClientBlocks.Range(func(k, _ any) bool {
				webuiClientBlocks.Delete(k)
				return false
			})
		}

		webuiClientBlocks.Store(id, true)
		if logWebUI && !logSimple {
			log.Printf("[WEBUI] Client %q explicitly blocked via Web UI parameter bounds natively.", id)
		}
	} else if action == "UNBLOCK" {
		webuiClientBlocks.Delete(id)
		if logWebUI && !logSimple {
			log.Printf("[WEBUI] Client %q explicitly unblocked via Web UI parameter bounds natively.", id)
		}
	} else {
		sendAPIError(w, "invalid action")
		return
	}

	sendAPISuccess(w, nil)
}

func handleApiClientsBulkBlock(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		sendAPIError(w, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		sendAPIError(w, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	r.ParseForm()

	action := strings.ToUpper(strings.TrimSpace(r.FormValue("action")))

	if action != "BLOCK" && action != "UNBLOCK" {
		sendAPIError(w, "invalid action")
		return
	}

	clients := getKnownClients()
	modifiedCount := 0

	count := 0
	webuiClientBlocks.Range(func(_, _ any) bool {
		count++
		return true
	})

	for _, c := range clients {
		if c.IsRandMAC || c.Name == "" {
			if action == "BLOCK" {
				if _, exists := webuiClientBlocks.Load(c.ID); !exists {
					if count >= 1000 {
						webuiClientBlocks.Range(func(k, _ any) bool {
							webuiClientBlocks.Delete(k)
							count--
							return false
						})
					}
					webuiClientBlocks.Store(c.ID, true)
					count++
					modifiedCount++
				}
			} else if action == "UNBLOCK" {
				if _, exists := webuiClientBlocks.Load(c.ID); exists {
					webuiClientBlocks.Delete(c.ID)
					count--
					modifiedCount++
				}
			}
		}
	}

	if logWebUI && !logSimple {
		log.Printf("[WEBUI] Bulk %s applied to %d privacy/unnamed clients natively.", action, modifiedCount)
	}

	sendAPISuccess(w, map[string]interface{}{"modified": modifiedCount})
}
