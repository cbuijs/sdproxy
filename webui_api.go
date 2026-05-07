/*
File:    webui_api.go
Version: 1.3.0
Updated: 07-May-2026 12:13 CEST

Description:
  JSON API endpoints for the sdproxy web UI.
  Extracted from webui.go.

Changes:
  1.3.0 - [SECURITY/FIX] Eliminated a Slow-Read Denial of Service vulnerability 
          against the `/api/logs` streaming endpoint. Dynamically injected an 
          `http.ResponseController` to lift the `WriteTimeout` bounds strictly 
          for authenticated SSE clients, enabling the global DoH multiplexer 
          to enforce rigorous Drop-Deadlines securely against attackers.
        - [SECURITY/FIX] Upgraded JSON boundary limiters in `/api/rules/set` to 
          leverage `http.MaxBytesReader` natively. Intercepts memory exhaustion 
          (OOM) streams during unmarshaling natively before hitting heap limitations.
*/

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

