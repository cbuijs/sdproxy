/*
File:    webui_logs.go
Description:
  Live Log Streaming (SSE) and persistence for the sdproxy web UI.
  Extracted from webui.go.
*/

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Live Log Streaming (SSE)
// ---------------------------------------------------------------------------

const logRingSize = 5000

type logBroadcaster struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	ring    []string
	ringIdx int
}

// WebUILogStreamer intercepts standard logs via io.MultiWriter in main.go
// and broadcasts them to any active web UI clients listening to /api/logs.
var WebUILogStreamer = &logBroadcaster{
	clients: make(map[chan string]struct{}),
	ring:    make([]string, 0, logRingSize),
}

func (b *logBroadcaster) Write(p []byte) (n int, err error) {
	msg := string(p)
	msg = strings.TrimSuffix(msg, "\n")

	// If the global config strips timestamps (e.g. for systemd), manually
	// prepend the standard Go log date/time stamp for the Web UI stream.
	if cfg.Logging.StripTime {
		msg = time.Now().Format("2006/01/02 15:04:05 ") + msg
	}

	b.mu.Lock()
	if len(b.ring) < logRingSize {
		b.ring = append(b.ring, msg)
	} else {
		b.ring[b.ringIdx] = msg
		b.ringIdx = (b.ringIdx + 1) % logRingSize
	}
	for c := range b.clients {
		select {
		case c <- msg:
		default: // drop message if client is too slow to prevent blocking the DNS pipeline
		}
	}
	b.mu.Unlock()
	return len(p), nil
}

// Clear wipes the active log history ring. 
func (b *logBroadcaster) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ring = make([]string, 0, logRingSize)
	b.ringIdx = 0
}

// ---------------------------------------------------------------------------
// Log Persistence
// ---------------------------------------------------------------------------

// SaveLogs safely flushes the historical memory ring of the log streamer to disk.
func SaveLogs() {
	if !cfg.WebUI.Enabled {
		return
	}
	dir := historyDir()
	if dir == "" {
		return
	}

	WebUILogStreamer.mu.Lock()
	count := len(WebUILogStreamer.ring)
	out := make([]string, 0, count)
	if count < logRingSize {
		out = append(out, WebUILogStreamer.ring...)
	} else {
		out = append(out, WebUILogStreamer.ring[WebUILogStreamer.ringIdx:]...)
		out = append(out, WebUILogStreamer.ring[:WebUILogStreamer.ringIdx]...)
	}
	WebUILogStreamer.mu.Unlock()

	minTime := time.Now().Add(-time.Duration(retentionHours()) * time.Hour)
	var filtered []string
	for _, line := range out {
		// Log syntax adheres tightly to "2006/01/02 15:04:05" (19 chars) prefix
		if len(line) > 19 {
			t, err := time.Parse("2006/01/02 15:04:05", line[:19])
			if err == nil && t.Before(minTime) {
				continue
			}
		}
		filtered = append(filtered, line)
	}

	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "webui_logs.json")
	b, err := json.Marshal(filtered)
	if err == nil {
		_ = os.WriteFile(path+".tmp", b, 0644)
		_ = os.Rename(path+".tmp", path)
	}
}

// LoadLogs restores the historical memory ring while verifying time horizons against config.
func LoadLogs() {
	if !cfg.WebUI.Enabled {
		return
	}
	dir := historyDir()
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "webui_logs.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var logs []string
	if err := json.Unmarshal(b, &logs); err != nil {
		log.Printf("[WEBUI] Failed to load log history: %v", err)
		return
	}

	minTime := time.Now().Add(-time.Duration(retentionHours()) * time.Hour)
	WebUILogStreamer.mu.Lock()

	for _, line := range logs {
		if len(line) > 19 {
			t, err := time.Parse("2006/01/02 15:04:05", line[:19])
			if err == nil && t.Before(minTime) {
				continue
			}
		}
		if len(WebUILogStreamer.ring) < logRingSize {
			WebUILogStreamer.ring = append(WebUILogStreamer.ring, line)
		} else {
			WebUILogStreamer.ring[WebUILogStreamer.ringIdx] = line
			WebUILogStreamer.ringIdx = (WebUILogStreamer.ringIdx + 1) % logRingSize
		}
	}
	WebUILogStreamer.mu.Unlock()

	log.Printf("[WEBUI] Loaded %d historical log lines", len(logs))
}

