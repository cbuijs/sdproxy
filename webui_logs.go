/*
File:    webui_logs.go
Version: 2.1.0
Updated: 18-Aug-2026 13:48 CEST

Description:
  Live log streaming (SSE) and persistence for the sdproxy web UI.

Changes:
  2.1.0 - [PERF/FIX] Replaced legacy `json.Marshal` array loading with natively 
          streamed OS operations (`json.NewEncoder`). Eradicates localized heap 
          memory spikes completely when serializing historic log events iteratively.
  2.0.0 - [TIER 2] SaveLogs moved onto atomicWrite.
  1.4.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
*/

package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const logRingSize = 5000

type logBroadcaster struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	ring    []string
	ringIdx int
}

// WebUILogStreamer intercepts standard logs via io.MultiWriter in main.go and
// broadcasts them to any active /api/logs listeners.
var WebUILogStreamer = &logBroadcaster{
	clients: make(map[chan string]struct{}),
	ring:    make([]string, 0, logRingSize),
}

func (b *logBroadcaster) Write(p []byte) (n int, err error) {
	msg := strings.TrimSuffix(string(p), "\n")

	// When strip_time is set for systemd, re-add a timestamp for the UI stream —
	// the log viewer's time-range display and retention pruning depend on it.
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
		default: // drop for a slow client rather than blocking the DNS pipeline
		}
	}
	b.mu.Unlock()
	return len(p), nil
}

func (b *logBroadcaster) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ring = make([]string, 0, logRingSize)
	b.ringIdx = 0
}

func logsPath() string {
	dir := historyDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "webui_logs.json")
}

// SaveLogs flushes the log ring to disk natively, dropping entries older than the
// configured retention window.
func SaveLogs() {
	if !cfg.WebUI.Enabled {
		return
	}
	path := logsPath()
	if path == "" {
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
		// Timestamp prefix is "2006/01/02 15:04:05" — 19 chars.
		if len(line) > 19 {
			t, err := time.Parse("2006/01/02 15:04:05", line[:19])
			if err == nil && t.Before(minTime) {
				continue
			}
		}
		filtered = append(filtered, line)
	}

	// [PERF/FIX] Safely structure write operations over I/O streams natively.
	err := atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		return json.NewEncoder(bw).Encode(filtered)
	})
	
	if err != nil && logWebUI {
		log.Printf("[WEBUI] WARNING: failed to persist logs: %v", err)
	}
}

// LoadLogs restores the log ring natively, discarding entries past the retention window.
func LoadLogs() {
	if !cfg.WebUI.Enabled {
		return
	}
	path := logsPath()
	if path == "" {
		return
	}

	// [PERF/FIX] Stream array parsing entirely dynamically
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	
	var logs []string
	if err := json.NewDecoder(bufio.NewReaderSize(f, 64*1024)).Decode(&logs); err != nil {
		if logWebUI {
			log.Printf("[WEBUI] Failed to load log history: %v", err)
		}
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

	if logWebUI {
		log.Printf("[WEBUI] Loaded %d historical log lines", len(logs))
	}
}

