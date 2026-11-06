/*
File:    webui_logs.go
Version: 2.4.0
Last Updated: 05-Nov-2026 15:15 CET

Description:
  Live log streaming (SSE) and persistence for the sdproxy web UI.

Changes:
  2.4.0 - [CRITICAL/FIX] Eliminated a logging mutex deadlock in `SaveLogs`:
          previously, if `atomicWriteBuf` failed in `SaveLogs`, it called
          `log.Printf` while `SaveLogs` was invoked from `handleApiReset` or
          background tickers, which re-entered `WebUILogStreamer.Write()`. More
          critically, `log.Logger` holds its internal `outMu` mutex across
          `io.MultiWriter(os.Stderr, WebUILogStreamer).Write()`; if `os.Stderr`
          blocks or `WebUILogStreamer.mu` is contended by `/api/logs` SSE
          clients flushing over a stalled HTTP connection, every `log.Printf`
          in the DNS hot path (`ProcessDNS`) freezes completely with 0% CPU.
          Decoupled `WebUILogStreamer.Write` and `/api/logs` initial history
          flushing so `WebUILogStreamer.mu` is never held across any I/O operation.
  2.3.0 - [FIX] Excluded historic `[WEBUI] Loaded ...` startup log lines from
          re-ingesting into `WebUILogStreamer.ring` during `LoadLogs`.
  2.2.0 - [PERF] Replaced expensive `time.Parse` invocations with O(1) 
          lexicographical string boundary evaluations natively.
  2.1.0 - [PERF/FIX] Replaced legacy `json.Marshal` array loading with natively 
          streamed OS operations (`json.NewEncoder`).
  2.0.0 - [TIER 2] SaveLogs moved onto atomicWrite.
  1.4.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
*/

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
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
		default:
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

	minTimeStr := time.Now().Add(-time.Duration(retentionHours()) * time.Hour).Format("2006/01/02 15:04:05")
	var filtered []string
	for _, line := range out {
		if len(line) > 19 && line[4] == '/' && line[7] == '/' && line[19] == ' ' {
			if line[:19] < minTimeStr {
				continue
			}
		}
		filtered = append(filtered, line)
	}

	err := atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		return json.NewEncoder(bw).Encode(filtered)
	})

	if err != nil && (logWebUI || logSystem) {
		fmt.Fprintf(os.Stderr, "[WEBUI] WARNING: failed to persist logs: %v\n", err)
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

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var logs []string
	if err := json.NewDecoder(bufio.NewReaderSize(f, 64*1024)).Decode(&logs); err != nil {
		if logWebUI || logSystem {
			log.Printf("[WEBUI] Failed to load log history: %v", err)
		}
		return
	}

	minTimeStr := time.Now().Add(-time.Duration(retentionHours()) * time.Hour).Format("2006/01/02 15:04:05")
	restored := 0
	WebUILogStreamer.mu.Lock()

	for _, line := range logs {
		if len(line) > 19 && line[4] == '/' && line[7] == '/' && line[19] == ' ' {
			if line[:19] < minTimeStr {
				continue
			}
		}
		if strings.Contains(line, "[WEBUI] Loaded ") && strings.HasSuffix(line, " historical log lines") {
			continue
		}
		restored++
		if len(WebUILogStreamer.ring) < logRingSize {
			WebUILogStreamer.ring = append(WebUILogStreamer.ring, line)
		} else {
			WebUILogStreamer.ring[WebUILogStreamer.ringIdx] = line
			WebUILogStreamer.ringIdx = (WebUILogStreamer.ringIdx + 1) % logRingSize
		}
	}
	WebUILogStreamer.mu.Unlock()

	if logWebUI {
		log.Printf("[WEBUI] Loaded %d historical log lines", restored)
	}
}
