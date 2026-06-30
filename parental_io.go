/*
File:    parental_io.go
Version: 1.4.0
Updated: 22-Jun-2026 10:42 CEST

Description:
  Snapshot persistence for the sdproxy parental subsystem.
  Extracted from parental.go to isolate Disk I/O operations.

Changes:
  1.4.0 - [SECURITY/FIX] Hardened `saveSnapshot` to explicitly intercept and purge 
          corrupted partial arrays natively. Enforced strict `os.Remove` invocations 
          upon `os.WriteFile` failures to guarantee 0-byte anomalies do not linger 
          on the disk partitions organically.
  1.3.0 - [LOGGING] Safely guarded snapshot loading debug events natively 
          through the `logParental` parameter flag.
  1.2.0 - [SECURITY/FIX] Addressed a fatal deadlock vulnerability entirely halting 
          the global DNS pipeline on first-contact queries. Removed the nested 
          `gs.mu.Lock()` natively within `loadSnapshot`. Conforms explicitly to the 
          isolated lock boundaries instantiated by `CheckParental`.
  1.1.0 - [RELIABILITY] Hardened `saveSnapshot` persistence logic to utilize 
          atomic `.tmp` file renames. This natively safeguards the system against 
          JSON corruption in the event of abrupt power loss or kernel panics 
          during active I/O writes.
*/

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Snapshot persistence
// ---------------------------------------------------------------------------

type snapshotData struct {
	Remaining map[string]int64 `json:"remaining"`
}

// saveSnapshot writes current budget counters for sk to disk safely via atomic rename.
func saveSnapshot(sk string, gs *groupState) {
	path := snapshotPathForKey(sk)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	gs.mu.Lock()
	data := snapshotData{Remaining: make(map[string]int64, len(gs.remaining))}
	for k, v := range gs.remaining {
		data.Remaining[k] = v
	}
	gs.mu.Unlock()
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	
	// Write out securely to a temporary file first, then atomically rename 
	// to prevent partial JSON corruption during abrupt power loss.
	// [SECURITY/FIX] Rigorously purge structural artifacts natively upon I/O failures.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, b, 0o644); err == nil {
		_ = os.Rename(tmpPath, path)
	} else {
		os.Remove(tmpPath)
		if logParental {
			log.Printf("[PARENTAL] WARNING: Failed to securely write snapshot payload to disk: %v", err)
		}
	}
}

// loadSnapshot restores budget counters for sk from today's snapshot file.
// Silent no-op when no snapshot exists for today.
//
// [SECURITY NOTE]
// The caller is strictly responsible for acquiring `gs.mu.Lock()` prior 
// to invoking this function to prevent redundant internal deadlock loops.
func loadSnapshot(sk string, gs *groupState) {
	path := snapshotPathForKey(sk)
	b, err := os.ReadFile(path)
	if err != nil {
		return // no snapshot today — start fresh
	}
	var data snapshotData
	if err := json.Unmarshal(b, &data); err != nil {
		return
	}

	// [SECURITY/FIX] Do NOT call gs.mu.Lock() here.
	// CheckParental explicitly acquires the structural mutex prior to invoking Disk I/O.
	// Nested locks inherently instigate fatal deadlocks on identical channels natively.
	for k, v := range data.Remaining {
		gs.remaining[k] = v
	}
	
	if logParental {
		log.Printf("[PARENTAL] [%s] Restored budget snapshot from %s", sk, path)
	}
}

// ---------------------------------------------------------------------------
// Path & Directory helpers
// ---------------------------------------------------------------------------

// snapshotPathForKey returns a filesystem-safe snapshot path for a state key.
// "/" → "_" and ":" → "-" so device-mode keys are valid filename components.
func snapshotPathForKey(sk string) string {
	safe := strings.ReplaceAll(sk, "/", "_")
	safe  = strings.ReplaceAll(safe, ":", "-")
	return filepath.Join(snapshotDir(), "parental-"+safe+"-"+today()+".json")
}

// snapshotDir returns the configured snapshot directory, defaulting to /tmp/sdproxy.
func snapshotDir() string {
	if cfg.Parental.SnapshotDir != "" {
		return cfg.Parental.SnapshotDir
	}
	return "/tmp/sdproxy"
}

// today returns today's date as "YYYY-MM-DD" for use in snapshot filenames.
func today() string {
	return time.Now().Format("2006-01-02")
}

