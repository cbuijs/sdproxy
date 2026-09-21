/*
File:    parental_io.go
Version: 2.0.0
Updated: 22-Jul-2026 22:10 CEST

Description:
  Snapshot persistence for the sdproxy parental subsystem.
  Extracted from parental.go to isolate disk I/O.

Changes:
  2.0.0 - [TIER 2] saveSnapshot moved onto atomicWrite.
  1.5.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
  1.4.0 - [SECURITY/FIX] Failed writes now purge the .tmp so a 0-byte artifact
          cannot linger on disk.
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

type snapshotData struct {
	Remaining map[string]int64 `json:"remaining"`
}

// saveSnapshot writes the current budget counters for sk to disk.
func saveSnapshot(sk string, gs *groupState) {
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

	if err := atomicWrite(snapshotPathForKey(sk), b, 0644); err != nil && logParental {
		log.Printf("[PARENTAL] WARNING: Failed to write snapshot for %q: %v", sk, err)
	}
}

// loadSnapshot restores budget counters for sk from today's snapshot file.
// Silent no-op when no snapshot exists for today.
//
// [SECURITY NOTE] The caller must already hold gs.mu. Locking here would
// deadlock against CheckParental, which acquires it before invoking disk I/O.
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

	for k, v := range data.Remaining {
		gs.remaining[k] = v
	}

	if logParental {
		log.Printf("[PARENTAL] [%s] Restored budget snapshot from %s", sk, path)
	}
}

// snapshotPathForKey returns a filesystem-safe snapshot path for a state key.
// "/" → "_" and ":" → "-" so device-mode keys are valid filename components.
func snapshotPathForKey(sk string) string {
	safe := strings.ReplaceAll(sk, "/", "_")
	safe = strings.ReplaceAll(safe, ":", "-")
	return filepath.Join(snapshotDir(), "parental-"+safe+"-"+today()+".json")
}

func snapshotDir() string {
	if cfg.Parental.SnapshotDir != "" {
		return cfg.Parental.SnapshotDir
	}
	return "/tmp/sdproxy"
}

// today returns today's date as "YYYY-MM-DD" for snapshot filenames.
func today() string {
	return time.Now().Format("2006-01-02")
}

