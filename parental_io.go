/*
File:    parental_io.go
Version: 2.2.0
Last Updated: 04-Nov-2026 19:38 CET

Description:
  Snapshot persistence for the sdproxy parental subsystem.
  Extracted from parental.go to isolate disk I/O.

Changes:
  2.2.0 - [FIX] Enabled snapshot write failure warnings in `saveSnapshot` when
          `logSystem` or `logParental` is active so Simple Logging Mode
          (`logSimple: true`) retains all disk I/O warnings.
  2.1.0 - [SECURITY/FIX] Aligned `today()` with `cfg.Parental.TimeOffsetHours` and
          `.Local()` so snapshot filenames roll over at the exact same timezone-adjusted
          midnight boundary as `runMidnightReset` and `inAnyScheduleWindow`.
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

	if err := atomicWrite(snapshotPathForKey(sk), b, 0644); err != nil && (logParental || logSystem) {
		log.Printf("[PARENTAL] WARNING: Failed to write snapshot for %q: %v", sk, err)
	}
}

func loadSnapshot(sk string, gs *groupState) {
	path := snapshotPathForKey(sk)
	b, err := os.ReadFile(path)
	if err != nil {
		return
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

func today() string {
	return time.Now().Local().Add(time.Duration(cfg.Parental.TimeOffsetHours) * time.Hour).Format("2006-01-02")
}
