/*
File:    parental_io.go
Version: 2.3.0
Last Updated: 24-Nov-2026 12:30 CET

Description:
  Snapshot persistence and daily snapshot pruning for the sdproxy parental subsystem.

Changes:
  2.3.0 - [SECURITY/FIX] Scoped `loadSnapshot` strictly to keys currently active
          in `gs.remaining` (clamped to `[0, configuredMax]`) so categories
          removed or switched to `UNLIMITED`/`ALLOW`/`FREE`/`LOG`/`UNTRIGGER`
          are never resurrected as exhausted budgets.
        - [SECURITY/HYGIENE] Hardened `snapshotPathForKey` against invalid/traversal
          characters and excessive lengths, and added `pruneOldSnapshots()` to
          reclaim outdated `parental-*-YYYY-MM-DD.json` files.
  2.2.0 - [FIX] Enabled snapshot write failure warnings in `saveSnapshot` when
          `logSystem` or `logParental` is active.
  2.1.0 - [SECURITY/FIX] Aligned `today()` with `cfg.Parental.TimeOffsetHours` and
          `.Local()`.
  2.0.0 - [TIER 2] `saveSnapshot` moved onto `atomicWrite`.
  1.5.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
  1.4.0 - [SECURITY/FIX] Failed writes purge `.tmp` artifacts.
*/

package main

import (
	"crypto/sha256"
	"encoding/hex"
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
		cfgMax, active := gs.remaining[k]
		if !active {
			continue
		}
		if v < 0 {
			v = 0
		} else if v > cfgMax {
			v = cfgMax
		}
		gs.remaining[k] = v
	}

	if logParental {
		log.Printf("[PARENTAL] [%s] Restored budget snapshot from %s", sk, path)
	}
}

func sanitizeSnapshotKey(sk string) string {
	var b strings.Builder
	b.Grow(len(sk))
	for i := 0; i < len(sk); i++ {
		c := sk[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
			b.WriteByte(c)
		case c == ':':
			b.WriteByte('-')
		case c == '.':
			if i+1 < len(sk) && sk[i+1] == '.' {
				b.WriteByte('_')
			} else {
				b.WriteByte('.')
			}
		default:
			b.WriteByte('_')
		}
	}
	safe := strings.Trim(b.String(), ".")
	if safe == "" {
		safe = "default"
	}
	if len(safe) > 120 {
		h := sha256.Sum256([]byte(sk))
		safe = safe[:96] + "-" + hex.EncodeToString(h[:8])
	}
	return safe
}

func snapshotPathForKey(sk string) string {
	return filepath.Join(snapshotDir(), "parental-"+sanitizeSnapshotKey(sk)+"-"+today()+".json")
}

func pruneOldSnapshots() {
	dir := snapshotDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	keepSuffix := "-" + today() + ".json"
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasPrefix(name, "parental-") || !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, keepSuffix) {
			continue
		}
		if len(name) < len("parental-x-2006-01-02.json") {
			continue
		}
		datePart := name[len(name)-len("2006-01-02.json") : len(name)-len(".json")]
		if len(datePart) == 10 && datePart[4] == '-' && datePart[7] == '-' &&
			name[len(name)-len("-2006-01-02.json")] == '-' &&
			isAllDigits(datePart[0:4]) && isAllDigits(datePart[5:7]) && isAllDigits(datePart[8:10]) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
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
