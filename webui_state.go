/*
File:    webui_state.go
Version: 2.2.0
Last Updated: 04-Nov-2026 19:20 CET

Description:
  Group override state management and ephemeral client trackers for the
  sdproxy web UI. Handles temporary/permanent overrides, expiration ticking,
  and volatile client blocking.

Changes:
  2.2.0 - [CLEANUP] Guarded runtime group-override change and expiry log lines
          with `logWebUI && !logSimple` so Simple Logging Mode only emits
          startup messages, errors/warnings, and DNS query/answer lines.
  2.1.0 - [SECURITY/FIX] Pruned unknown or removed group keys in `LoadGroupOverrides`
          so stale entries from `parental-overrides.json` do not linger in memory.
  2.0.0 - [TIER 2] SaveGroupOverrides moved onto atomicWrite.
  1.8.0 - [FEAT] webuiClientBlocks: ephemeral sync.Map of clients (IP or MAC)
          blocked interactively from the Web UI. Intentionally not persisted.
  1.7.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
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

type OverrideState struct {
	Mode       string    `json:"mode"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	RevertMode string    `json:"revert_mode,omitempty"`
}

var (
	groupOverride        = make(map[string]OverrideState)
	groupOverrideMu      sync.RWMutex
	expirationTickerOnce sync.Once

	webuiClientBlocks sync.Map
)

func GetGroupOverride(name string) string {
	name = strings.ToLower(name)
	groupOverrideMu.RLock()
	v, ok := groupOverride[name]
	groupOverrideMu.RUnlock()
	if !ok || v.Mode == "" {
		return "DEFAULT"
	}
	return v.Mode
}

func SetGroupOverride(name, mode string, durationMinutes int) string {
	name = strings.ToLower(name)
	if _, exists := cfg.Groups[name]; !exists {
		return "DEFAULT"
	}
	groupOverrideMu.Lock()
	v, ok := groupOverride[name]
	if !ok {
		v = OverrideState{Mode: "DEFAULT"}
	}

	if mode == "CANCEL_TIMER" {
		if !v.ExpiresAt.IsZero() {
			if logWebUI && !logSimple {
				log.Printf("[WEBUI] Timer canceled for group %q. Reverted to %s.", name, v.RevertMode)
			}
			v.Mode = v.RevertMode
			v.ExpiresAt = time.Time{}
			v.RevertMode = ""
		}
	} else {
		if durationMinutes > 0 {
			if v.ExpiresAt.IsZero() {
				v.RevertMode = v.Mode
				if v.RevertMode == "" {
					v.RevertMode = "DEFAULT"
				}
			}
			v.Mode = mode
			v.ExpiresAt = time.Now().Add(time.Duration(durationMinutes) * time.Minute)
			if logWebUI && !logSimple {
				log.Printf("[WEBUI] Set temporary override for group %q: %s for %dm", name, mode, durationMinutes)
			}
		} else {
			v.Mode = mode
			v.ExpiresAt = time.Time{}
			v.RevertMode = ""
			if logWebUI && !logSimple {
				log.Printf("[WEBUI] Set permanent override for group %q: %s", name, mode)
			}
		}
	}

	groupOverride[name] = v
	resultMode := v.Mode
	groupOverrideMu.Unlock()
	SaveGroupOverrides()

	return resultMode
}

func runOverrideExpirationTicker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			changed := false
			now := time.Now()

			groupOverrideMu.Lock()
			for k, v := range groupOverride {
				if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
					if logWebUI && !logSimple {
						log.Printf("[WEBUI] Temporary override for group %q expired. Reverted to %s.", k, v.RevertMode)
					}
					v.Mode = v.RevertMode
					v.ExpiresAt = time.Time{}
					v.RevertMode = ""
					groupOverride[k] = v
					changed = true
				}
			}
			groupOverrideMu.Unlock()

			if changed {
				SaveGroupOverrides()
			}
		case <-shutdownCh:
			return
		}
	}
}

func overridesPath() string {
	dir := snapshotDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "parental-overrides.json")
}

func SaveGroupOverrides() {
	path := overridesPath()
	if path == "" {
		return
	}

	groupOverrideMu.RLock()
	b, err := json.Marshal(groupOverride)
	groupOverrideMu.RUnlock()

	if err != nil {
		return
	}
	if err := atomicWrite(path, b, 0644); err != nil && (logWebUI || logSystem) {
		log.Printf("[WEBUI] WARNING: failed to persist group overrides: %v", err)
	}
}

func LoadGroupOverrides() {
	defer expirationTickerOnce.Do(func() {
		go runOverrideExpirationTicker()
	})

	path := overridesPath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var newFmt map[string]OverrideState
	if err := json.Unmarshal(b, &newFmt); err == nil && len(newFmt) > 0 {
		loaded := 0
		groupOverrideMu.Lock()
		for k, v := range newFmt {
			kLower := strings.ToLower(k)
			if _, exists := cfg.Groups[kLower]; exists {
				groupOverride[kLower] = v
				loaded++
			}
		}
		groupOverrideMu.Unlock()
		if logWebUI {
			log.Printf("[WEBUI] Loaded %d group overrides", loaded)
		}
		return
	}

	var oldFmt map[string]string
	if err := json.Unmarshal(b, &oldFmt); err == nil {
		loaded := 0
		groupOverrideMu.Lock()
		for k, v := range oldFmt {
			kLower := strings.ToLower(k)
			if _, exists := cfg.Groups[kLower]; exists {
				groupOverride[kLower] = OverrideState{Mode: v}
				loaded++
			}
		}
		groupOverrideMu.Unlock()
		if logWebUI {
			log.Printf("[WEBUI] Migrated %d group overrides from legacy format", loaded)
		}
	}
}
