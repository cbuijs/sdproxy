/*
File:    webui_state.go
Version: 2.0.0
Updated: 22-Jul-2026 22:10 CEST

Description:
  Group override state management and ephemeral client trackers for the
  sdproxy web UI. Handles temporary/permanent overrides, expiration ticking,
  and volatile client blocking.

Changes:
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

// OverrideState holds the current runtime mode and optional expiration data.
type OverrideState struct {
	Mode       string    `json:"mode"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	RevertMode string    `json:"revert_mode,omitempty"`
}

var (
	groupOverride        = make(map[string]OverrideState)
	groupOverrideMu      sync.RWMutex
	expirationTickerOnce sync.Once

	// webuiClientBlocks holds clients (IP or MAC) blocked from the Web UI.
	// Deliberately volatile: a reboot should clear an ad-hoc block.
	webuiClientBlocks sync.Map
)

// GetGroupOverride returns the current override for a group ("DEFAULT" when
// none set). Called from CheckParental on every query — must stay cheap.
// The background expiration ticker handles reversions so this never has to.
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

// SetGroupOverride sets the runtime override mode for a group. A positive
// durationMinutes makes it temporary; it reverts to the previous state on
// expiry. Returns the resulting mode.
func SetGroupOverride(name, mode string, durationMinutes int) string {
	name = strings.ToLower(name)
	groupOverrideMu.Lock()
	v, ok := groupOverride[name]
	if !ok {
		v = OverrideState{Mode: "DEFAULT"}
	}

	if mode == "CANCEL_TIMER" {
		if !v.ExpiresAt.IsZero() {
			if logWebUI {
				log.Printf("[WEBUI] Timer canceled for group %q. Reverted to %s.", name, v.RevertMode)
			}
			v.Mode = v.RevertMode
			v.ExpiresAt = time.Time{}
			v.RevertMode = ""
		}
	} else {
		if durationMinutes > 0 {
			// Only capture RevertMode when starting a fresh timer, so extending
			// an active one doesn't overwrite the original state.
			if v.ExpiresAt.IsZero() {
				v.RevertMode = v.Mode
				if v.RevertMode == "" {
					v.RevertMode = "DEFAULT"
				}
			}
			v.Mode = mode
			v.ExpiresAt = time.Now().Add(time.Duration(durationMinutes) * time.Minute)
			if logWebUI {
				log.Printf("[WEBUI] Set temporary override for group %q: %s for %dm", name, mode, durationMinutes)
			}
		} else {
			v.Mode = mode
			v.ExpiresAt = time.Time{}
			v.RevertMode = ""
			if logWebUI {
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

// runOverrideExpirationTicker reverts expired temporary overrides once a second.
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
					if logWebUI {
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
	if err := atomicWrite(path, b, 0644); err != nil && logWebUI {
		log.Printf("[WEBUI] WARNING: failed to persist group overrides: %v", err)
	}
}

// LoadGroupOverrides restores persisted overrides and starts the expiry ticker.
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
		groupOverrideMu.Lock()
		for k, v := range newFmt {
			groupOverride[strings.ToLower(k)] = v
		}
		groupOverrideMu.Unlock()
		if logWebUI {
			log.Printf("[WEBUI] Loaded %d group overrides", len(newFmt))
		}
		return
	}

	// Legacy map[string]string format.
	var oldFmt map[string]string
	if err := json.Unmarshal(b, &oldFmt); err == nil {
		groupOverrideMu.Lock()
		for k, v := range oldFmt {
			groupOverride[strings.ToLower(k)] = OverrideState{Mode: v}
		}
		groupOverrideMu.Unlock()
		if logWebUI {
			log.Printf("[WEBUI] Migrated %d group overrides from legacy format", len(oldFmt))
		}
	}
}

