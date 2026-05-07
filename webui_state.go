/*
File:    webui_state.go
Description:
  Group override state management for the sdproxy web UI.
  Extracted from webui.go.
  Handles temporary and permanent overrides, expiration ticking,
  and disk persistence.
*/

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Group override state
// ---------------------------------------------------------------------------

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
)

// GetGroupOverride returns the current override for a group ("DEFAULT" when
// none set). Called from CheckParental on every DNS query — must be cheap.
// The background expiration ticker handles reversions to keep this fast.
func GetGroupOverride(name string) string {
	groupOverrideMu.RLock()
	v, ok := groupOverride[name]
	groupOverrideMu.RUnlock()
	if !ok || v.Mode == "" {
		return "DEFAULT"
	}
	return v.Mode
}

// SetGroupOverride sets the runtime override mode for a group.
// If durationMinutes > 0, it becomes a temporary override and will revert
// to its previous state upon expiration. Returns the resulting mode.
func SetGroupOverride(name, mode string, durationMinutes int) string {
	groupOverrideMu.Lock()
	v, ok := groupOverride[name]
	if !ok {
		v = OverrideState{Mode: "DEFAULT"}
	}

	if mode == "CANCEL_TIMER" {
		if !v.ExpiresAt.IsZero() {
			log.Printf("[WEBUI] Timer canceled for group %q. Reverted to %s.", name, v.RevertMode)
			v.Mode = v.RevertMode
			v.ExpiresAt = time.Time{}
			v.RevertMode = ""
		}
	} else {
		if durationMinutes > 0 {
			// If not currently in a timer, save the current mode as RevertMode.
			if v.ExpiresAt.IsZero() {
				v.RevertMode = v.Mode
				if v.RevertMode == "" {
					v.RevertMode = "DEFAULT"
				}
			}
			v.Mode = mode
			v.ExpiresAt = time.Now().Add(time.Duration(durationMinutes) * time.Minute)
			log.Printf("[WEBUI] Set temporary override for group %q: %s for %dm", name, mode, durationMinutes)
		} else {
			// Permanent override
			v.Mode = mode
			v.ExpiresAt = time.Time{}
			v.RevertMode = ""
			log.Printf("[WEBUI] Set permanent override for group %q: %s", name, mode)
		}
	}

	groupOverride[name] = v
	resultMode := v.Mode
	groupOverrideMu.Unlock()
	SaveGroupOverrides()
	
	return resultMode
}

// runOverrideExpirationTicker checks for expired temporary overrides every second
// and reverts them to their previous state automatically.
func runOverrideExpirationTicker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for range t.C {
		changed := false
		now := time.Now()

		groupOverrideMu.Lock()
		for k, v := range groupOverride {
			if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
				log.Printf("[WEBUI] Temporary override for group %q expired. Reverted to %s.", k, v.RevertMode)
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
	}
}

// SaveGroupOverrides persists the current group overrides to disk.
func SaveGroupOverrides() {
	dir := snapshotDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[WEBUI] Failed to create snapshot dir for overrides: %v", err)
		return
	}

	groupOverrideMu.RLock()
	b, err := json.Marshal(groupOverride)
	groupOverrideMu.RUnlock()

	if err == nil {
		path := filepath.Join(dir, "parental-overrides.json")
		_ = os.WriteFile(path+".tmp", b, 0644)
		_ = os.Rename(path+".tmp", path)
	}
}

// LoadGroupOverrides restores the persistent group overrides from disk.
func LoadGroupOverrides() {
	defer expirationTickerOnce.Do(func() {
		go runOverrideExpirationTicker()
	})

	dir := snapshotDir()
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "parental-overrides.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return // no overrides saved yet or file missing
	}

	// Try the new structured format
	var newFmt map[string]OverrideState
	if err := json.Unmarshal(b, &newFmt); err == nil && len(newFmt) > 0 {
		groupOverrideMu.Lock()
		for k, v := range newFmt {
			groupOverride[k] = v
		}
		groupOverrideMu.Unlock()
		log.Printf("[WEBUI] Loaded %d group overrides", len(newFmt))
		return
	}

	// Fallback to legacy map[string]string format
	var oldFmt map[string]string
	if err := json.Unmarshal(b, &oldFmt); err == nil {
		groupOverrideMu.Lock()
		for k, v := range oldFmt {
			groupOverride[k] = OverrideState{Mode: v}
		}
		groupOverrideMu.Unlock()
		log.Printf("[WEBUI] Migrated %d group overrides from legacy format", len(oldFmt))
	}
}

