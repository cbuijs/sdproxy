/*
File:    rules.go
Version: 1.0.0
Updated: 03-May-2026 20:19 CEST

Description:
  Custom Rules engine for sdproxy.
  Provides dynamic, immediate-effect allowlisting and blocklisting 
  capabilities per-group or globally via the Web UI.
*/

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CustomRule defines a user-configured domain rule.
type CustomRule struct {
	Domain  string `json:"domain"`
	Action  string `json:"action"` // "ALLOW", "BLOCK"
	Group   string `json:"group"`  // "global" or specific group name
	Enabled bool   `json:"enabled"`
}

var (
	customRulesMu  sync.RWMutex
	customRules    []CustomRule
	customRulesMap map[string]map[string]CustomRule // group -> domain -> rule
)

// InitRules prepares the map and loads rules from disk.
func InitRules() {
	customRules = []CustomRule{}
	customRulesMap = make(map[string]map[string]CustomRule)
	LoadRules()
}

// LoadRules retrieves persisted custom rules from the history directory.
func LoadRules() {
	dir := historyDir()
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "custom-rules.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var rules []CustomRule
	if err := json.Unmarshal(b, &rules); err != nil {
		log.Printf("[RULES] Failed to parse custom-rules.json: %v", err)
		return
	}

	customRulesMu.Lock()
	customRules = rules
	customRulesMap = make(map[string]map[string]CustomRule)

	activeCount := 0
	for _, r := range rules {
		if r.Group == "" {
			r.Group = "global"
		}
		if customRulesMap[r.Group] == nil {
			customRulesMap[r.Group] = make(map[string]CustomRule)
		}
		customRulesMap[r.Group][r.Domain] = r
		if r.Enabled {
			activeCount++
		}
	}
	customRulesMu.Unlock()

	log.Printf("[RULES] Loaded %d custom rules (%d active)", len(rules), activeCount)
}

// SaveRules safely persists the custom rules via atomic rename.
func SaveRules() {
	dir := historyDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[RULES] Failed to create snapshot dir: %v", err)
		return
	}

	customRulesMu.RLock()
	b, err := json.Marshal(customRules)
	customRulesMu.RUnlock()

	if err == nil {
		path := filepath.Join(dir, "custom-rules.json")
		_ = os.WriteFile(path+".tmp", b, 0644)
		_ = os.Rename(path+".tmp", path)
	}
}

// CheckRules performs a hierarchical suffix walk against the active rule maps.
// Group rules strictly take precedence over global rules natively.
func CheckRules(domain string, group string) (action string, match string) {
	customRulesMu.RLock()
	defer customRulesMu.RUnlock()

	if len(customRules) == 0 {
		return "", ""
	}

	search := domain
	for {
		if group != "" && group != "global" && customRulesMap[group] != nil {
			if rule, ok := customRulesMap[group][search]; ok && rule.Enabled {
				return rule.Action, search
			}
		}
		
		if customRulesMap["global"] != nil {
			if rule, ok := customRulesMap["global"][search]; ok && rule.Enabled {
				return rule.Action, search
			}
		}

		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}

	return "", ""
}

// GetRules returns a deep copy of the currently configured rules for the API.
func GetRules() []CustomRule {
	customRulesMu.RLock()
	defer customRulesMu.RUnlock()
	res := make([]CustomRule, len(customRules))
	copy(res, customRules)
	return res
}

// SetRules cleanly overwrites the live configuration map.
func SetRules(rules []CustomRule) {
	customRulesMu.Lock()
	defer customRulesMu.Unlock()

	customRules = rules
	customRulesMap = make(map[string]map[string]CustomRule)

	for i := range customRules {
		r := &customRules[i]
		r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
		if r.Group == "" {
			r.Group = "global"
		}
		if customRulesMap[r.Group] == nil {
			customRulesMap[r.Group] = make(map[string]CustomRule)
		}
		customRulesMap[r.Group][r.Domain] = *r
	}
}

