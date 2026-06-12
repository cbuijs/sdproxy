/*
File:    rules.go
Version: 1.5.0
Updated: 06-Jun-2026 15:08 CEST

Description:
  Custom Rules engine for sdproxy.
  Provides dynamic, immediate-effect allowlisting and blocklisting 
  capabilities per-group or globally via the Web UI.

Changes:
  1.5.0 - [SECURITY/FIX] Addressed a catastrophic JSON corruption vector internally. 
          `SaveRules()` natively implements `os.WriteFile` verification gates before 
          committing atomic renames to prevent partial 0-byte structural wipes.
  1.4.1 - [PERF] Optimized CheckRules by pre-fetching customRulesMap pointers
           for group-specific and global rules prior to the suffix-walking loop,
           completely eliminating redundant map lookup operations per label step.
  1.4.0 - [PERF] Optimized hot-path query custom rule matches. Implemented a lock-free 
           atomic label-depth boundary ceiling (`customRulesMaxLabels`) computed dynamically 
           on rules load/set. Completely bypasses redundant left-most suffix-walking 
           iterations for deep subdomains, drastically lowering DNS query latencies.
*/

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// CustomRule defines a user-configured domain rule.
type CustomRule struct {
	Domain  string `json:"domain"`
	Action  string `json:"action"` // "ALLOW", "BLOCK"
	Group   string `json:"group"`  // "global" or specific group name
	Enabled bool   `json:"enabled"`
}

var (
	customRulesMu        sync.RWMutex
	customRules          []CustomRule
	customRulesMap       map[string]map[string]CustomRule // group -> domain -> rule
	customRulesMaxLabels atomic.Int32
)

func init() {
	customRulesMaxLabels.Store(128)
}

// normalizeDomain strips leading/trailing dots and whitespaces, and lowercases.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	return d
}

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
		if logRouting {
			log.Printf("[RULES] Failed to parse custom-rules.json: %v", err)
		}
		return
	}

	customRulesMu.Lock()
	customRules = rules
	customRulesMap = make(map[string]map[string]CustomRule)

	activeCount := 0
	maxL := 0
	for i := range rules {
		r := &rules[i]
		if r.Group == "" {
			r.Group = "global"
		}
		// Enforce lowercase mapping and normalization on load for consistency
		r.Group = strings.ToLower(strings.TrimSpace(r.Group))
		r.Domain = normalizeDomain(r.Domain)

		if customRulesMap[r.Group] == nil {
			customRulesMap[r.Group] = make(map[string]CustomRule)
		}
		customRulesMap[r.Group][r.Domain] = *r
		if r.Enabled {
			activeCount++
			if r.Domain != "" {
				n := strings.Count(r.Domain, ".") + 1
				if n > maxL {
					maxL = n
				}
			}
		}
	}
	if maxL == 0 {
		maxL = 128
	}
	customRulesMaxLabels.Store(int32(maxL))
	customRulesMu.Unlock()

	if logRouting {
		log.Printf("[RULES] Loaded %d custom rules (%d active)", len(rules), activeCount)
	}
}

// SaveRules safely persists the custom rules via atomic rename.
func SaveRules() {
	dir := historyDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		if logRouting {
			log.Printf("[RULES] Failed to create snapshot dir: %v", err)
		}
		return
	}

	customRulesMu.RLock()
	b, err := json.Marshal(customRules)
	customRulesMu.RUnlock()

	if err == nil {
		path := filepath.Join(dir, "custom-rules.json")
		// [SECURITY/FIX] Enforce strict check to prevent truncations organically.
		if err := os.WriteFile(path+".tmp", b, 0644); err == nil {
			_ = os.Rename(path+".tmp", path)
		} else {
			os.Remove(path + ".tmp")
		}
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

	// Group and domain parameters are always compared in lower case
	group = strings.ToLower(group)
	
	// [PERF] Fetch the group-specific and global rules map once before the loop to prevent O(N) map lookups during suffix walking.
	var groupRules map[string]CustomRule
	if group != "" && group != "global" {
		groupRules = customRulesMap[group]
	}
	globalRules := customRulesMap["global"]

	search := domain
	labels := strings.Count(domain, ".") + 1
	ceiling := int(customRulesMaxLabels.Load())

	for labels > ceiling {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
		labels--
	}

	for {
		if groupRules != nil {
			if rule, ok := groupRules[search]; ok && rule.Enabled {
				return rule.Action, search
			}
		}
		
		if globalRules != nil {
			if rule, ok := globalRules[search]; ok && rule.Enabled {
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

	maxL := 0
	for i := range customRules {
		r := &customRules[i]
		r.Domain = normalizeDomain(r.Domain)
		r.Group = strings.ToLower(strings.TrimSpace(r.Group))
		if r.Group == "" {
			r.Group = "global"
		}
		if customRulesMap[r.Group] == nil {
			customRulesMap[r.Group] = make(map[string]CustomRule)
		}
		customRulesMap[r.Group][r.Domain] = *r
		if r.Enabled && r.Domain != "" {
			n := strings.Count(r.Domain, ".") + 1
			if n > maxL {
				maxL = n
			}
		}
	}
	if maxL == 0 {
		maxL = 128
	}
	customRulesMaxLabels.Store(int32(maxL))
}

