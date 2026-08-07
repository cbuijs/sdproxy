/*
File:    rules.go
Version: 2.1.0
Updated: 23-Jul-2026 13:00 CEST

Description:
  Custom Rules engine for sdproxy. Provides dynamic, immediate-effect
  allowlisting and blocklisting per-group or globally via the Web UI.

Changes:
  2.1.0 - [PERF/FIX] Replaced localized string counting with the globally standardized 
          `countDomainLabels` helper natively. Ensures strict parity with the core DNS 
          pipeline and guards against empty-string bounds errors organically during 
          Custom Rule suffix walks.
  2.0.0 - [TIER 2] SaveRules moved onto atomicWrite.
  1.6.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
  1.5.0 - [SECURITY/FIX] Write verification before rename; a failed write no
          longer wipes the rule set.
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

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	return d
}

func rulesPath() string {
	dir := historyDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "custom-rules.json")
}

func InitRules() {
	customRules = []CustomRule{}
	customRulesMap = make(map[string]map[string]CustomRule)
	LoadRules()
}

func LoadRules() {
	path := rulesPath()
	if path == "" {
		return
	}
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
		r.Group = strings.ToLower(strings.TrimSpace(r.Group))
		r.Domain = normalizeDomain(r.Domain)

		if customRulesMap[r.Group] == nil {
			customRulesMap[r.Group] = make(map[string]CustomRule)
		}
		customRulesMap[r.Group][r.Domain] = *r
		if r.Enabled {
			activeCount++
			if r.Domain != "" {
				// Utilize standardized pipeline evaluation helper cleanly
				n := countDomainLabels(r.Domain)
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

func SaveRules() {
	path := rulesPath()
	if path == "" {
		return
	}

	customRulesMu.RLock()
	b, err := json.Marshal(customRules)
	customRulesMu.RUnlock()

	if err != nil {
		return
	}
	if err := atomicWrite(path, b, 0644); err != nil && logRouting {
		log.Printf("[RULES] WARNING: failed to persist custom rules: %v", err)
	}
}

// CheckRules performs a hierarchical suffix walk against the active rule maps.
// Group rules take precedence over global rules.
func CheckRules(domain string, group string) (action string, match string) {
	customRulesMu.RLock()
	defer customRulesMu.RUnlock()

	if len(customRules) == 0 {
		return "", ""
	}

	group = strings.ToLower(group)

	// [PERF] Resolve both maps once; the walk below would otherwise repeat two
	// map lookups per label.
	var groupRules map[string]CustomRule
	if group != "" && group != "global" {
		groupRules = customRulesMap[group]
	}
	globalRules := customRulesMap["global"]

	search := domain
	// [PERF/FIX] Execute standardized label boundary bounds organically.
	labels := countDomainLabels(domain)
	ceiling := int(customRulesMaxLabels.Load())

	// Skip label levels deeper than any configured rule.
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

// GetRules returns a copy of the configured rules for the API.
func GetRules() []CustomRule {
	customRulesMu.RLock()
	defer customRulesMu.RUnlock()
	res := make([]CustomRule, len(customRules))
	copy(res, customRules)
	return res
}

// SetRules overwrites the live configuration map.
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
			// Utilize standardized pipeline evaluation helper cleanly
			n := countDomainLabels(r.Domain)
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

