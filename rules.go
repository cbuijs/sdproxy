/*
File:    rules.go
Version: 2.3.0
Last Updated: 17-Oct-2026 19:54 CEST

Description:
  Custom Rules engine for sdproxy. Provides dynamic, immediate-effect
  allowlisting and blocklisting per-group or globally via the Web UI.

Changes:
  2.3.0 - [SECURITY/FIX] Added `customRulesMinLabels` floor bound in `LoadRules`,
          `SetRules`, and `CheckRules` to match `walkDomainMaps` and `categoryOf`,
          avoiding unnecessary map probes on bare TLD labels when no TLD-level
          custom rules are active.
        - [SECURITY/FIX] Normalized `r.Action` to uppercase (`ALLOW` or `BLOCK`)
          during `LoadRules` and `SetRules` so hand-edited or lowercased JSON
          files evaluate accurately in `ProcessDNS`.
  2.2.0 - [CLEANUP] Condensed string formatting sequences inside `normalizeDomain` 
          organically, shedding unnecessary multi-line buffer mutations.
  2.1.0 - [PERF/FIX] Replaced localized string counting with the globally standardized 
          `countDomainLabels` helper natively. Ensures strict parity with the core DNS 
          pipeline and guards against empty-string bounds errors organically during 
          Custom Rule suffix walks.
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
	customRulesMinLabels atomic.Int32
	customRulesMaxLabels atomic.Int32
)

func init() {
	customRulesMinLabels.Store(1)
	customRulesMaxLabels.Store(128)
}

func normalizeDomain(d string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
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

func rebuildRulesIndexLocked() int {
	customRulesMap = make(map[string]map[string]CustomRule)
	activeCount := 0
	minL, maxL := 128, 0

	for i := range customRules {
		r := &customRules[i]
		if r.Group == "" {
			r.Group = "global"
		}
		r.Group = strings.ToLower(strings.TrimSpace(r.Group))
		r.Domain = normalizeDomain(r.Domain)
		r.Action = strings.ToUpper(strings.TrimSpace(r.Action))

		if r.Domain == "" || (r.Action != "ALLOW" && r.Action != "BLOCK") {
			continue
		}

		if customRulesMap[r.Group] == nil {
			customRulesMap[r.Group] = make(map[string]CustomRule)
		}
		customRulesMap[r.Group][r.Domain] = *r
		if r.Enabled {
			activeCount++
			n := countDomainLabels(r.Domain)
			if n < minL {
				minL = n
			}
			if n > maxL {
				maxL = n
			}
		}
	}

	if activeCount == 0 {
		minL = 1
		maxL = 128
	}
	customRulesMinLabels.Store(int32(minL))
	customRulesMaxLabels.Store(int32(maxL))
	return activeCount
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
	activeCount := rebuildRulesIndexLocked()
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

	if len(customRules) == 0 || domain == "" {
		return "", ""
	}

	group = strings.ToLower(group)

	var groupRules map[string]CustomRule
	if group != "" && group != "global" {
		groupRules = customRulesMap[group]
	}
	globalRules := customRulesMap["global"]

	if groupRules == nil && globalRules == nil {
		return "", ""
	}

	search := domain
	labels := countDomainLabels(domain)
	ceiling := int(customRulesMaxLabels.Load())
	floor := int(customRulesMinLabels.Load())

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
		if idx < 0 || labels <= floor {
			break
		}
		search = search[idx+1:]
		labels--
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
	rebuildRulesIndexLocked()
}

