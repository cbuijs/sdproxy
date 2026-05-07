/*
File:    parental_bg.go
Version: 1.4.0
Updated: 27-Apr-2026 17:51 CEST

Description:
  Background sync and timer goroutines for the sdproxy parental subsystem.
  Extracted from parental.go to isolate cron-like behavior from the hot-path.

Changes:
  1.4.0 - [FIX] Substituted legacy `clientLabel` invocation with `buildClientID` 
          to resolve build errors following the telemetry standardization refactor.
  1.3.0 - [FIX] Adjusted `runDebitTicker` to iterate over `gs.lastSeen` instead 
          of `gs.remaining`. This guarantees categories functioning with an 
          "unlimited" configuration properly activate activity trackers and 
          successfully drain the "total" umbrella budget.
  1.2.0 - [PERF] Updated `clientLabel` bindings to accommodate the new `netip.Addr` 
          high-performance signatures.
*/

package main

import (
	"log"
	"net/netip"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Background debit ticker
// ---------------------------------------------------------------------------

// runDebitTicker fires every ticker_interval seconds and:
//  1. Identifies which categories are still within their idle_pause window.
//  2. Logs "timer paused" for categories that just went idle.
//  3. Decrements remaining[cat] and remaining["total"] for active categories.
//  4. Saves a snapshot to disk.
func runDebitTicker() {
	interval := cfg.Parental.TickerInterval
	if interval <= 0 {
		interval = 10
	}
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	defer tick.Stop()

	for now := range tick.C {
		parentalStateMu.RLock()
		sks := make([]string, 0, len(groupStates))
		for sk := range groupStates {
			sks = append(sks, sk)
		}
		parentalStateMu.RUnlock()

		for _, sk := range sks {
			parentalStateMu.RLock()
			gs, ok    := groupStates[sk]
			groupName := stateToGroup[sk]
			parentalStateMu.RUnlock()
			if !ok {
				continue
			}
			grpCfg, ok := cfg.Groups[groupName]
			if !ok {
				continue
			}
			gs.mu.Lock()

			// Stack-allocate a small scratch slice for the active category list —
			// avoids a heap allocation on the common (≤8 categories) case.
			var activeScratch [8]string
			active := activeScratch[:0]

			// By iterating over lastSeen, we ensure that ANY category explicitly visited
			// registers activity. This securely captures "unlimited" categories ensuring
			// they trigger the deduction against the "total" umbrella budget.
			for cat, ls := range gs.lastSeen {
				if cat == "total" {
					continue
				}
				if now.Sub(ls) < effectiveIdlePause(grpCfg, cat) {
					active = append(active, cat)
				} else if gs.sessionActive[cat] {
					addr, _ := netip.ParseAddr(gs.lastClientIP)
					log.Printf("[PARENTAL] [%s] Category %q timer paused | client: %s | remaining: %s",
						sk, cat, buildClientID(gs.lastClientIP, gs.lastClientName, addr.Unmap()), remainingStr(gs, cat))
					gs.sessionActive[cat] = false
				}
			}

			if len(active) > 0 {
				for _, cat := range active {
					if rem, ok := gs.remaining[cat]; ok {
						gs.remaining[cat] = rem - int64(interval)
					}
				}
				if rem, ok := gs.remaining["total"]; ok {
					gs.remaining["total"] = rem - int64(interval)
				}
				gs.mu.Unlock()
				saveSnapshot(sk, gs)
			} else {
				gs.mu.Unlock()
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Background goroutines
// ---------------------------------------------------------------------------

// runWeeklyListRefresh re-fetches all category lists every Sunday at 03:00.
func runWeeklyListRefresh() {
	for {
		now             := time.Now()
		daysUntilSunday := (7 - int(now.Weekday())) % 7
		if daysUntilSunday == 0 && now.Hour() >= 3 {
			daysUntilSunday = 7
		}
		next := time.Date(now.Year(), now.Month(), now.Day()+daysUntilSunday, 3, 0, 0, 0, now.Location())
		time.Sleep(time.Until(next))
		log.Printf("[PARENTAL] Weekly category list refresh starting")
		loadAllCategoryLists(false) // Weekly background updates utilize standard cache metadata
	}
}

// runMidnightReset fires just after midnight every day, reseeds all budget
// counters from the current config, and clears per-session tracking state.
// hardBlocked and hardAllowed are NOT reset — they are permanent config rules.
func runMidnightReset() {
	for {
		now  := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 1, 0, now.Location())
		time.Sleep(time.Until(next))
		log.Printf("[PARENTAL] Midnight reset — resetting all budgets")

		parentalStateMu.RLock()
		sks := make([]string, 0, len(groupStates))
		for sk := range groupStates {
			sks = append(sks, sk)
		}
		parentalStateMu.RUnlock()

		for _, sk := range sks {
			parentalStateMu.RLock()
			gs, ok    := groupStates[sk]
			groupName := stateToGroup[sk]
			parentalStateMu.RUnlock()
			if !ok {
				continue
			}
			grpCfg, ok := cfg.Groups[groupName]
			if !ok {
				continue
			}
			gs.mu.Lock()
			for key, val := range grpCfg.Budget {
				switch strings.ToLower(val) {
				case "allow", "block", "free", "log", "unlimited":
					delete(gs.remaining, key) // permanent rules carry no counter
				default:
					d, err := time.ParseDuration(val)
					if err != nil {
						continue
					}
					gs.remaining[key] = int64(d.Seconds())
				}
			}
			gs.warnedThresholds = make(map[string]bool)
			gs.lastSeen         = make(map[string]time.Time)
			gs.sessionActive    = make(map[string]bool)
			gs.mu.Unlock()
		}
	}
}

