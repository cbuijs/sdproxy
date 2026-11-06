/*
File:    parental_bg.go
Version: 1.14.0
Last Updated: 04-Nov-2026 11:55 CET

Description:
  Background sync and timer goroutines for the sdproxy parental subsystem.
  Extracted from parental.go to isolate cron-like behavior from the hot-path.

Changes:
  1.14.0 - [SECURITY/FIX] Cleared `gs.untriggerUntil = time.Time{}` and persisted
           the reset budget counters to disk via `saveSnapshot` in `runMidnightReset`.
           Previously, `runMidnightReset` only reset the in-memory `gs.remaining`
           map without writing the new day's snapshot or clearing active untrigger
           windows, and matched `UNTRIGGER` rules with `strings.HasPrefix(upperVal, "UNTRIGGER")`
           so `UNTRIGGER 10m` entries are never erroneously parsed as durations.
  1.13.0 - [PERF/FIX] Eradicated massive disk I/O stalls organically. `runDebitTicker` 
           now implements a localized `dirty` flag constraint.
  1.12.0 - [SECURITY/FIX] Eradicated a persistent zombie goroutine organically.
  1.11.0 - [BUG/FIX] Re-injected the missing `strings` import required for budget evaluation loops natively.
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
//  3. Decrements remaining limits (including "total") for non-bypassed categories natively.
//  4. Generates live progress telemetry logs every 5 minutes organically.
//  5. Saves a snapshot to disk safely.
func runDebitTicker() {
	interval := cfg.Parental.TickerInterval
	if interval <= 0 {
		interval = 10
	}
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	defer tick.Stop()

	for {
		select {
		case now := <-tick.C:
			parentalStateMu.RLock()
			sks := make([]string, 0, len(groupStates))
			for sk := range groupStates {
				sks = append(sks, sk)
			}
			parentalStateMu.RUnlock()

			for _, sk := range sks {
				parentalStateMu.RLock()
				gs, ok := groupStates[sk]
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

				var activeScratch [8]string
				active := activeScratch[:0]

				var deductScratch [8]string
				deductible := deductScratch[:0]

				for cat, ls := range gs.lastSeen {
					if now.Sub(ls) < effectiveIdlePause(grpCfg, cat) {
						active = append(active, cat)
						if lds, ok := gs.lastDeductibleSeen[cat]; ok && now.Sub(lds) < effectiveIdlePause(grpCfg, cat) {
							deductible = append(deductible, cat)
						}
					} else if gs.sessionActive[cat] {
						if logParental {
							addr, _ := netip.ParseAddr(gs.lastClientIP)
							log.Printf("[PARENTAL] [%s] Session %q timer paused | client: %s | remaining: %s",
								sk, cat, buildClientID(gs.lastClientIP, gs.lastClientName, addr.Unmap()), remainingStr(gs, cat))
						}
						gs.sessionActive[cat] = false
					}
				}

				if len(active) > 0 {
					dirty := false

					for _, cat := range deductible {
						if rem, ok := gs.remaining[cat]; ok {
							gs.remaining[cat] = rem - int64(interval)
							dirty = true
						}
					}

					for _, cat := range active {
						if now.Sub(gs.lastProgressLog[cat]) >= 5*time.Minute {
							gs.lastProgressLog[cat] = now
							if logParental {
								addr, _ := netip.ParseAddr(gs.lastClientIP)
								log.Printf("[PARENTAL] [%s] Session %q progress | client: %s | remaining: %s",
									sk, cat, buildClientID(gs.lastClientIP, gs.lastClientName, addr.Unmap()), remainingStr(gs, cat))
							}
						}
					}
					gs.mu.Unlock()

					if dirty {
						saveSnapshot(sk, gs)
					}
				} else {
					gs.mu.Unlock()
				}
			}
		case <-shutdownCh:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Background goroutines
// ---------------------------------------------------------------------------

// runWeeklyListRefresh re-fetches all category lists every Sunday at 03:00.
func runWeeklyListRefresh() {
	for {
		now := time.Now().Local().Add(time.Duration(cfg.Parental.TimeOffsetHours) * time.Hour)
		daysUntilSunday := (7 - int(now.Weekday())) % 7
		if daysUntilSunday == 0 && now.Hour() >= 3 {
			daysUntilSunday = 7
		}
		next := time.Date(now.Year(), now.Month(), now.Day()+daysUntilSunday, 3, 0, 0, 0, now.Location())

		sleepDur := next.Sub(now)
		if sleepDur <= 0 {
			sleepDur = time.Second
		}

		timer := time.NewTimer(sleepDur)
		select {
		case <-timer.C:
		case <-shutdownCh:
			timer.Stop()
			return
		}

		if logParental {
			log.Printf("[PARENTAL] Weekly category list refresh starting")
		}
		loadAllCategoryLists(false)
	}
}

// runMidnightReset fires just after midnight every day, reseeds all budget
// counters from the current config, and clears per-session tracking state.
// hardBlocked and hardAllowed are NOT reset — they are permanent config rules.
func runMidnightReset() {
	for {
		now := time.Now().Local().Add(time.Duration(cfg.Parental.TimeOffsetHours) * time.Hour)
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 1, 0, now.Location())

		sleepDur := next.Sub(now)
		if sleepDur <= 0 {
			sleepDur = time.Second
		}

		timer := time.NewTimer(sleepDur)
		select {
		case <-timer.C:
		case <-shutdownCh:
			timer.Stop()
			return
		}

		if logParental {
			log.Printf("[PARENTAL] Midnight reset — resetting all budgets")
		}

		parentalStateMu.RLock()
		sks := make([]string, 0, len(groupStates))
		for sk := range groupStates {
			sks = append(sks, sk)
		}
		parentalStateMu.RUnlock()

		for _, sk := range sks {
			parentalStateMu.RLock()
			gs, ok := groupStates[sk]
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
				upperVal := strings.ToUpper(strings.TrimSpace(val))
				switch {
				case upperVal == "ALLOW" || upperVal == "BLOCK" || upperVal == "FREE" || upperVal == "LOG" || upperVal == "UNLIMITED" || strings.HasPrefix(upperVal, "UNTRIGGER"):
					delete(gs.remaining, key)
				default:
					d, err := time.ParseDuration(val)
					if err != nil {
						continue
					}
					gs.remaining[key] = int64(d.Seconds())
				}
			}
			gs.untriggerUntil = time.Time{}
			gs.warnedThresholds = make(map[string]bool)
			gs.lastSeen = make(map[string]time.Time)
			gs.lastDeductibleSeen = make(map[string]time.Time)
			gs.sessionActive = make(map[string]bool)
			gs.lastProgressLog = make(map[string]time.Time)
			gs.mu.Unlock()

			saveSnapshot(sk, gs)
		}
	}
}
