/*
File:    parental_sched.go
Description:
  Schedule validation, duration evaluation, and budget accounting formatting.
  Extracted from parental.go to logically separate strict time and scheduling
  operations from the hot-path router logic.
*/

package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Budget helpers
// ---------------------------------------------------------------------------

// effectiveBlockTTL returns the block TTL, falling back through:
// group config → global parental config → hard default (20 s).
func effectiveBlockTTL(groupTTL int) int {
	if groupTTL > 0 {
		return groupTTL
	}
	if cfg.Parental.BlockTTL > 0 {
		return cfg.Parental.BlockTTL
	}
	return 20
}

// effectiveIdlePause returns the idle-pause duration for a category, falling
// back through: category config → global default → deprecated alias → 2 m.
func effectiveIdlePause(_ GroupConfig, cat string) time.Duration {
	if cc, ok := cfg.Parental.Categories[cat]; ok {
		if cc.IdlePause != "" {
			if d, err := time.ParseDuration(cc.IdlePause); err == nil {
				return d
			}
		}
		if cc.SessionWindow != "" {
			if d, err := time.ParseDuration(cc.SessionWindow); err == nil {
				return d
			}
		}
	}
	if cfg.Parental.DefaultIdlePause != "" {
		if d, err := time.ParseDuration(cfg.Parental.DefaultIdlePause); err == nil {
			return d
		}
	}
	if cfg.Parental.DefaultSessionWindow != "" {
		if d, err := time.ParseDuration(cfg.Parental.DefaultSessionWindow); err == nil {
			return d
		}
	}
	return 2 * time.Minute
}

// logBlockRateLimited suppresses repeated block-log lines per state+reason key.
// Must be called with gs.mu held.
func logBlockRateLimited(gs *groupState, sk, key, msg string) {
	rk := sk + ":" + key
	if last, ok := gs.lastBlockLog[rk]; ok && time.Since(last) < blockLogRateLimit {
		return
	}
	gs.lastBlockLog[rk] = time.Now()
	log.Print(msg)
}

// checkBudgetWarning fires a one-shot log when the remaining budget for key
// crosses one of the budgetWarnThresholds for the first time today.
// Must be called with gs.mu held.
func checkBudgetWarning(gs *groupState, sk, key string) {
	rem, limited := gs.remaining[key]
	if !limited || rem <= 0 {
		return
	}
	for _, thresh := range budgetWarnThresholds {
		wk := key + ":" + strconv.FormatInt(thresh, 10)
		if rem <= thresh && !gs.warnedThresholds[wk] {
			gs.warnedThresholds[wk] = true
			log.Printf("[PARENTAL] [%s] Budget warning: %q has %s left", sk, key, fmtSeconds(rem))
		}
	}
}

// remainingStr returns a human-readable budget remaining string for key.
// Must be called with gs.mu held.
func remainingStr(gs *groupState, key string) string {
	rem, limited := gs.remaining[key]
	if !limited {
		return "unlimited"
	}
	if rem <= 0 {
		return "exhausted"
	}
	return fmtSeconds(rem)
}

// fmtSeconds formats a seconds count as a concise human string.
func fmtSeconds(sec int64) string {
	if sec <= 0 {
		return "0s"
	}
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// ---------------------------------------------------------------------------
// Schedule helpers
// ---------------------------------------------------------------------------

// inAnyScheduleWindow returns true when now falls inside at least one of the
// schedule entries. An empty schedule is treated as always-allowed.
func inAnyScheduleWindow(schedule []string) bool {
	now := time.Now()
	for _, entry := range schedule {
		if inScheduleEntry(now, entry) {
			return true
		}
	}
	return false
}

// inScheduleEntry parses and evaluates one schedule entry against t.
// Format: "[days ]HH:MM-HH:MM"  e.g. "Mon-Fri 08:00-17:00" or "07:00-22:00".
func inScheduleEntry(t time.Time, entry string) bool {
	entry = strings.TrimSpace(entry)
	parts := strings.Fields(entry)
	if len(parts) == 0 {
		return false
	}
	var dayPart, timePart string
	if len(parts) == 1 {
		timePart = parts[0]
	} else {
		dayPart  = parts[0]
		timePart = parts[1]
	}
	if dayPart != "" {
		if !parseScheduleDays(dayPart, t.Weekday()) {
			return false
		}
	}
	return inTimeRange(t, timePart)
}

// parseScheduleDays returns true when wd is covered by the day spec.
// Accepts: single day ("Mon"), range ("Mon-Fri"), or comma list ("Sat,Sun").
func parseScheduleDays(spec string, wd time.Weekday) bool {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "-"); idx > 0 {
			start, ok1 := dayNamesMap[strings.ToLower(part[:idx])]
			end,   ok2 := dayNamesMap[strings.ToLower(part[idx+1:])]
			if !ok1 || !ok2 {
				continue
			}
			if start <= end {
				if wd >= start && wd <= end {
					return true
				}
			} else { // wraps Sunday (e.g. Fri-Mon)
				if wd >= start || wd <= end {
					return true
				}
			}
		} else {
			if d, ok := dayNamesMap[strings.ToLower(part)]; ok && d == wd {
				return true
			}
		}
	}
	return false
}

// inTimeRange returns true when t falls within the HH:MM-HH:MM range.
// Ranges that cross midnight (e.g. "22:00-06:00") are handled correctly.
func inTimeRange(t time.Time, rangeStr string) bool {
	idx := strings.Index(rangeStr, "-")
	if idx < 0 {
		return false
	}
	startH, startM, ok1 := parseHHMM(rangeStr[:idx])
	endH,   endM,   ok2 := parseHHMM(rangeStr[idx+1:])
	if !ok1 || !ok2 {
		return false
	}
	cur   := t.Hour()*60 + t.Minute()
	start := startH*60 + startM
	end   := endH*60 + endM
	if start <= end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end // crosses midnight
}

// parseHHMM splits "HH:MM" into (hour, minute, ok).
func parseHHMM(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	idx := strings.Index(s, ":")
	if idx < 0 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(s[:idx])
	m, err2 := strconv.Atoi(s[idx+1:])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// dayNamesMap maps lowercase day abbreviations and full names to time.Weekday.
var dayNamesMap = map[string]time.Weekday{
	"sun": time.Sunday, "sunday":    time.Sunday,
	"mon": time.Monday, "monday":    time.Monday,
	"tue": time.Tuesday, "tuesday":  time.Tuesday,
	"wed": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday":    time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

