/*
File:    parental_sched.go
Version: 1.5.0
Last Updated: 04-Nov-2026 20:55 CET

Description:
  Schedule validation, duration evaluation, and budget accounting formatting.
  Extracted from parental.go to logically separate strict time and scheduling
  operations from the hot-path router logic.

Changes:
  1.5.0 - [FIX] Guarded `checkBudgetWarning` log output with `if logParental`
          while keeping threshold state tracking active so Simple Logging Mode
          (`logSimple: true`) does not emit runtime `[PARENTAL] Budget warning`
          lines.
  1.4.0 - [FEAT] Guarded `logBlockRateLimited` with `!logSimple && logParental`
          so Simple Logging Mode does not emit a second `[PARENTAL]` block line
          in addition to the `[DNS]` per-query answer line.
  1.3.0 - [FEAT] Incorporated `cfg.Parental.TimeOffsetHours` dynamically into 
          `inAnyScheduleWindow` to enable administrators to actively shift 
          system timezone constraints natively for schedule bounds.
  1.2.0 - [SECURITY/FIX] Hardened the `inAnyScheduleWindow` mechanic to explicitly 
          invoke `time.Now().Local()` securely.
  1.1.0 - [FIX] Resolved a severe scheduling interpretation flaw. 
          The documented `weekdays` and `weekend` string macros were missing 
          from the `dayNamesMap` evaluation loop.
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

func effectiveBlockTTL(groupTTL int) int {
	if groupTTL > 0 {
		return groupTTL
	}
	if cfg.Parental.BlockTTL > 0 {
		return cfg.Parental.BlockTTL
	}
	return 20
}

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
	if logSimple || !logParental {
		return
	}
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
			if logParental {
				log.Printf("[PARENTAL] [%s] Budget warning: %q has %s left", sk, key, fmtSeconds(rem))
			}
		}
	}
}

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

func inAnyScheduleWindow(schedule []string) bool {
	now := time.Now().Local().Add(time.Duration(cfg.Parental.TimeOffsetHours) * time.Hour)
	for _, entry := range schedule {
		if inScheduleEntry(now, entry) {
			return true
		}
	}
	return false
}

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
		dayPart = parts[0]
		timePart = parts[1]
	}
	if dayPart != "" {
		if !parseScheduleDays(dayPart, t.Weekday()) {
			return false
		}
	}
	return inTimeRange(t, timePart)
}

func parseScheduleDays(spec string, wd time.Weekday) bool {
	spec = strings.ToLower(spec)
	spec = strings.ReplaceAll(spec, "weekdays", "mon-fri")
	spec = strings.ReplaceAll(spec, "weekend", "sat,sun")

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "-"); idx > 0 {
			start, ok1 := dayNamesMap[strings.ToLower(part[:idx])]
			end, ok2 := dayNamesMap[strings.ToLower(part[idx+1:])]
			if !ok1 || !ok2 {
				continue
			}
			if start <= end {
				if wd >= start && wd <= end {
					return true
				}
			} else {
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

func inTimeRange(t time.Time, rangeStr string) bool {
	idx := strings.Index(rangeStr, "-")
	if idx < 0 {
		return false
	}
	startH, startM, ok1 := parseHHMM(rangeStr[:idx])
	endH, endM, ok2 := parseHHMM(rangeStr[idx+1:])
	if !ok1 || !ok2 {
		return false
	}
	cur := t.Hour()*60 + t.Minute()
	start := startH*60 + startM
	end := endH*60 + endM

	if end == 1439 {
		end = 1440
	}

	if start <= end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end
}

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

var dayNamesMap = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday,
	"mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tuesday": time.Tuesday,
	"wed": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}
