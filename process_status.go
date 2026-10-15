/*
File:    process_status.go
Version: 1.2.0
Last Updated: 15-Oct-2026 17:26 CEST

Description:
  Shared log-status annotation for the sdproxy resolution pipeline.

  The cache-hit path and the upstream-miss path both terminate in a query log
  line, and both must decorate that line with the parental verdict, the rrs:
  alias marker and the ECS disposition.

Changes:
  1.2.0 - [FIX] Changed `strings.HasPrefix` on `untriggerBudgetPrefix` inside
          `scheduleUntriggerExpiry` to a case-insensitive check. Config values
          like `UNTRIGGER 10m` were previously ignored, falling back to 5m.
  1.1.0 - [FIX] scheduleUntriggerExpiry had two timer-lifecycle defects, both
          reachable from any client that hits an untrigger source twice.
        - [FIX] The untrigger duration parser accepted any budget string longer
          than nine characters and sliced val[9:] out of it.
        - [FIX] annotateECS no longer assumes qc.group is non-nil.
  1.0.0 - [REFACTOR] Extracted from process.go 3.90.0.
        - [FIX] Unified two divergent renderings of the same parental verdict.
        - [FIX] The ACTIVATING_UNTRIGGER and UNTRIGGER_SOURCE verdicts were
          handled ONLY on the upstream path.
*/

package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

var untriggerTimerMu sync.Mutex

func (qc *queryCtx) annotateParental(status string) string {
	switch qc.parentalReason {
	case "FREE":
		return status + parentalSuffix("PARENTAL FREE", qc.parentalCategory, qc.parentalMatchedApex)

	case "ALLOW":
		return status + parentalSuffix("PARENTAL ALLOW", qc.parentalCategory, qc.parentalMatchedApex)

	case "LOG":
		return status + parentalSuffix("PARENTAL LOG", qc.parentalCategory, qc.parentalMatchedApex)

	case "UNTRIGGER":
		return status + parentalSuffix("UNTRIGGERED BYPASS", qc.parentalCategory, qc.parentalMatchedApex)

	case "ACTIVATING_UNTRIGGER":
		qc.scheduleUntriggerExpiry()
		return status + parentalSuffix("ACTIVATING UNTRIGGER WINDOW", qc.parentalCategory, qc.parentalMatchedApex)

	case "UNTRIGGER_SOURCE":
		return status + parentalSuffix("UNTRIGGER SOURCE", qc.parentalCategory, qc.parentalMatchedApex)
	}

	if qc.parentalCategory != "" {
		return status + fmt.Sprintf(" (CATEGORY: %s, apex: %s)", qc.parentalCategory, qc.parentalMatchedApex)
	}
	return status
}

func parentalSuffix(label, category, apex string) string {
	if category == "" {
		return " (" + label + ")"
	}
	return fmt.Sprintf(" (%s: %s, apex: %s)", label, category, apex)
}

const untriggerBudgetPrefix = "untrigger "

func (qc *queryCtx) scheduleUntriggerExpiry() {
	dur := 5 * time.Minute

	if qc.clientGroup != "" {
		if grp, ok := cfg.Groups[qc.clientGroup]; ok {
			val := grp.Budget[qc.parentalCategory]
			if val == "" {
				val = grp.Budget["total"]
			}

			// [FIX 1.2.0] Case-insensitive prefix check for UNTRIGGER duration.
			if len(val) >= len(untriggerBudgetPrefix) && strings.EqualFold(val[:len(untriggerBudgetPrefix)], untriggerBudgetPrefix) {
				if d, err := time.ParseDuration(strings.TrimSpace(val[len(untriggerBudgetPrefix):])); err == nil && d > 0 {
					dur = d
				}
			}
		}
	}

	timerKey := qc.clientID + "|" + qc.parentalCategory

	logProtocol := qc.protocol
	logClientID := qc.clientID

	untriggerTimerMu.Lock()
	defer untriggerTimerMu.Unlock()

	if existing, ok := untriggerLogTimers.Load(timerKey); ok {
		existing.(*time.Timer).Stop()
	}

	var self *time.Timer

	self = time.AfterFunc(dur, func() {
		log.Printf("[DNS] [%s] %s | PARENTAL UNTRIGGER WINDOW ENDED | Normal strict BLOCK policies resumed.",
			logProtocol, logClientID)

		untriggerTimerMu.Lock()
		if cur, ok := untriggerLogTimers.Load(timerKey); ok && cur.(*time.Timer) == self {
			untriggerLogTimers.Delete(timerKey)
		}
		untriggerTimerMu.Unlock()
	})

	untriggerLogTimers.Store(timerKey, self)
}

func (qc *queryCtx) annotateAlias(status string) string {
	if qc.spoofedAlias == "" {
		return status
	}
	return fmt.Sprintf("SPOOFED ALIAS (%s) | %s", qc.spoofedAlias, status)
}

func (qc *queryCtx) annotateECS(status string) string {
	if qc.cacheKey.ECS == "passed-ecs" {
		return status + " [ECS: PASS]"
	}
	if qc.cacheKey.ECS == "" {
		return status
	}

	if qc.group == nil {
		return status + fmt.Sprintf(" [ECS: %s]", qc.cacheKey.ECS)
	}

	if qc.group.ECSAction == "add" {
		return status + fmt.Sprintf(" [ECS: ADD %s]", qc.cacheKey.ECS)
	}
	return status + " [ECS: PASS]"
}

