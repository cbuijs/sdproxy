/*
File:    process_status.go
Version: 1.1.0
Last Updated: 07-Aug-2026 21:30 CEST

Description:
  Shared log-status annotation for the sdproxy resolution pipeline.

  The cache-hit path and the upstream-miss path both terminate in a query log
  line, and both must decorate that line with the parental verdict, the rrs:
  alias marker and the ECS disposition. Before the 3.90.0 split these two
  blocks were sixty near-identical lines duplicated in one function — and they
  had already drifted apart. This file is the single source of truth.

Changes:
  1.1.0 - [FIX] scheduleUntriggerExpiry had two timer-lifecycle defects, both
          reachable from any client that hits an untrigger source twice.

          Race: the Load -> Stop -> Store sequence was not atomic. Two queries
          arriving concurrently for the same (client, category) both observed
          the same existing timer, both stopped it, and both stored — leaving
          one live timer with no map entry, i.e. a leak that fires a spurious
          "WINDOW ENDED" line at an arbitrary later moment.

          Stale delete: the AfterFunc callback deleted the map key
          unconditionally. If the window had since been extended, the callback
          for the SUPERSEDED timer removed the map entry belonging to the
          CURRENT one. The next extension then found nothing to stop, so it
          armed a second live timer, and the client received two window-ended
          notices for one window — and each further extension added another.

          Both are closed by a dedicated mutex around the swap plus an identity
          check in the callback: the entry is removed only if it is still the
          timer that is firing. The mutex is taken only on the ACTIVATING_
          UNTRIGGER verdict, not on the query hot path.
        - [FIX] The untrigger duration parser accepted any budget string longer
          than nine characters and sliced val[9:] out of it. That happened to
          be harmless (ParseDuration rejects the garbage and the default is
          kept) but it was parsing a value it had never established was an
          "untrigger ..." directive at all. Now prefix-checked, and a
          non-positive parsed duration falls back to the default rather than
          arming a timer that fires immediately.
        - [FIX] annotateECS no longer assumes qc.group is non-nil. It is now
          populated at stage 4 (process_query.go 1.1.0), which is what makes it
          callable from the cache-hit path at all — but paths that exit before
          stage 4 completes still reach the log line with a nil group, and
          "add" must not silently render as "[ECS: PASS]" for them.
  1.0.0 - [REFACTOR] Extracted from process.go 3.90.0.
        - [FIX] Unified two divergent renderings of the same parental verdict.
          A parentalReason of "UNTRIGGER" logged "(PARENTAL UNTRIGGER: ...)"
          when the answer came from cache but "(UNTRIGGERED BYPASS: ...)" when
          it came from upstream — identical policy state, two different strings,
          depending purely on whether the record happened to be cached. An
          operator grepping their logs would see one and not the other.
          Unified on the upstream wording, which describes what actually
          happened rather than naming the mechanism.
        - [FIX] The ACTIVATING_UNTRIGGER and UNTRIGGER_SOURCE verdicts were
          handled ONLY on the upstream path. CheckParental runs BEFORE the cache
          lookup, so both can be reached by a query that then hits cache — in
          which case the cache path fell through to the generic
          "(CATEGORY: ...)" branch and, critically, never armed the window-expiry
          timer. A client that activated an untrigger window on a cached name
          therefore never received the "WINDOW ENDED" notice at all. Both
          verdicts are now handled identically on both paths.
*/

package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// untriggerTimerMu serialises the stop-and-replace swap on untriggerLogTimers.
//
// [FIX 1.1.0] untriggerLogTimers is a sync.Map, which makes each individual
// operation atomic but says nothing about the Load -> Stop -> Store SEQUENCE
// that re-arming requires. Two concurrent activations for the same key both
// read the same predecessor, both stopped it, and both stored — one of the two
// stored timers then had no map entry and could never be stopped again.
//
// A plain Mutex is the right instrument here rather than something cleverer:
// it is taken only when a query actually carries the ACTIVATING_UNTRIGGER
// verdict, which is a rare administrative event, never on the resolution hot
// path. The sync.Map is kept because the callback and any future reader still
// benefit from lock-free reads.
var untriggerTimerMu sync.Mutex

// annotateParental appends the parental verdict to a status string.
//
// Returns status unchanged when there is no verdict to report, so callers do
// not need to guard.
//
// [FIX 1.0.0] This is deliberately path-agnostic. The two copies it replaces
// had drifted — see the file header — and the drift was invisible precisely
// because the strings only differ on the branch a given query does not take.
func (qc *queryCtx) annotateParental(status string) string {
	switch qc.parentalReason {
	case "FREE":
		return status + parentalSuffix("PARENTAL FREE", qc.parentalCategory, qc.parentalMatchedApex)

	case "ALLOW":
		return status + parentalSuffix("PARENTAL ALLOW", qc.parentalCategory, qc.parentalMatchedApex)

	case "LOG":
		return status + parentalSuffix("PARENTAL LOG", qc.parentalCategory, qc.parentalMatchedApex)

	case "UNTRIGGER":
		// [FIX 1.0.0] Was "PARENTAL UNTRIGGER" on the cache path and
		// "UNTRIGGERED BYPASS" on the upstream path. One string now.
		return status + parentalSuffix("UNTRIGGERED BYPASS", qc.parentalCategory, qc.parentalMatchedApex)

	case "ACTIVATING_UNTRIGGER":
		// [FIX 1.0.0] Previously unreachable on the cache-hit path, which meant
		// a query that opened an untrigger window against an already-cached name
		// silently skipped the timer below and never announced the window
		// closing. CheckParental runs before the cache lookup, so this verdict
		// reaches both paths and must be handled on both.
		qc.scheduleUntriggerExpiry()
		return status + parentalSuffix("ACTIVATING UNTRIGGER WINDOW", qc.parentalCategory, qc.parentalMatchedApex)

	case "UNTRIGGER_SOURCE":
		return status + parentalSuffix("UNTRIGGER SOURCE", qc.parentalCategory, qc.parentalMatchedApex)
	}

	// No specific verdict, but the name was still categorised.
	if qc.parentalCategory != "" {
		return status + fmt.Sprintf(" (CATEGORY: %s, apex: %s)", qc.parentalCategory, qc.parentalMatchedApex)
	}
	return status
}

// parentalSuffix renders "(LABEL: category, apex: apex)", degrading to
// "(LABEL)" when the verdict carried no category.
//
// The degraded form matters: several verdicts (a group-wide FREE window, for
// instance) apply to the whole client rather than to a categorised domain, and
// printing "category: , apex: " for those was noise in every log line.
func parentalSuffix(label, category, apex string) string {
	if category == "" {
		return " (" + label + ")"
	}
	return fmt.Sprintf(" (%s: %s, apex: %s)", label, category, apex)
}

// untriggerBudgetPrefix is the keyword that introduces an untrigger directive
// in a group's Budget map, including its trailing separator space. Sliced off
// to leave the duration.
const untriggerBudgetPrefix = "untrigger "

// scheduleUntriggerExpiry arms the asynchronous notice announcing the end of a
// parental untrigger window.
//
// Without it the operator sees the window open and then has to infer that it
// closed from the absence of further bypass lines — which is indistinguishable
// from the client simply going quiet.
//
// Re-arming semantics: a client that keeps hitting the untrigger source extends
// its window, so any timer already pending for this (client, category) pair is
// stopped before the replacement is installed. Skipping that would queue one
// goroutine-backed timer per query from a chatty client.
func (qc *queryCtx) scheduleUntriggerExpiry() {
	// Default matches the parental engine's own fallback window.
	dur := 5 * time.Minute

	if qc.clientGroup != "" {
		if grp, ok := cfg.Groups[qc.clientGroup]; ok {
			val := grp.Budget[qc.parentalCategory]
			if val == "" {
				val = grp.Budget["total"]
			}

			// [FIX 1.1.0] Establish that this IS an untrigger directive before
			// slicing a duration out of it.
			//
			// The previous form was `if len(val) > 9 { ParseDuration(val[9:]) }`,
			// which happily took the tail of any eleven-character budget string
			// and handed it to the parser. It never misbehaved — ParseDuration
			// rejects the garbage and the default survives — but it was a
			// positional assumption about a config value whose shape had never
			// been checked, i.e. correct by luck rather than by construction.
			if strings.HasPrefix(val, untriggerBudgetPrefix) {
				if d, err := time.ParseDuration(strings.TrimSpace(val[len(untriggerBudgetPrefix):])); err == nil && d > 0 {
					dur = d
				}
			}
		}
	}

	timerKey := qc.clientID + "|" + qc.parentalCategory

	// Bind by value. The closure outlives this request by design, so it must not
	// depend on the queryCtx — which is stack-scoped to ProcessDNS — surviving.
	logProtocol := qc.protocol
	logClientID := qc.clientID

	// ── [FIX 1.1.0] Atomic stop-and-replace ──────────────────────────────
	//
	// Everything from the Load to the Store happens under untriggerTimerMu, so
	// two concurrent activations for the same key serialise: the second one is
	// guaranteed to observe the timer the first one installed, and therefore to
	// stop it rather than orphan it.
	untriggerTimerMu.Lock()
	defer untriggerTimerMu.Unlock()

	if existing, ok := untriggerLogTimers.Load(timerKey); ok {
		existing.(*time.Timer).Stop()
	}

	// `self` is declared before the closure so the callback can compare the map
	// entry against ITSELF. Reading it is safe despite the apparent write-after-
	// capture: the callback's first act is to take untriggerTimerMu, which this
	// function holds until after the assignment and the Store below. Even a
	// zero-duration timer therefore cannot observe a nil `self`.
	var self *time.Timer

	self = time.AfterFunc(dur, func() {
		log.Printf("[DNS] [%s] %s | PARENTAL UNTRIGGER WINDOW ENDED | Normal strict BLOCK policies resumed.",
			logProtocol, logClientID)

		// [FIX 1.1.0] Identity-checked delete.
		//
		// The unconditional Delete this replaces removed whatever was under the
		// key, which after an extension was the SUCCESSOR timer's entry, not
		// this one's. The successor then became invisible to the next
		// extension, which armed a further timer without stopping it — so a
		// client that kept extending its window accumulated one spurious
		// "WINDOW ENDED" line per extension, all of them arriving while the
		// window was in fact still open.
		untriggerTimerMu.Lock()
		if cur, ok := untriggerLogTimers.Load(timerKey); ok && cur.(*time.Timer) == self {
			untriggerLogTimers.Delete(timerKey)
		}
		untriggerTimerMu.Unlock()
	})

	untriggerLogTimers.Store(timerKey, self)
}

// annotateAlias prefixes the rrs: CNAME alias marker when the question was
// rewritten. Prefix rather than suffix so the substitution is the first thing
// visible on the line — an operator debugging an unexpected answer needs to know
// the name was rewritten before they read anything else about it.
func (qc *queryCtx) annotateAlias(status string) string {
	if qc.spoofedAlias == "" {
		return status
	}
	return fmt.Sprintf("SPOOFED ALIAS (%s) | %s", qc.spoofedAlias, status)
}

// annotateECS appends the EDNS0 Client Subnet disposition.
//
// Reads the derived cache key rather than re-deriving from the group, because
// the key is what actually partitioned the cache — if those two ever disagree,
// the log should show the value that governed the lookup, not the one that was
// supposed to.
//
// [FIX 1.1.0] Called from BOTH terminal paths now. It was upstream-only in
// 1.0.0, despite this file's own header promising the ECS disposition as one of
// the three annotations it unified — so a cache hit against an ECS-partitioned
// entry logged nothing about the subnet that selected it. That was only
// possible to fix once qc.group became available before the cache lookup
// (process_query.go 1.1.0); with the group still unset at stage 4, an "add"
// group would have mislabelled every cached answer as "[ECS: PASS]".
func (qc *queryCtx) annotateECS(status string) string {
	if qc.cacheKey.ECS == "passed-ecs" {
		return status + " [ECS: PASS]"
	}
	if qc.cacheKey.ECS == "" {
		return status
	}

	// A nil group means the query exited before stage 4 finished resolving one.
	// The key carries a subnet, so ECS is definitely in play — but we cannot
	// tell whether it was injected or forwarded. Say so rather than guessing:
	// silently rendering "PASS" for an "add" group is exactly the mislabelling
	// this annotation exists to prevent.
	if qc.group == nil {
		return status + fmt.Sprintf(" [ECS: %s]", qc.cacheKey.ECS)
	}

	if qc.group.ECSAction == "add" {
		return status + fmt.Sprintf(" [ECS: ADD %s]", qc.cacheKey.ECS)
	}
	return status + " [ECS: PASS]"
}
