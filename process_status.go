/*
File:    process_status.go
Version: 1.0.0
Last Updated: 05-Aug-2026 23:10 CEST

Description:
  Shared log-status annotation for the sdproxy resolution pipeline.

  The cache-hit path and the upstream-miss path both terminate in a query log
  line, and both must decorate that line with the parental verdict, the rrs:
  alias marker and the ECS disposition. Before the 3.90.0 split these two
  blocks were sixty near-identical lines duplicated in one function — and they
  had already drifted apart. This file is the single source of truth.

Changes:
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
	"time"
)

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
			// Budget values take the form "untrigger <duration>"; index 9 skips
			// the keyword and its trailing space. The length guard rejects a
			// bare "untrigger" with no duration attached.
			if len(val) > 9 {
				if d, err := time.ParseDuration(strings.TrimSpace(val[9:])); err == nil {
					dur = d
				}
			}
		}
	}

	timerKey := qc.clientID + "|" + qc.parentalCategory
	if existing, ok := untriggerLogTimers.Load(timerKey); ok {
		existing.(*time.Timer).Stop()
	}

	// Bind by value. The closure outlives this request by design, so it must not
	// depend on the queryCtx — which is stack-scoped to ProcessDNS — surviving.
	logProtocol := qc.protocol
	logClientID := qc.clientID

	t := time.AfterFunc(dur, func() {
		log.Printf("[DNS] [%s] %s | PARENTAL UNTRIGGER WINDOW ENDED | Normal strict BLOCK policies resumed.",
			logProtocol, logClientID)
		untriggerLogTimers.Delete(timerKey)
	})
	untriggerLogTimers.Store(timerKey, t)
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
func (qc *queryCtx) annotateECS(status string) string {
	if qc.cacheKey.ECS == "passed-ecs" {
		return status + " [ECS: PASS]"
	}
	if qc.cacheKey.ECS == "" {
		return status
	}
	if qc.group != nil && qc.group.ECSAction == "add" {
		return status + fmt.Sprintf(" [ECS: ADD %s]", qc.cacheKey.ECS)
	}
	return status + " [ECS: PASS]"
}
