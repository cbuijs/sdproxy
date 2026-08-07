/*
File:    process_query.go
Version: 1.0.0
Last Updated: 05-Aug-2026 23:10 CEST

Description:
  Per-query execution context for the sdproxy resolution pipeline.

  ProcessDNS accumulates roughly thirty pieces of per-query state before it can
  reach the cache lookup or the upstream dial: the transport handles, the
  normalised question, six client identity strings, the pre-lowercased DPI
  inputs, the routing verdict, the parental verdict and the derived cache key.
  Every downstream stage needs some subset of it.

  queryCtx exists so those stages can be separate functions instead of one
  thousand-line monolith. The alternative — threading the state positionally —
  is not hypothetical: the file this replaces once carried a twenty-parameter
  `executeUpstreamExchange`, which drifted silently out of sync with the live
  inline copy and took the qname_min_labels / qname_max_labels enforcement with
  it when it died. A struct makes that class of drift structurally impossible,
  because there is exactly one definition of what a query is.

Changes:
  1.0.0 - [REFACTOR] Extracted from process.go 3.90.0 as part of splitting a
          1.031-line file. Pure state carrier: no behaviour, no methods beyond
          trivial accessors, so the split itself changes nothing at runtime.
*/

package main

import (
	"net/netip"

	"github.com/miekg/dns"
)

// queryCtx carries the full per-query state through the resolution pipeline.
//
// Lifetime is exactly one ProcessDNS invocation. It is stack-allocated and
// passed by pointer; it is never shared across goroutines, never cached and
// never retained past the response write, so no field needs synchronisation.
//
// Field grouping mirrors the pipeline order in which the values become known,
// so a reader can tell at a glance which stage populates what. Anything below
// the "Populated by stage N" markers is zero until that stage has run — the
// stages themselves are ordered in ProcessDNS and must not be reordered without
// re-checking those dependencies.
type queryCtx struct {
	// ── Transport (populated at entry) ────────────────────────────────────
	w dns.ResponseWriter
	r *dns.Msg
	q dns.Question

	// ── Question (populated at entry) ─────────────────────────────────────
	//
	// qNameTrimmed is the ACTIVE resolution target and may have been rewritten
	// by an rrs: CNAME alias. originalQName / originalQNameTrimmed always hold
	// what the client actually asked for.
	//
	// Keeping both is not redundancy: policy decisions evaluate the target,
	// while telemetry and block records must attribute to the original, or an
	// operator sees blocks against a name nobody queried.
	qNameTrimmed         string
	originalQName        string
	originalQNameTrimmed string

	// originalID preserves the client's transaction ID across the pipeline.
	// Upstream exchanges deliberately randomise the ID they send (anti-spoofing),
	// so the response must be stamped back to the original before it is written.
	originalID uint16

	// doBit records the client's EDNS0 DNSSEC-OK flag. Partitions the cache and
	// governs whether RRSIG/NSEC records survive the minimise-answer transform.
	doBit bool

	// ── Client identity (populated at entry) ──────────────────────────────
	clientIP   string
	clientAddr netip.Addr
	clientMAC  string
	clientName string
	clientID   string

	// clientNameLower / sniLower / pathLower are pre-computed once here because
	// the policy, parental and filter stages each match against them several
	// times. Lowercasing per comparison instead cost millions of throwaway
	// strings under DPI-heavy configurations.
	clientNameLower string

	// ── Transport metadata (populated at entry) ───────────────────────────
	protocol  string
	sni       string
	sniLower  string
	path      string
	pathLower string

	// ── Populated by stage 1.5: identity resolution ───────────────────────
	//
	// sk is the parental state key; clientGroup the resolved policy group.
	// Both are re-resolved if the routing stage overrides the client name.
	sk          string
	clientGroup string

	// ── Populated by stages 1.6-1.8: overrides ────────────────────────────
	//
	// bypassGlobal comes from the client route (skip global rrs: and domain
	// policy). bypassPolicies comes from an explicit ALLOW custom rule.
	// They are NOT interchangeable and are deliberately kept separate: one is a
	// routing property, the other an administrative override, and they partition
	// the cache independently.
	bypassGlobal   bool
	bypassPolicies bool

	// spoofedAlias names the rrs: CNAME target when the question was rewritten,
	// otherwise empty. Log annotation only.
	spoofedAlias string

	// ── Populated by stage 2: routing ─────────────────────────────────────
	route routingContext

	// ── Populated by stage 3: parental controls ───────────────────────────
	//
	// Only reached when the query was NOT blocked — a block returns directly.
	// forcedTTL caps the response TTL so a budget window cannot be outlived by
	// a long-lived cached answer on the client side.
	parentalForcedTTL   uint32
	parentalReason      string
	parentalCategory    string
	parentalMatchedApex string

	// ── Populated by stage 4: cache key derivation ────────────────────────
	cacheKey DNSCacheKey

	// ── Populated by stage 7: upstream group resolution ───────────────────
	//
	// Guaranteed non-nil with at least one server once stage 7 has run; the
	// stage returns early otherwise.
	group *UpstreamGroup
}

// qtypeStr renders the question type for log lines.
//
// Trivial, but it appears in a dozen log statements across four files, and
// dns.TypeToString returns the empty string for unknown types — which produced
// log lines with a blank column rather than something diagnosable.
func (qc *queryCtx) qtypeStr() string {
	if s, ok := dns.TypeToString[qc.q.Qtype]; ok {
		return s
	}
	return "TYPE" + itoaU16(qc.q.Qtype)
}

// itoaU16 formats a uint16 without pulling strconv into the hot path's import
// set for a single call site.
func itoaU16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
