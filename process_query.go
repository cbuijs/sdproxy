/*
File:    process_query.go
Version: 1.4.0
Last Updated: 22-Oct-2026 13:35 CEST

Description:
  Per-query execution context for the sdproxy resolution pipeline.

Changes:
  1.4.0 - [FEAT] Added `ednsMAC` to `queryCtx` so post-cache and post-upstream
          policy and filter stages can pass the incoming EDNS0 Option 65001 MAC
          to `CheckParental` when `device` budget tracking is used on `mac:` routes.
  1.3.0 - [FIX] Added `ecsAddr` and `ecsPrefix` to `queryCtx` so post-cache and
          post-upstream policy and filter stages can pass the incoming EDNS0
          Client Subnet to `CheckParental` when `device` budget tracking is used
          on `ecs:` routes.
  1.2.0 - [FIX] Added `localPort` to `queryCtx` so downstream policy and filter
          stages can pass it to `CheckParental` when `device` budget tracking
          is used on port-based parental routes.
  1.1.0 - [FIX] `group` is now populated at stage 4 (cache-key derivation)
          rather than stage 7, and its field documentation says so.
        - [CLEANUP] Deleted itoaU16 in favour of the identical itoa64
          (stats_lastseen.go).
  1.0.0 - [REFACTOR] Extracted from process.go 3.90.0 as part of splitting a
          1.031-line file.
*/

package main

import (
	"net/netip"

	"github.com/miekg/dns"
)

type queryCtx struct {
	// ── Transport (populated at entry) ────────────────────────────────────
	w dns.ResponseWriter
	r *dns.Msg
	q dns.Question

	// ── Question (populated at entry) ─────────────────────────────────────
	qNameTrimmed         string
	originalQName        string
	originalQNameTrimmed string
	originalID           uint16
	doBit                bool

	// ── Client identity (populated at entry) ──────────────────────────────
	clientIP        string
	clientAddr      netip.Addr
	ecsAddr         netip.Addr
	ecsPrefix       netip.Prefix
	clientMAC       string
	ednsMAC         string
	clientName      string
	clientID        string
	clientNameLower string

	// ── Transport metadata (populated at entry) ────────────────────────────────────
	protocol  string
	sni       string
	sniLower  string
	path      string
	pathLower string
	localPort string

	// ── Populated by stage 1.5: identity resolution ───────────────────────
	sk          string
	clientGroup string

	// ── Populated by stages 1.6-1.8: overrides ────────────────────────────
	bypassGlobal   bool
	bypassPolicies bool
	spoofedAlias   string

	// ── Populated by stage 2: routing ─────────────────────────────────────
	route routingContext

	// ── Populated by stage 3: parental controls ───────────────────────────
	parentalForcedTTL   uint32
	parentalReason      string
	parentalCategory    string
	parentalMatchedApex string

	// ── Populated by stage 4: cache key derivation ────────────────────────
	cacheKey DNSCacheKey
	group    *UpstreamGroup
}

func (qc *queryCtx) qtypeStr() string {
	if s, ok := dns.TypeToString[qc.q.Qtype]; ok {
		return s
	}
	return "TYPE" + itoa64(int64(qc.q.Qtype))
}
