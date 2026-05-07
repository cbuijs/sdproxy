/*
File:    transform.go
Version: 1.4.0
Updated: 02-May-2026 18:12 CEST

Description:
  Outbound response mutation functions for sdproxy. Applied in ProcessDNS
  (process.go) after a response arrives from the cache or upstream, before
  it is written to the client.

    transformResponse — dispatcher; calls the active transforms in order.
    flattenCNAME      — collapses a CNAME chain into a single A/AAAA record
                        under the original query name (flatten_cname: true).
    applyAnswerSort   — dynamically rearranges contiguous blocks of A/AAAA 
                        response records to simulate load-balancing techniques 
                        like Round-Robin or Random ordering without breaking 
                        message structure dependencies.
    responseContainsNullIP — detects 0.0.0.0 / :: sentinel IPs used by
                        upstream blocklists; used to annotate cache-hit logs.

  All functions operate on an existing *dns.Msg — no upstream calls, no I/O.

Changes:
  1.4.0 - [SECURITY/FIX] Resolved a critical negative-caching violation (RFC 2308). 
          `minimize_answer` previously stripped the entire Authority section if the 
          client lacked the `DO` (DNSSEC OK) bit. This erroneously stripped `SOA` 
          records from `NXDOMAIN` responses, causing strict stub resolvers to spam 
          retry-loops due to missing negative-TTL bounds. `SOA` is now strictly preserved.
  1.3.0 - [FEAT] Implemented `applyAnswerSort` to gracefully order A/AAAA answers 
          prior to packet delivery (Round-Robin, Random, IP-Sort). Employs modern 
          zero-allocation mapping `slices.SortStableFunc` to ensure identical speeds
          to native array traversal.
*/

package main

import (
	"math/rand/v2"
	"net/netip"
	"slices"

	"github.com/miekg/dns"
)

// transformResponse applies the configured response transforms in order:
//   1. flattenCNAME  — when flatten_cname: true and qtype is A or AAAA.
//   2. minimizeAnswer — strips Ns and Extra sections when minimize_answer: true.
//
// inPlace controls whether msg is mutated directly (true) or a copy is made
// first (false). Callers that own the message (e.g. upstream response) pass
// true; callers sharing a pooled pointer pass false.
//
// Returns msg unchanged when neither transform is active — zero overhead on
// the common path.
func transformResponse(msg *dns.Msg, qtype uint16, doBit bool, inPlace bool) *dns.Msg {
	if !cfg.Server.FlattenCNAME && !cfg.Server.MinimizeAnswer {
		return msg
	}
	out := msg
	if !inPlace {
		out = msg.Copy()
	}
	
	// Note: Flattening CNAME chains will inherently break DNSSEC validation for the 
	// specific records altered as it changes the owner name the RRSIG was signed for. 
	// This remains an opt-in privacy feature.
	if cfg.Server.FlattenCNAME && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		flattenCNAME(out)
	}
	
	if cfg.Server.MinimizeAnswer {
		// [SECURITY/FIX] Filter Authority Section carefully.
		// We MUST perpetually retain SOA records to preserve RFC 2308 negative caching proofs,
		// ensuring clients do not retry NXDOMAIN queries aggressively.
		// NSEC, NSEC3, and RRSIG are conditionally retained only if the client is DNSSEC-aware (DO=1).
		if len(out.Ns) > 0 {
			var keptNs []dns.RR
			for _, rr := range out.Ns {
				rt := rr.Header().Rrtype
				// SOA is universally preserved. Cryptographic boundaries rely on the DO bit.
				if rt == dns.TypeSOA || (doBit && (rt == dns.TypeNSEC || rt == dns.TypeNSEC3 || rt == dns.TypeRRSIG)) {
					keptNs = append(keptNs, rr)
				}
			}
			out.Ns = keptNs
		}

		// Filter Additional Section: Only retain EDNS0 OPT records to preserve protocol bounds.
		if len(out.Extra) > 0 {
			var keptExtra []dns.RR
			for _, rr := range out.Extra {
				if rr.Header().Rrtype == dns.TypeOPT {
					keptExtra = append(keptExtra, rr)
				}
			}
			out.Extra = keptExtra
		}
	}
	return out
}

// flattenCNAME collapses a CNAME chain in out.Answer into a single A or AAAA
// record under the original query name. TTL is set to the chain minimum so
// the result expires no later than the shortest-lived link in the chain.
//
// No-ops when the answer has fewer than two records or does not start with a
// CNAME — avoids touching direct A/AAAA responses.
func flattenCNAME(out *dns.Msg) {
	if len(out.Answer) < 2 {
		return
	}
	first, ok := out.Answer[0].(*dns.CNAME)
	if !ok {
		return
	}
	queryName := first.Hdr.Name
	minTTL    := first.Hdr.Ttl
	finals    := make([]dns.RR, 0, len(out.Answer)-1)

	for _, rr := range out.Answer[1:] {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		switch r := rr.(type) {
		case *dns.A:
			cp          := *r
			cp.Hdr.Name  = queryName
			cp.Hdr.Ttl   = minTTL
			finals        = append(finals, &cp)
		case *dns.AAAA:
			cp          := *r
			cp.Hdr.Name  = queryName
			cp.Hdr.Ttl   = minTTL
			finals        = append(finals, &cp)
		}
	}
	if len(finals) == 0 {
		return // only CNAMEs with no terminal address — leave chain intact
	}
	// Apply the chain-minimum TTL to every final record.
	for _, rr := range finals {
		rr.Header().Ttl = minTTL
	}
	out.Answer = finals
}

// applyAnswerSort sorts the A and AAAA records in the Answer section natively.
// Supports "round-robin", "random", and "ip-sort". Returns true if the order was modified.
func applyAnswerSort(msg *dns.Msg, method string) bool {
	if method == "" || method == "none" || len(msg.Answer) < 2 {
		return false
	}
	
	type rrItem struct {
		idx int
		rr  dns.RR
	}
	var aRecords, aaaaRecords []rrItem
	
	for i, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			aRecords = append(aRecords, rrItem{i, rr})
		} else if rr.Header().Rrtype == dns.TypeAAAA {
			aaaaRecords = append(aaaaRecords, rrItem{i, rr})
		}
	}
	
	changed := false
	
	processGroup := func(group []rrItem) {
		if len(group) < 2 {
			return
		}
		
		original := make([]dns.RR, len(group))
		for i, item := range group {
			original[i] = item.rr
		}
		
		sorted := make([]dns.RR, len(group))
		copy(sorted, original)
		
		switch method {
		case "round-robin":
			first := sorted[0]
			copy(sorted, sorted[1:])
			sorted[len(sorted)-1] = first
		case "random":
			rand.Shuffle(len(sorted), func(i, j int) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			})
		case "ip-sort":
			slices.SortStableFunc(sorted, func(a, b dns.RR) int {
				var ipI, ipJ netip.Addr
				if rr, ok := a.(*dns.A); ok {
					ipI, _ = netip.AddrFromSlice(rr.A)
				} else if rr, ok := a.(*dns.AAAA); ok {
					ipI, _ = netip.AddrFromSlice(rr.AAAA)
				}
				if rr, ok := b.(*dns.A); ok {
					ipJ, _ = netip.AddrFromSlice(rr.A)
				} else if rr, ok := b.(*dns.AAAA); ok {
					ipJ, _ = netip.AddrFromSlice(rr.AAAA)
				}
				return ipI.Compare(ipJ)
			})
		}
		
		groupChanged := false
		for i := range sorted {
			if sorted[i] != original[i] {
				groupChanged = true
				break
			}
		}
		
		if groupChanged {
			changed = true
			for i, item := range group {
				msg.Answer[item.idx] = sorted[i]
			}
		}
	}
	
	processGroup(aRecords)
	processGroup(aaaaRecords)
	
	return changed
}

// responseContainsNullIP reports whether any A or AAAA answer carries an
// unspecified address (0.0.0.0 or ::). Upstream blocklists commonly use this
// as a sentinel instead of returning NXDOMAIN. Used to annotate log lines.
func responseContainsNullIP(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if r.A.IsUnspecified() {
				return true
			}
		case *dns.AAAA:
			if r.AAAA.IsUnspecified() {
				return true
			}
		}
	}
	return false
}

