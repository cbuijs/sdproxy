/*
File:    transform.go
Version: 1.14.0
Last Updated: 21-Oct-2026 14:53 CEST

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

  All functions operate on an existing *dns.Msg — no upstream calls, no I/O.

Changes:
  1.14.0 - [SECURITY/FIX] Cleared `out.Ns` in `flattenCNAME` when terminal A/AAAA
           records are collapsed onto `queryName`, preventing target-zone `NS`/`SOA`
           authority records from leaking alongside flattened answers.
  1.13.0 - [SECURITY/FIX] Cleared `out.AuthenticatedData = false` in `flattenCNAME`
           when terminal A/AAAA records are rewritten onto `queryName`, because
           collapsing the CNAME chain and omitting signatures means the resulting
           synthesized RRset is no longer cryptographically verifiable by the client.
  1.12.0 - [SECURITY/FIX] Bypassed `flattenCNAME` when `doBit` (`DO=1`) is set,
           and omitted `RRSIG` records when flattening for `DO=0` clients.
  1.11.0 - [SECURITY/FIX] Preserved matching `RRSIG` records (`r.TypeCovered == qtype`)
           in `flattenCNAME` when `doBit` (`DO=1`) is requested.
  1.10.0 - [SECURITY/FIX] Hardened `flattenCNAME` to verify that terminal A/AAAA
           records belong to the CNAME chain rooted at `queryName` before rewriting
           their owner names.
  1.9.0 - [SECURITY/FIX] Preserved non-CNAME/non-A/AAAA records during `flattenCNAME`.
  1.8.0 - [SECURITY/FIX] Fixed multi-hop CNAME flattening in `flattenCNAME`.
  1.7.0 - [CLEANUP] Pruned the unused `responseContainsNullIP` utility function organically. 
  1.6.0 - [PERF] Eradicated heap allocations in `applyAnswerSort` natively. 
  1.5.0 - [SECURITY/FIX] Hardened `flattenCNAME` to dynamically isolate and map the 
          originating CNAME record regardless of the upstream's Answer array sorting 
          order.
*/

package main

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// transformResponse applies the configured response transforms in order:
//   1. flattenCNAME  — when flatten_cname: true, qtype is A or AAAA, and DO=0.
//   2. minimizeAnswer — strips Ns and Extra sections when minimize_answer: true.
func transformResponse(msg *dns.Msg, qtype uint16, doBit bool, inPlace bool) *dns.Msg {
	if !cfg.Server.FlattenCNAME && !cfg.Server.MinimizeAnswer {
		return msg
	}
	out := msg
	if !inPlace {
		out = msg.Copy()
	}

	// [SECURITY/FIX 1.12.0] Never flatten CNAME chains when the client requested DNSSEC (DO=1).
	// Rewriting the owner name of terminal A/AAAA records breaks cryptographic RRSIG validation.
	if cfg.Server.FlattenCNAME && !doBit && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		flattenCNAME(out, qtype)
	}

	if cfg.Server.MinimizeAnswer {
		if len(out.Ns) > 0 {
			needFilter := false
			for _, rr := range out.Ns {
				rt := rr.Header().Rrtype
				if !(rt == dns.TypeSOA || (doBit && (rt == dns.TypeNSEC || rt == dns.TypeNSEC3 || rt == dns.TypeRRSIG))) {
					needFilter = true
					break
				}
			}
			if needFilter {
				keptNs := make([]dns.RR, 0, len(out.Ns))
				for _, rr := range out.Ns {
					rt := rr.Header().Rrtype
					if rt == dns.TypeSOA || (doBit && (rt == dns.TypeNSEC || rt == dns.TypeNSEC3 || rt == dns.TypeRRSIG)) {
						keptNs = append(keptNs, rr)
					}
				}
				out.Ns = keptNs
			}
		}

		if len(out.Extra) > 0 {
			needFilter := false
			for _, rr := range out.Extra {
				if rr.Header().Rrtype != dns.TypeOPT {
					needFilter = true
					break
				}
			}
			if needFilter {
				keptExtra := make([]dns.RR, 0, len(out.Extra))
				for _, rr := range out.Extra {
					if rr.Header().Rrtype == dns.TypeOPT {
						keptExtra = append(keptExtra, rr)
					}
				}
				out.Extra = keptExtra
			}
		}
	}
	return out
}

// flattenCNAME collapses a CNAME chain in out.Answer into terminal A or AAAA
// records under the original query name. TTL is set to the chain minimum so
// the result expires no later than the shortest-lived link in the chain.
func flattenCNAME(out *dns.Msg, qtype uint16) {
	if len(out.Answer) < 2 {
		return
	}

	var cname *dns.CNAME

	queryName := ""
	if len(out.Question) > 0 {
		queryName = out.Question[0].Name
	}

	for _, rr := range out.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			if queryName == "" || strings.EqualFold(c.Hdr.Name, queryName) {
				cname = c
				if queryName == "" {
					queryName = c.Hdr.Name
				}
				break
			}
		}
	}

	if cname == nil {
		return
	}

	// Build the valid CNAME chain rooted at queryName so only records belonging
	// to the chain contribute to minTTL and get flattened onto queryName.
	var chainStack [64]string
	chainNames := chainStack[:0]
	chainNames = append(chainNames, strings.ToLower(queryName))

	minTTL := cname.Hdr.Ttl
	for depth := 0; depth < 16; depth++ {
		added := false
		for _, rr := range out.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				owner := strings.ToLower(c.Hdr.Name)
				if isValidBailiwickName(chainNames, owner) {
					if c.Hdr.Ttl < minTTL {
						minTTL = c.Hdr.Ttl
					}
					target := strings.ToLower(c.Target)
					if !isValidBailiwickName(chainNames, target) && len(chainNames) < 64 {
						chainNames = append(chainNames, target)
						added = true
					}
				}
			}
		}
		if !added {
			break
		}
	}

	finals := make([]dns.RR, 0, len(out.Answer)-1)
	hasTerminal := false

	for _, rr := range out.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA && isValidBailiwickName(chainNames, strings.ToLower(r.Hdr.Name)) {
				if r.Hdr.Ttl < minTTL {
					minTTL = r.Hdr.Ttl
				}
				cp := *r
				cp.Hdr.Name = queryName
				finals = append(finals, &cp)
				hasTerminal = true
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA && isValidBailiwickName(chainNames, strings.ToLower(r.Hdr.Name)) {
				if r.Hdr.Ttl < minTTL {
					minTTL = r.Hdr.Ttl
				}
				cp := *r
				cp.Hdr.Name = queryName
				finals = append(finals, &cp)
				hasTerminal = true
			}
		}
	}

	if !hasTerminal {
		return
	}

	for _, rr := range finals {
		rr.Header().Ttl = minTTL
	}
	out.AuthenticatedData = false
	out.Answer = finals
	out.Ns = nil
}

// applyAnswerSort sorts the A and AAAA records in the Answer section natively.
func applyAnswerSort(msg *dns.Msg, method string) bool {
	if method == "" || method == "none" || len(msg.Answer) < 2 {
		return false
	}

	type rrItem struct {
		idx int
		rr  dns.RR
	}

	var aRecordsBuf [16]rrItem
	var aaaaRecordsBuf [16]rrItem
	aRecords := aRecordsBuf[:0]
	aaaaRecords := aaaaRecordsBuf[:0]

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

		var origBuf [16]dns.RR
		var original []dns.RR
		if len(group) <= 16 {
			original = origBuf[:len(group)]
		} else {
			original = make([]dns.RR, len(group))
		}

		for i, item := range group {
			original[i] = item.rr
		}

		var sortBuf [16]dns.RR
		var sorted []dns.RR
		if len(group) <= 16 {
			sorted = sortBuf[:len(group)]
		} else {
			sorted = make([]dns.RR, len(group))
		}
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

