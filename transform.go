/*
File:    transform.go
Version: 1.17.0
Last Updated: 05-Nov-2026 14:36 CET

Description:
  Outbound response mutation functions for sdproxy. Applied in ProcessDNS
  (process.go) after a response arrives from the cache or upstream, before
  it is written to the client.

    transformResponse — dispatcher; calls the active transforms in order.
    flattenCNAME      — collapses a CNAME/DNAME chain into a single A/AAAA record
                        under the original query name (flatten_cname: true).
    applyAnswerSort   — dynamically rearranges contiguous blocks of A/AAAA 
                        response records to simulate load-balancing techniques 
                        like Round-Robin, Random, IP-Sort, or Proximity ordering
                        without breaking message structure dependencies.

  All functions operate on an existing *dns.Msg — no upstream calls, no I/O.

Changes:
  1.17.0 - [FIX] Normalized IPv4-mapped IPv6 addresses (`ip.Unmap()`) before
           extracting 16-byte slices in `minProximityV6` and before comparing
           addresses in `ip-sort` within `applyAnswerSort`.
  1.16.0 - [FEAT] Added `"proximity"` sorting to `applyAnswerSort`, ordering A and
           AAAA answers from closest to farthest in the 32-bit/128-bit address space
           relative to the local listener and outbound query source addresses
           (`proximityRefV4`, `proximityRefV6`, plus the per-request local socket IP).
  1.15.0 - [SECURITY/FIX] Extended `flattenCNAME` to recognize RFC 6672 `DNAME`
           records when walking the alias chain and computing `minTTL`.
  1.14.0 - [SECURITY/FIX] Cleared `out.Ns` in `flattenCNAME` when terminal A/AAAA
           records are collapsed onto `queryName`, preventing target-zone `NS`/`SOA`
           authority records from leaking alongside flattened answers.
  1.13.0 - [SECURITY/FIX] Cleared `out.AuthenticatedData = false` in `flattenCNAME`
           when terminal A/AAAA records are rewritten onto `queryName`.
  1.12.0 - [SECURITY/FIX] Bypassed `flattenCNAME` when `doBit` (`DO=1`) is set,
           and omitted `RRSIG` records when flattening for `DO=0` clients.
  1.11.0 - [SECURITY/FIX] Preserved matching `RRSIG` records (`r.TypeCovered == qtype`)
           in `flattenCNAME` when `doBit` (`DO=1`) is requested.
  1.10.0 - [SECURITY/FIX] Hardened `flattenCNAME` to verify that terminal A/AAAA
           records belong to the CNAME chain rooted at `queryName` before rewriting
           their owner names.
  1.9.0  - [SECURITY/FIX] Preserved non-CNAME/non-A/AAAA records during `flattenCNAME`.
  1.8.0  - [SECURITY/FIX] Fixed multi-hop CNAME flattening in `flattenCNAME`.
*/

package main

import (
	"encoding/binary"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// transformResponse applies the configured response transforms in order:
//   1. flattenCNAME  — when flatten_cname: true, qtype is A or AAAA, and DO=0.
//   2. minimizeAnswer — strips Ns and Additional sections when minimize_answer: true.
func transformResponse(msg *dns.Msg, qtype uint16, doBit bool, inPlace bool) *dns.Msg {
	if !cfg.Server.FlattenCNAME && !cfg.Server.MinimizeAnswer {
		return msg
	}
	out := msg
	if !inPlace {
		out = msg.Copy()
	}

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

// flattenCNAME collapses a CNAME/DNAME chain in out.Answer into terminal A or AAAA
// records under the original query name. TTL is set to the chain minimum so
// the result expires no later than the shortest-lived link in the chain.
func flattenCNAME(out *dns.Msg, qtype uint16) {
	if len(out.Answer) < 2 {
		return
	}

	var firstAliasTTL uint32
	hasAlias := false

	queryName := ""
	if len(out.Question) > 0 {
		queryName = out.Question[0].Name
	}
	qLower := strings.ToLower(queryName)

	for _, rr := range out.Answer {
		switch r := rr.(type) {
		case *dns.CNAME:
			if queryName == "" || strings.EqualFold(r.Hdr.Name, queryName) {
				firstAliasTTL = r.Hdr.Ttl
				hasAlias = true
				if queryName == "" {
					queryName = r.Hdr.Name
					qLower = strings.ToLower(queryName)
				}
			}
		case *dns.DNAME:
			ownerLower := strings.ToLower(r.Hdr.Name)
			if qLower != "" && hasDotSuffix(qLower, ownerLower) {
				firstAliasTTL = r.Hdr.Ttl
				hasAlias = true
			}
		}
		if hasAlias {
			break
		}
	}

	if !hasAlias || queryName == "" {
		return
	}

	var chainStack [64]string
	chainNames := chainStack[:0]
	chainNames = append(chainNames, qLower)

	minTTL := firstAliasTTL
	for depth := 0; depth < 16; depth++ {
		added := false
		for _, rr := range out.Answer {
			owner := strings.ToLower(rr.Header().Name)
			switch r := rr.(type) {
			case *dns.CNAME:
				if isValidBailiwickName(chainNames, owner) {
					if r.Hdr.Ttl < minTTL {
						minTTL = r.Hdr.Ttl
					}
					target := strings.ToLower(r.Target)
					if !isValidBailiwickName(chainNames, target) && len(chainNames) < 64 {
						chainNames = append(chainNames, target)
						added = true
					}
				}
			case *dns.DNAME:
				for _, vn := range chainNames {
					if hasDotSuffix(vn, owner) {
						if r.Hdr.Ttl < minTTL {
							minTTL = r.Hdr.Ttl
						}
						if !isValidBailiwickName(chainNames, owner) && len(chainNames) < 64 {
							chainNames = append(chainNames, owner)
							added = true
						}
						prefix := vn[:len(vn)-len(owner)]
						synthTarget := prefix + strings.ToLower(r.Target)
						if len(synthTarget) <= 254 && !isValidBailiwickName(chainNames, synthTarget) && len(chainNames) < 64 {
							chainNames = append(chainNames, synthTarget)
							added = true
						}
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

// ---------------------------------------------------------------------------
// Address-Space Proximity Helpers (32-bit IPv4 & 128-bit IPv6)
// ---------------------------------------------------------------------------

func absDiff32(a, b uint32) uint32 {
	if a >= b {
		return a - b
	}
	return b - a
}

func absDiff128(a, b [2]uint64) [2]uint64 {
	if a[0] > b[0] || (a[0] == b[0] && a[1] >= b[1]) {
		lo, borrow := bits.Sub64(a[1], b[1], 0)
		hi, _ := bits.Sub64(a[0], b[0], borrow)
		return [2]uint64{hi, lo}
	}
	lo, borrow := bits.Sub64(b[1], a[1], 0)
	hi, _ := bits.Sub64(b[0], a[0], borrow)
	return [2]uint64{hi, lo}
}

func cmpU128(a, b [2]uint64) int {
	if a[0] < b[0] {
		return -1
	}
	if a[0] > b[0] {
		return 1
	}
	if a[1] < b[1] {
		return -1
	}
	if a[1] > b[1] {
		return 1
	}
	return 0
}

func minProximityV4(ip netip.Addr, localV4 uint32, hasLocalV4 bool) (uint32, uint32) {
	if !ip.IsValid() {
		return ^uint32(0), ^uint32(0)
	}
	b := ip.Unmap().As4()
	val := binary.BigEndian.Uint32(b[:])
	minDist := ^uint32(0)

	if hasLocalV4 {
		minDist = absDiff32(val, localV4)
	}
	for _, ref := range proximityRefV4 {
		if d := absDiff32(val, ref); d < minDist {
			minDist = d
		}
	}
	return minDist, val
}

func minProximityV6(ip netip.Addr, localV6 [2]uint64, hasLocalV6 bool) ([2]uint64, [2]uint64) {
	maxU128 := [2]uint64{^uint64(0), ^uint64(0)}
	if !ip.IsValid() {
		return maxU128, maxU128
	}
	b := ip.As16()
	val := [2]uint64{
		binary.BigEndian.Uint64(b[0:8]),
		binary.BigEndian.Uint64(b[8:16]),
	}
	minDist := maxU128

	if hasLocalV6 {
		minDist = absDiff128(val, localV6)
	}
	for _, ref := range proximityRefV6 {
		if d := absDiff128(val, ref); cmpU128(d, minDist) < 0 {
			minDist = d
		}
	}
	return minDist, val
}

// applyAnswerSort sorts the A and AAAA records in the Answer section natively.
func applyAnswerSort(msg *dns.Msg, method string, localAddrs ...netip.Addr) bool {
	if method == "" || method == "none" || len(msg.Answer) < 2 {
		return false
	}

	var (
		hasLocalV4 bool
		localV4    uint32
		hasLocalV6 bool
		localV6    [2]uint64
	)
	if method == "proximity" && len(localAddrs) > 0 && localAddrs[0].IsValid() {
		la := localAddrs[0].Unmap()
		if !la.IsUnspecified() {
			if la.Is4() {
				b := la.As4()
				localV4 = binary.BigEndian.Uint32(b[:])
				hasLocalV4 = true
			} else if la.Is6() {
				b := la.As16()
				localV6 = [2]uint64{
					binary.BigEndian.Uint64(b[0:8]),
					binary.BigEndian.Uint64(b[8:16]),
				}
				hasLocalV6 = true
			}
		}
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
					if addr, ok := netip.AddrFromSlice(rr.A); ok {
						ipI = addr.Unmap()
					}
				} else if rr, ok := a.(*dns.AAAA); ok {
					ipI, _ = netip.AddrFromSlice(rr.AAAA)
				}
				if rr, ok := b.(*dns.A); ok {
					if addr, ok := netip.AddrFromSlice(rr.A); ok {
						ipJ = addr.Unmap()
					}
				} else if rr, ok := b.(*dns.AAAA); ok {
					ipJ, _ = netip.AddrFromSlice(rr.AAAA)
				}
				return ipI.Compare(ipJ)
			})
		case "proximity":
			slices.SortStableFunc(sorted, func(a, b dns.RR) int {
				if rrA, okA := a.(*dns.A); okA {
					if rrB, okB := b.(*dns.A); okB {
						ipA, _ := netip.AddrFromSlice(rrA.A)
						ipB, _ := netip.AddrFromSlice(rrB.A)
						distA, valA := minProximityV4(ipA, localV4, hasLocalV4)
						distB, valB := minProximityV4(ipB, localV4, hasLocalV4)
						if distA < distB {
							return -1
						}
						if distA > distB {
							return 1
						}
						if valA < valB {
							return -1
						}
						if valA > valB {
							return 1
						}
						return 0
					}
				}
				if rrA, okA := a.(*dns.AAAA); okA {
					if rrB, okB := b.(*dns.AAAA); okB {
						ipA, _ := netip.AddrFromSlice(rrA.AAAA)
						ipB, _ := netip.AddrFromSlice(rrB.AAAA)
						distA, valA := minProximityV6(ipA, localV6, hasLocalV6)
						distB, valB := minProximityV6(ipB, localV6, hasLocalV6)
						if c := cmpU128(distA, distB); c != 0 {
							return c
						}
						return cmpU128(valA, valB)
					}
				}
				return 0
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
