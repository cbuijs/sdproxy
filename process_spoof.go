/*
File:    process_spoof.go
Version: 1.42.0
Last Updated: 19-Nov-2026 17:15 CET

Description:
  Spoofed Records (RRs) processor for sdproxy.
  Intercepts explicit A, AAAA, and CNAME queries matching global or 
  per-group overrides natively (both exact domains and `/pattern/` regexes).
  Capable of recursive target resolutions by seamlessly wrapping the
  ResponseWriter and dynamically traversing the standard pipeline.

Changes:
  1.42.0 - [SECURITY/FIX] Derived `soaTTL` in `spoofResponseWriter.WriteMsg` via
           `extractAuthorityTTL(res.Ns)` so non-SOA authority records and
           0-second SOA `Minttl` values are handled identically to `CacheSet`
           and `applyRcodeOnlyWireTTL`.
  1.41.0 - [SECURITY/FIX] Preserved the configured `rcode_ttl` / `rcode_min_ttl` /
           `negative_ttl` floor on synthesized negative SOA records inside
           `spoofResponseWriter.WriteMsg` while still capping the final SOA
           wire TTL by `minAliasTTL` (the resolved CNAME/DNAME alias chain TTL)
           and `capTTL` (`parentalForcedTTL`), preventing a 0-second or
           sub-`rcode_min_ttl` target SOA from defeating `rcode_min_ttl`.
  1.40.0 - [SECURITY/FIX] Capped negative SOA wire TTLs in
           `spoofResponseWriter.WriteMsg` by `minTTL` (and `minAliasTTL`) after
           `applyRcodeOnlyWireTTL(res)` so spoofed CNAME negative responses
           never exceed a `parentalForcedTTL` cap or a shorter intermediate
           alias TTL.
  1.39.0 - [SECURITY/FIX] Clamped terminal record TTLs in `spoofResponseWriter.WriteMsg`
           to the minimum alias TTL (`minAliasTTL`) across the resolved CNAME/DNAME
           chain (`walkBailiwickChain`), matching `flattenCNAME` (`transform.go`).
  1.38.0 - [FIX] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.42.0) to
           positive spoofed `CNAME`, `A`, and `AAAA` responses in
           `handleSpoofedRecords`.
  1.37.0 - [SECURITY/FIX] Added cross-hop cycle tracking across `ProcessDNS`
           Step 1.6 iterations by recording the existing `srw.originalQname`
           and `srw.cnameTarget` in `visited` when `handleSpoofedRecords` is
           invoked on an already-wrapped `*spoofResponseWriter`.
  1.36.0 - [FEAT] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.36.0) on
           RCODE-only (`NODATA` / `NXDOMAIN`) responses in `spoofResponseWriter.WriteMsg`
           and `handleSpoofedRecords`.
  1.35.0 - [REFACTOR/PERF] Switched `spoofResponseWriter.WriteMsg` to use the
           shared `walkBailiwickChain` helper (`cache_rw.go` 1.35.0).
  1.34.0 - [SECURITY/FIX] Prevented `handleSpoofedRecords` from mutating `q.Name`
           and `qNameTrimmed` on `CNAME` queries when `hop > 0` in a multi-hop
           `rrs:` CNAME chain.
  1.33.0 - [SECURITY/FIX] Resolved multi-hop `rrs:` CNAME chains (up to 8 hops,
           with cycle detection) in `handleSpoofedRecords`.
*/

package main

import (
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

type spoofResponseWriter struct {
	dns.ResponseWriter
	originalQname string
	cnameTarget   string
	protocol      string
	maxUDPSize    int
	qtype         uint16
}

func (w *spoofResponseWriter) WriteMsg(res *dns.Msg) error {
	targetFqdn := strings.ToLower(dns.Fqdn(w.cnameTarget))

	var chainStack [64]string
	chainNames, minAliasTTL, _ := walkBailiwickChain(res.Answer, targetFqdn, 16, &chainStack)

	var finals []dns.RR
	var cnames []dns.RR
	hasTerminal := false

	for _, rr := range res.Answer {
		rt := rr.Header().Rrtype
		ownerLower := strings.ToLower(rr.Header().Name)
		if !isValidBailiwickName(chainNames, ownerLower) {
			continue
		}
		if rt == dns.TypeCNAME {
			cnames = append(cnames, dns.Copy(rr))
		} else if rt == dns.TypeDNAME || rt == dns.TypeRRSIG {
			continue
		} else if rt == w.qtype || w.qtype == dns.TypeANY {
			cloned := dns.Copy(rr)
			cloned.Header().Name = w.originalQname
			if minAliasTTL != ^uint32(0) && minAliasTTL > 0 && cloned.Header().Ttl > minAliasTTL {
				cloned.Header().Ttl = minAliasTTL
			}
			finals = append(finals, cloned)
			hasTerminal = true
		}
	}

	res.AuthenticatedData = false

	if hasTerminal {
		res.Answer = finals
		res.Ns = nil
	} else if len(cnames) > 0 && w.qtype != dns.TypeRRSIG {
		for i, rr := range cnames {
			if cname, ok := rr.(*dns.CNAME); ok {
				if strings.EqualFold(dns.Fqdn(cname.Header().Name), targetFqdn) {
					cname.Header().Name = w.originalQname
					cnames[i] = cname
					break
				}
			}
		}
		res.Answer = cnames
		res.Ns = nil
	} else {
		res.Answer = nil
	}

	if len(res.Question) > 0 {
		qCopy := make([]dns.Question, len(res.Question))
		copy(qCopy, res.Question)
		qCopy[0].Name = w.originalQname
		res.Question = qCopy
	}

	if len(res.Extra) > 0 {
		var keptExtra []dns.RR
		for _, rr := range res.Extra {
			if rr.Header().Rrtype == dns.TypeOPT {
				keptExtra = append(keptExtra, rr)
			}
		}
		res.Extra = keptExtra
	}

	if len(res.Answer) == 0 && !res.Truncated {
		soaTTL, hasSOATTL := extractAuthorityTTL(res.Ns)
		if !hasSOATTL || soaTTL == 0 {
			soaTTL = syntheticTTL
		}
		if res.Rcode == dns.RcodeNameError || res.Rcode == dns.RcodeSuccess {
			SetNegativeSOA(res, w.originalQname, soaTTL)
			applyRcodeOnlyWireTTL(res)
			capTTL := ^uint32(0)
			if minAliasTTL != ^uint32(0) && minAliasTTL > 0 {
				capTTL = minAliasTTL
			}
			if hasSOATTL && soaTTL > 0 && soaTTL < capTTL {
				minFloor, _ := rcodeTTLBounds(res.Rcode)
				if !isHardRcodeTTLOverride(res.Rcode) && soaTTL >= minFloor {
					capTTL = soaTTL
				}
			}
			if capTTL != ^uint32(0) {
				for _, rr := range res.Ns {
					if rr.Header().Ttl > capTTL {
						rr.Header().Ttl = capTTL
					}
					if soa, ok := rr.(*dns.SOA); ok && soa.Minttl > capTTL {
						soa.Minttl = capTTL
					}
				}
			}
		} else {
			res.Ns = nil
		}
	}

	if w.protocol == "UDP" && !res.Truncated && w.maxUDPSize > 0 && res.Len() > w.maxUDPSize {
		res.Truncated = true
		res.Authoritative = false
		res.Answer = nil
		res.Ns = nil
	}

	return w.ResponseWriter.WriteMsg(res)
}

func lookupSpoofRecord(domain, clientGroup string, bypassGlobal bool) (spoofRecord, bool) {
	if clientGroup != "" {
		if gm := groupRRs[clientGroup]; gm != nil {
			if rec, ok := gm[domain]; ok {
				return rec, true
			}
		}
		if gr := groupRRRegexes[clientGroup]; len(gr) > 0 {
			for i := range gr {
				if gr[i].re.MatchString(domain) {
					return gr[i].rec, true
				}
			}
		}
	}

	if !bypassGlobal {
		if len(globalRRs) > 0 {
			if rec, ok := globalRRs[domain]; ok {
				return rec, true
			}
		}
		if len(globalRRRegexes) > 0 {
			for i := range globalRRRegexes {
				if globalRRRegexes[i].re.MatchString(domain) {
					return globalRRRegexes[i].rec, true
				}
			}
		}
	}
	return spoofRecord{}, false
}

// handleSpoofedRecords evaluates incoming queries against the RRs maps and regexes dynamically.
// Precedence: group exact > group regex > global exact > global regex.
func handleSpoofedRecords(w *dns.ResponseWriter, r *dns.Msg, q *dns.Question, qNameTrimmed *string, clientGroup, clientIP, clientID, protocol, protoEndpoint string, bypassGlobal bool) (bool, string) {
	record, found := lookupSpoofRecord(*qNameTrimmed, clientGroup, bypassGlobal)
	if !found || (record.CNAME == "" && len(record.IPs) == 0) {
		return false, ""
	}

	originalQname := q.Name
	var lastAlias string
	var visited [10]string
	visitedCount := 0

	if srw, ok := (*w).(*spoofResponseWriter); ok && srw.originalQname != "" {
		originalQname = srw.originalQname
		if origClean := lowerTrimDot(srw.originalQname); origClean != "" {
			visited[visitedCount] = origClean
			visitedCount++
		}
		if srw.cnameTarget != "" && (visitedCount == 0 || visited[visitedCount-1] != srw.cnameTarget) {
			visited[visitedCount] = srw.cnameTarget
			visitedCount++
		}
	}

	for hop := 0; hop < 8 && record.CNAME != ""; hop++ {
		targetClean := lowerTrimDot(record.CNAME)
		if targetClean == "" || strings.EqualFold(*qNameTrimmed, targetClean) || !isValidQNAME(targetClean, dns.TypeA) {
			break
		}
		cycle := false
		for i := 0; i < visitedCount; i++ {
			if visited[i] == targetClean {
				cycle = true
				break
			}
		}
		if cycle {
			break
		}
		if visitedCount < len(visited) {
			visited[visitedCount] = *qNameTrimmed
			visitedCount++
		}

		if q.Qtype == dns.TypeCNAME {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{}
			resp.SetReply(r)
			resp.Authoritative = true
			if len(resp.Question) > 0 {
				qCopy := make([]dns.Question, len(resp.Question))
				copy(qCopy, resp.Question)
				qCopy[0].Name = originalQname
				resp.Question = qCopy
			}
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: originalQname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: syntheticTTL},
				Target: dns.Fqdn(targetClean),
			})

			applyRcodeOnlyWireTTL(resp)
			IncrReturnCode(resp.Rcode, false)
			enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

			(*w).WriteMsg(resp)
			msgPool.Put(resp)
			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQname, "CNAME", "NOERROR", "RRs CNAME ("+targetClean+")", false)
				} else {
					log.Printf("[DNS] [%s] %s -> %s CNAME | [SPOOFED CNAME] | NOERROR", protocol, clientID, originalQname)
				}
			}
			return true, ""
		}

		q.Name = dns.Fqdn(targetClean)
		*qNameTrimmed = targetClean
		lastAlias = targetClean

		nextRec, nextFound := lookupSpoofRecord(targetClean, clientGroup, bypassGlobal)
		if !nextFound || (nextRec.CNAME == "" && len(nextRec.IPs) == 0) {
			record = spoofRecord{}
			break
		}
		record = nextRec
	}

	if lastAlias != "" {
		qSlice := make([]dns.Question, len(r.Question))
		copy(qSlice, r.Question)
		qSlice[0] = *q
		r.Question = qSlice

		if len(record.IPs) == 0 {
			if srw, ok := (*w).(*spoofResponseWriter); ok {
				srw.cnameTarget = lastAlias
				return false, lastAlias
			}

			maxUDP := 512
			if opt := r.IsEdns0(); opt != nil {
				if int(opt.UDPSize()) >= 512 {
					maxUDP = int(opt.UDPSize())
				}
			}
			if maxUDP > 1232 {
				maxUDP = 1232
			}

			*w = &spoofResponseWriter{
				ResponseWriter: *w,
				originalQname:  originalQname,
				cnameTarget:    lastAlias,
				protocol:       protocol,
				maxUDPSize:     maxUDP,
				qtype:          q.Qtype,
			}

			return false, lastAlias
		}
	}

	if len(record.IPs) == 0 {
		return false, lastAlias
	}

	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		IncrPolicyBlock()

		resp := msgPool.Get().(*dns.Msg)
		*resp = dns.Msg{}
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess

		SetNegativeSOA(resp, originalQname, syntheticTTL)
		applyRcodeOnlyWireTTL(resp)
		if lastAlias != "" {
			qCopy := make([]dns.Question, len(resp.Question))
			copy(qCopy, resp.Question)
			qCopy[0].Name = originalQname
			resp.Question = qCopy
		}
		IncrReturnCode(resp.Rcode, false)
		enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

		(*w).WriteMsg(resp)
		msgPool.Put(resp)

		if logQueries {
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, originalQname, qtypeName(q.Qtype), "NOERROR (NODATA)", "RRs", false)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | [SPOOFED] Unsupported Type | NODATA", protocol, clientID, originalQname, qtypeName(q.Qtype))
			}
		}
		return true, ""
	}

	resp := msgPool.Get().(*dns.Msg)
	*resp = dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = true
	if lastAlias != "" && len(resp.Question) > 0 {
		qCopy := make([]dns.Question, len(resp.Question))
		copy(qCopy, resp.Question)
		qCopy[0].Name = originalQname
		resp.Question = qCopy
	}

	hasAnswers := false
	isNullIP := false
	for _, ip := range record.IPs {
		if q.Qtype == dns.TypeA && ip.Is4() {
			if ip.IsUnspecified() {
				isNullIP = true
			}
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: originalQname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: syntheticTTL},
				A:   ip.AsSlice(),
			})
			hasAnswers = true
		} else if q.Qtype == dns.TypeAAAA && ip.Is6() {
			if ip.IsUnspecified() {
				isNullIP = true
			}
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: originalQname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: syntheticTTL},
				AAAA: ip.AsSlice(),
			})
			hasAnswers = true
		}
	}

	if !hasAnswers {
		SetNegativeSOA(resp, originalQname, syntheticTTL)
	}
	applyRcodeOnlyWireTTL(resp)

	if isNullIP {
		IncrPolicyBlock()
		RecordBlockEvent(clientIP, lowerTrimDot(originalQname), "RRs (NULL-IP)")
	}
	IncrReturnCode(resp.Rcode, isNullIP)
	if resp.Rcode == dns.RcodeNameError {
		IncrNXDomain(lowerTrimDot(originalQname))
	}
	enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

	(*w).WriteMsg(resp)
	msgPool.Put(resp)

	if logQueries {
		if logSimple {
			rcStr := "NOERROR"
			if !hasAnswers {
				rcStr = "NOERROR (NODATA)"
			} else if isNullIP {
				rcStr = "NOERROR (NULL-IP)"
			}
			logQuerySimple(protoEndpoint, clientIP, originalQname, qtypeName(q.Qtype), rcStr, "RRs IP", false)
		} else {
			rcStr := "NOERROR"
			if isNullIP {
				rcStr = "NOERROR (NULL-IP)"
			}
			log.Printf("[DNS] [%s] %s -> %s %s | [SPOOFED IP] | %s", protocol, clientID, originalQname, qtypeName(q.Qtype), rcStr)
		}
	}

	return true, ""
}
