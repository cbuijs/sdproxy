/*
File:    process_spoof.go
Version: 1.34.0
Last Updated: 10-Nov-2026 15:10 CET

Description:
  Spoofed Records (RRs) processor for sdproxy.
  Intercepts explicit A, AAAA, and CNAME queries matching global or 
  per-group overrides natively (both exact domains and `/pattern/` regexes).
  Capable of recursive target resolutions by seamlessly wrapping the
  ResponseWriter and dynamically traversing the standard pipeline.

Changes:
  1.34.0 - [SECURITY/FIX] Prevented `handleSpoofedRecords` from mutating `q.Name`
           and `qNameTrimmed` on `CNAME` queries when `hop > 0` in a multi-hop
           `rrs:` CNAME chain. Previously, a `CNAME` query matching a multi-hop
           chain Returned `CNAME -> target1` at `hop == 0`, whereas if a chain
           had already advanced past `hop == 0` it rewrote `q.Name` and leaked
           the query downstream.
  1.33.0 - [SECURITY/FIX] Resolved multi-hop `rrs:` CNAME chains (up to 8 hops,
           with cycle detection) in `handleSpoofedRecords` so a per-group or
           global CNAME pointing to another `rrs:` entry (CNAME or static IP)
           resolves completely in a single pass.
  1.32.0 - [SECURITY/FIX] Recorded `IncrNXDomain` when a spoofed IP record
           resolves to `NXDOMAIN` (or when a direct spoofed response carries
           `RcodeNameError`) and validated that `targetClean` in a spoofed
           CNAME record is a syntactically valid DNS QNAME (`isValidQNAME`)
           before rewriting the query pipeline.
  1.31.0 - [SECURITY/FIX] Updated `handleSpoofedRecords` so chained CNAME
           rewrites update an existing `*spoofResponseWriter`'s `cnameTarget`
           in place instead of nesting a second `spoofResponseWriter`.
  1.30.0 - [SECURITY/FIX] Extended `spoofResponseWriter.WriteMsg` bailiwick chain
           walking to recognize RFC 6672 `DNAME` records alongside `CNAME` records.
  1.29.0 - [SECURITY/FIX] Replaced `PreserveEDNS0` with `enforceUDPDefenses` and
           recorded `IncrReturnCode`, `IncrPolicyBlock`, and `RecordBlockEvent`
           when a spoofed IP record resolves to a NULL-IP (`0.0.0.0` / `::`) or
           returns a direct CNAME / NODATA response.
  1.28.0 - [SECURITY/FIX] Logged `originalQname` instead of the mutated `q.Name`
           when a second `handleSpoofedRecords` pass intercepts a query after a
           route `client_name` override.
  1.27.0 - [SECURITY/FIX] Guarded against self-referential CNAME aliases in
           `handleSpoofedRecords` (`strings.EqualFold(*qNameTrimmed, targetClean)`).
  1.26.0 - [FEAT] Added `clientIP` and `protoEndpoint` to `handleSpoofedRecords`
           and emitted concise query/answer logs via `logQuerySimple` when
           `logSimple` is enabled.
  1.25.0 - [SECURITY/FIX] Preserved OPT (EDNS0) records in `res.Extra` and stripped
           stale glue records in `spoofResponseWriter.WriteMsg`.
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
	chainNames := chainStack[:0]
	chainNames = append(chainNames, targetFqdn)

	for depth := 0; depth < 16; depth++ {
		added := false
		for _, rr := range res.Answer {
			owner := strings.ToLower(rr.Header().Name)
			switch r := rr.(type) {
			case *dns.CNAME:
				if isValidBailiwickName(chainNames, owner) {
					t := strings.ToLower(r.Target)
					if !isValidBailiwickName(chainNames, t) && len(chainNames) < 64 {
						chainNames = append(chainNames, t)
						added = true
					}
				}
			case *dns.DNAME:
				for _, vn := range chainNames {
					if hasDotSuffix(vn, owner) {
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
		var minTTL uint32 = syntheticTTL
		for _, rr := range res.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				if soa.Hdr.Ttl > 0 && soa.Hdr.Ttl < minTTL {
					minTTL = soa.Hdr.Ttl
				}
				if soa.Minttl > 0 && soa.Minttl < minTTL {
					minTTL = soa.Minttl
				}
			}
		}
		if res.Rcode == dns.RcodeNameError || res.Rcode == dns.RcodeSuccess {
			SetNegativeSOA(res, w.originalQname, minTTL)
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
	if srw, ok := (*w).(*spoofResponseWriter); ok && srw.originalQname != "" {
		originalQname = srw.originalQname
	}

	var lastAlias string
	var visited [8]string
	visitedCount := 0

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
		visited[visitedCount] = *qNameTrimmed
		visitedCount++

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
