/*
File:    process_spoof.go
Version: 1.24.0
Last Updated: 23-Oct-2026 14:10 CEST

Description:
  Spoofed Records (RRs) processor for sdproxy.
  Intercepts explicit A, AAAA, and CNAME queries matching global or 
  per-group overrides natively (both exact domains and `/pattern/` regexes).
  Capable of recursive target resolutions by seamlessly wrapping the
  ResponseWriter and dynamically traversing the standard pipeline.

Changes:
  1.24.0 - [FEAT] Added regular expression matching (`groupRRRegexes` and
           `globalRRRegexes`) in `handleSpoofedRecords`. Precedence:
           group exact > group regex > global exact > global regex.
  1.23.0 - [SECURITY/FIX] Isolated `r.Question` slice before rewriting
           `q.Name` and `r.Question[0]` in `handleSpoofedRecords`. Prevents
           in-place mutation of `r.Question` when `r` shares its Question
           slice backing array with caller or transport structures.
  1.22.0 - [SECURITY/FIX] Isolated `res.Question` slice before rewriting
           `res.Question[0].Name = w.originalQname` in `spoofResponseWriter.WriteMsg`
           so callers that constructed `res` via `SetReply(r)` (aliasing `r.Question`'s
           backing array) never mutate `r.Question` in place.
  1.21.0 - [SECURITY/FIX] Cleared `res.Ns` when `hasTerminal` is true or when returning
           an incomplete CNAME chain in `spoofResponseWriter.WriteMsg`.
  1.20.0 - [SECURITY/FIX] Stopped rewriting `cname.Header().Name` to `w.originalQname` on
           incomplete CNAME chains when `RRSIG` records are present.
  1.19.0 - [SECURITY/FIX] Stripped DNSSEC records (`NSEC`, `NSEC3`, `RRSIG`) from `res.Ns`
           in `spoofResponseWriter.WriteMsg` when returning an incomplete CNAME chain or
           referrals, and dropped `TypeRRSIG` terminal records when `w.qtype == dns.TypeRRSIG`.
  1.18.0 - [SECURITY/FIX] Dropped invalid `RRSIG` records in `spoofResponseWriter.WriteMsg`.
  1.17.0 - [SECURITY/FIX] Preserved matching `RRSIG` records (`sig.TypeCovered == w.qtype`)
           in `spoofResponseWriter.WriteMsg` when `hasTerminal` is true and DNSSEC (`DO=1`)
           is requested.
  1.16.0 - [SECURITY/FIX] Implemented the missing `RRSIG` preservation logic in
           `spoofResponseWriter.WriteMsg` when `DO=1` is requested.
  1.15.0 - [SECURITY/FIX] Preserved matching `RRSIG` records (`r.TypeCovered == w.qtype`)
           in `spoofResponseWriter.WriteMsg` when `hasTerminal` is true and DNSSEC (`DO=1`)
           is requested.
*/

package main

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

// spoofResponseWriter wraps the standard dns.ResponseWriter to natively 
// inject CNAME aliases into the Answer section of downstream payloads 
// without inducing connection blocks or execution latency.
type spoofResponseWriter struct {
	dns.ResponseWriter
	originalQname string
	cnameTarget   string
	protocol      string
	maxUDPSize    int
	qtype         uint16
}

// WriteMsg intercepts the resolved DNS payload arriving from the cache or 
// upstream provider natively. It forcefully extracts terminal payloads matching
// the requested QTYPE and maps them directly back to the originally requested QNAME
// to guarantee total transparency.
func (w *spoofResponseWriter) WriteMsg(res *dns.Msg) error {
	targetFqdn := strings.ToLower(dns.Fqdn(w.cnameTarget))

	var chainStack [64]string
	chainNames := chainStack[:0]
	chainNames = append(chainNames, targetFqdn)

	for depth := 0; depth < 16; depth++ {
		added := false
		for _, rr := range res.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				owner := strings.ToLower(c.Hdr.Name)
				if isValidBailiwickName(chainNames, owner) {
					t := strings.ToLower(c.Target)
					if !isValidBailiwickName(chainNames, t) && len(chainNames) < 64 {
						chainNames = append(chainNames, t)
						added = true
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

	// Natively extract only terminal payloads matching the queried type and belonging
	// to the resolved CNAME chain, mapping them back to the originally requested QNAME.
	// RRSIGs are never rewritten to w.originalQname because DNSSEC signatures
	// cryptographically bind to the original owner name (RFC 4034 §3.1.8).
	for _, rr := range res.Answer {
		rt := rr.Header().Rrtype
		ownerLower := strings.ToLower(rr.Header().Name)
		if !isValidBailiwickName(chainNames, ownerLower) {
			continue
		}
		if rt == dns.TypeCNAME {
			cnames = append(cnames, dns.Copy(rr))
		} else if rt == dns.TypeRRSIG {
			continue
		} else if rt == w.qtype || w.qtype == dns.TypeANY {
			cloned := dns.Copy(rr)
			cloned.Header().Name = w.originalQname
			finals = append(finals, cloned)
			hasTerminal = true
		}
	}

	// Because the alias mapping from w.originalQname is locally synthesized and
	// unsigned, clear AuthenticatedData.
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

	if len(res.Answer) == 0 {
		var minTTL uint32 = syntheticTTL
		hasSOA := false
		for _, rr := range res.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				hasSOA = true
				if soa.Hdr.Ttl > 0 && soa.Hdr.Ttl < minTTL {
					minTTL = soa.Hdr.Ttl
				}
				if soa.Minttl > 0 && soa.Minttl < minTTL {
					minTTL = soa.Minttl
				}
			}
		}
		if hasSOA || res.Rcode == dns.RcodeNameError || res.Rcode == dns.RcodeSuccess {
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

// handleSpoofedRecords evaluates incoming queries against the RRs maps and regexes dynamically.
// Precedence: group exact > group regex > global exact > global regex.
func handleSpoofedRecords(w *dns.ResponseWriter, r *dns.Msg, q *dns.Question, qNameTrimmed *string, clientGroup, clientID, protocol string, bypassGlobal bool) (bool, string) {
	var record spoofRecord
	var found bool

	if clientGroup != "" {
		if gm := groupRRs[clientGroup]; gm != nil {
			record, found = gm[*qNameTrimmed]
		}
		if !found {
			if gr := groupRRRegexes[clientGroup]; len(gr) > 0 {
				for i := range gr {
					if gr[i].re.MatchString(*qNameTrimmed) {
						record = gr[i].rec
						found = true
						break
					}
				}
			}
		}
	}

	if !found && !bypassGlobal {
		if len(globalRRs) > 0 {
			record, found = globalRRs[*qNameTrimmed]
		}
		if !found && len(globalRRRegexes) > 0 {
			for i := range globalRRRegexes {
				if globalRRRegexes[i].re.MatchString(*qNameTrimmed) {
					record = globalRRRegexes[i].rec
					found = true
					break
				}
			}
		}
	}

	if !found {
		return false, ""
	}

	if record.CNAME != "" {
		if q.Qtype == dns.TypeCNAME {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{}
			resp.SetReply(r)
			resp.Authoritative = true
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: syntheticTTL},
				Target: dns.Fqdn(record.CNAME),
			})

			PreserveEDNS0(r, resp)

			(*w).WriteMsg(resp)
			msgPool.Put(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s CNAME | [SPOOFED CNAME] | NOERROR", protocol, clientID, q.Name)
			}
			return true, ""
		}

		originalQname := q.Name
		target := record.CNAME

		q.Name = dns.Fqdn(target)
		*qNameTrimmed = lowerTrimDot(target)
		qSlice := make([]dns.Question, len(r.Question))
		copy(qSlice, r.Question)
		qSlice[0] = *q
		r.Question = qSlice

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
			cnameTarget:    target,
			protocol:       protocol,
			maxUDPSize:     maxUDP,
			qtype:          q.Qtype,
		}

		return false, target
	}

	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		IncrPolicyBlock()

		resp := msgPool.Get().(*dns.Msg)
		*resp = dns.Msg{}
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess

		SetNegativeSOA(resp, q.Name, syntheticTTL)
		PreserveEDNS0(r, resp)

		(*w).WriteMsg(resp)
		msgPool.Put(resp)

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | [SPOOFED] Unsupported Type | NODATA", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
		}
		return true, ""
	}

	resp := msgPool.Get().(*dns.Msg)
	*resp = dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = true

	hasAnswers := false
	for _, ip := range record.IPs {
		if q.Qtype == dns.TypeA && ip.Is4() {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: syntheticTTL},
				A:   ip.AsSlice(),
			})
			hasAnswers = true
		} else if q.Qtype == dns.TypeAAAA && ip.Is6() {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: syntheticTTL},
				AAAA: ip.AsSlice(),
			})
			hasAnswers = true
		}
	}

	if !hasAnswers {
		SetNegativeSOA(resp, q.Name, syntheticTTL)
	}

	PreserveEDNS0(r, resp)

	(*w).WriteMsg(resp)
	msgPool.Put(resp)

	if logQueries {
		log.Printf("[DNS] [%s] %s -> %s %s | [SPOOFED IP] | NOERROR", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
	}

	return true, ""
}
