/*
File:    process_spoof.go
Version: 1.10.0
Last Updated: 15-Oct-2026 17:42 CEST

Description:
  Spoofed Records (RRs) processor for sdproxy.
  Intercepts explicit A, AAAA, and CNAME queries matching global or 
  per-group overrides natively. Capable of recursive target resolutions 
  by seamlessly wrapping the ResponseWriter and dynamically traversing 
  the standard pipeline.

Changes:
  1.10.0 - [SECURITY/FIX] Fixed negative caching SOA zone mismatch in `spoofResponseWriter`.
           When an upstream returns NXDOMAIN or NODATA for a spoofed CNAME target, its SOA
           owner is the target's apex zone (e.g., `google.com.`), not the exact CNAME target.
           Previously, `soa.Header().Name` was unconditionally overwritten with `w.originalQname`,
           corrupting the SOA zone into the queried subdomain while leaving `Ns`/`Mbox` pointing
           at the target's nameservers. Worse, if `cache_synthetic` cached a negative response,
           mutating the SOA in-place modified the shared RR header in `msgPool` or cache memory.
           Now clones any mutated RR before rewriting its owner name, and synthesizes a clean
           authoritative SOA for `w.originalQname` on negative responses.
  1.9.0  - [SECURITY/FIX] Addressed an undeclared memory leak within the error 
           handling branches natively. Explicitly enforced `msgPool.Put()` returns 
           on synthetic block generation constructed during unsupported-type short-circuits.
  1.8.0  - [FEAT] Modified `handleSpoofedRecords` to securely ignore global RRS definitions 
           for clients mapped with `BypassGlobal` privileges.
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
}

// WriteMsg intercepts the resolved DNS payload arriving from the cache or 
// upstream provider natively. It forcefully extracts terminal IP payloads 
// and maps them directly back to the original client request to guarantee 
// total transparency.
func (w *spoofResponseWriter) WriteMsg(res *dns.Msg) error {
	var finals []dns.RR
	hasTerminal := false
	
	// Natively extract only terminal A and AAAA payloads, forcefully mapping 
	// them back to the originally requested QNAME. Clone before mutating to avoid
	// corrupting shared RR pointers when `transformResponse` was a no-op.
	for _, rr := range res.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			cloned := dns.Copy(rr)
			cloned.Header().Name = w.originalQname
			finals = append(finals, cloned)
			hasTerminal = true
		}
	}

	// If the upstream successfully resolved the terminal IPs, we return the flattened array natively.
	// However, if the upstream returned an incomplete CNAME chain (requiring the client to chase it),
	// we MUST preserve the CNAMEs to prevent returning an artificial NODATA void.
	if hasTerminal {
		res.Answer = finals
	} else if len(res.Answer) > 0 {
		// [SECURITY/FIX] Preserve the chain but rewrite the apex owner natively to bridge the alias.
		// Target the specific apex CNAME matching our alias target to ensure out-of-order chains 
		// returned by the upstream do not fracture the resolution path organically.
		targetMatch := w.cnameTarget
		if !strings.HasSuffix(targetMatch, ".") {
			targetMatch += "."
		}

		for i, rr := range res.Answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				recName := cname.Header().Name
				if !strings.HasSuffix(recName, ".") {
					recName += "."
				}
				if strings.EqualFold(recName, targetMatch) {
					cloned := dns.Copy(cname)
					cloned.Header().Name = w.originalQname
					res.Answer[i] = cloned
					break
				}
			}
		}
	}

	// Restore the original Question context to comply rigorously 
	// with RFC 1035 packet matching and stub resolver requirements natively.
	if len(res.Question) > 0 {
		res.Question[0].Name = w.originalQname
	}

	// [SECURITY/FIX 1.10.0] Replace foreign-zone SOA records in the Authority section
	// with a clean synthetic SOA matching `w.originalQname` so strict stub resolvers
	// accept the negative proof without cross-zone NS/Mbox mismatches.
	if len(res.Ns) > 0 {
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
		if hasSOA {
			SetNegativeSOA(res, w.originalQname, minTTL)
		}
	}

	return w.ResponseWriter.WriteMsg(res)
}

// handleSpoofedRecords evaluates incoming queries against the RRs maps dynamically.
// Returns a boolean indicating if the query was fully intercepted and served, 
// and a string signaling the target alias if recursive resolution is necessary.
func handleSpoofedRecords(w *dns.ResponseWriter, r *dns.Msg, q *dns.Question, qNameTrimmed *string, clientGroup, clientID, protocol string, bypassGlobal bool) (bool, string) {
	var record spoofRecord
	var found bool

	// Hierarchy 1: Group-specific overrides (highest precedence)
	if clientGroup != "" && groupRRs[clientGroup] != nil {
		record, found = groupRRs[clientGroup][*qNameTrimmed]
	}
	
	// Hierarchy 2: Global overrides (skips if the client bypasses global policies natively)
	if !found && !bypassGlobal {
		record, found = globalRRs[*qNameTrimmed]
	}

	if !found {
		return false, ""
	}

	// We established a strict structural override match.
	// Enforce Type constraints natively to protect the alias integrity.
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA && q.Qtype != dns.TypeCNAME {
		IncrPolicyBlock()
		
		// Return NODATA (NOERROR + 0 Answers) instead of NXDOMAIN.
		// RFC 8020: NXDOMAIN means the entire name does not exist. Returning NXDOMAIN 
		// for HTTPS/TXT records kills the domain entirely on modern OS stub resolvers, 
		// breaking A/AAAA fallbacks. NODATA correctly forces the fallback to the spoofed CNAME.
		resp := msgPool.Get().(*dns.Msg)
		*resp = dns.Msg{}
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess // NOERROR
		
		SetNegativeSOA(resp, q.Name, syntheticTTL)
		PreserveEDNS0(r, resp)

		(*w).WriteMsg(resp)
		msgPool.Put(resp)

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | [SPOOFED] Unsupported Type | NODATA", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
		}
		return true, ""
	}

	// ── Evaluate CNAME (Alias) Overrides ──
	if record.CNAME != "" {
		if q.Qtype == dns.TypeCNAME {
			// Immediately answer literal CNAME queries natively without upstream resolution
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

		// For A/AAAA queries issued against a CNAME override, we dynamically mutate 
		// the target constraint and forcefully fall through. The primary pipeline 
		// securely routs, resolves, and caches the target IP organically.
		originalQname := q.Name
		target := record.CNAME

		q.Name = dns.Fqdn(target)
		*qNameTrimmed = lowerTrimDot(target)
		r.Question[0] = *q

		*w = &spoofResponseWriter{
			ResponseWriter: *w,
			originalQname:  originalQname,
			cnameTarget:    target,
		}

		return false, target // Cascade dynamically down the primary pipeline, signaling the alias
	}

	// ── Evaluate A/AAAA (Literal IP) Overrides ──
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

	// If queried for an A record but we only possess AAAA (or vice versa),
	// dynamically synthesize a proper NODATA (NOERROR + 0 Answers) response natively.
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

