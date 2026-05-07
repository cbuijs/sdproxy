/*
File:    process_spoof.go
Version: 1.3.0
Updated: 07-May-2026 10:23 CEST

Description:
  Spoofed Records (RRs) processor for sdproxy.
  Intercepts explicit A, AAAA, and CNAME queries matching global or 
  per-group overrides natively. Capable of recursive target resolutions 
  by seamlessly wrapping the ResponseWriter and dynamically traversing 
  the standard pipeline.

Changes:
  1.3.0 - [SECURITY/FIX] Enforced strict transparent CNAME flattening on the fly. 
          When mapping recursive targets (e.g., SafeSearch), the engine now 
          natively extracts terminal IP payloads and forcefully binds them to the 
          original query name, guaranteeing absolute client-side transparency.
          Fixed a logging obfuscation flaw where the pipeline tracked the alias 
          target instead of the originally requested domain.
  1.2.0 - [FEAT/FIX] Integrated `flatten_cname` compliance. If CNAME flattening is 
          globally enabled, the proxy now entirely hides the spoofed alias target, 
          seamlessly disguising the recursively resolved IP endpoints natively under 
          the original query name requested by the client.
  1.1.0 - [SECURITY/FIX] Resolved a severe DNS specification violation (RFC 8020).
          Unsupported query types (e.g., HTTPS/Type65, TXT) executed against a 
          spoofed domain previously returned NXDOMAIN. This falsely signaled to 
          modern OS stub resolvers that the entire domain did not exist, fatally 
          aborting A/AAAA fallbacks. The engine now correctly synthesizes NODATA 
          responses (NOERROR + 0 Answers) to preserve fallback resolution natively.
*/

package main

import (
	"log"

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
	
	// Natively extract only terminal A and AAAA payloads, forcefully mapping 
	// them back to the originally requested QNAME. This implements strict 
	// transparent CNAME flattening to hide the spoofed alias target from the client.
	for _, rr := range res.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			rr.Header().Name = w.originalQname
			finals = append(finals, rr)
		}
	}

	res.Answer = finals

	// Restore the original Question context to comply rigorously 
	// with RFC 1035 packet matching and stub resolver requirements natively.
	if len(res.Question) > 0 {
		res.Question[0].Name = w.originalQname
	}

	return w.ResponseWriter.WriteMsg(res)
}

// handleSpoofedRecords evaluates incoming queries against the RRs maps dynamically.
// Returns a boolean indicating if the query was fully intercepted and served, 
// and a string signaling the target alias if recursive resolution is necessary.
func handleSpoofedRecords(w *dns.ResponseWriter, r *dns.Msg, q *dns.Question, qNameTrimmed *string, clientGroup, clientID, protocol string) (bool, string) {
	var record spoofRecord
	var found bool

	// Hierarchy 1: Group-specific overrides (highest precedence)
	if clientGroup != "" && groupRRs[clientGroup] != nil {
		record, found = groupRRs[clientGroup][*qNameTrimmed]
	}
	
	// Hierarchy 2: Global overrides
	if !found {
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
		
		// Inject fake SOA for negative caching of the unsupported query type
		resp.Ns = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: syntheticTTL},
			Ns:      "ns.sdproxy.", Mbox: "hostmaster.sdproxy.",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: syntheticTTL,
		}}

		// Preserve EDNS0 protocol limits cleanly
		if opt := r.IsEdns0(); opt != nil {
			resp.Extra = append(resp.Extra, dns.Copy(opt))
		}

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

			// Preserve EDNS0 protocol limits cleanly
			if opt := r.IsEdns0(); opt != nil {
				resp.Extra = append(resp.Extra, dns.Copy(opt))
			}

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
		resp.Ns = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: syntheticTTL},
			Ns:      "ns.sdproxy.", Mbox: "hostmaster.sdproxy.",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: syntheticTTL,
		}}
	}

	if opt := r.IsEdns0(); opt != nil {
		resp.Extra = append(resp.Extra, dns.Copy(opt))
	}

	(*w).WriteMsg(resp)
	msgPool.Put(resp)

	if logQueries {
		log.Printf("[DNS] [%s] %s -> %s %s | [SPOOFED IP] | NOERROR", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
	}

	return true, ""
}

