/*
File:    process_local.go
Version: 1.9.0
Last Updated: 29-Aug-2026 10:39 CEST

Description:
  Intercepts queries for locally known hosts or DHCP leases and "spoofs"
  responses to serve them directly without upstream forwarding.
  Extracted from process.go to improve modularity.

Changes:
  1.9.0 - [SECURITY/FIX] Eradicated a critical LAN Privacy Leakage vulnerability natively.
          When clients queried local hostnames for non-standard types (e.g., HTTPS, TXT), 
          the identity router previously ignored them, causing internal LAN names 
          to be forwarded and leaked to public upstream providers. These queries 
          are now definitively trapped and answered with an authoritative NODATA 
          (NOERROR + SOA) response natively.
  1.8.0 - [PERF/CLEANUP] Simplified IP allocation mappings utilizing `addr.AsSlice()` 
          natively, eliminating redundant memory buffering constructs.
  1.7.0 - [SECURITY/FIX] Eradicated a critical LAN Privacy Leakage vulnerability natively.
          When queried for an incompatible IP family (e.g., AAAA queried on an IPv4 host), 
          the identity router now explicitly traps the query and emits an authoritative 
          `NODATA` (NOERROR + 0 Answers) response. This definitively prevents the pipeline 
          from maliciously or inadvertently forwarding internal LAN hostnames to external 
          upstream providers for public resolution.
  1.6.0 - [REFACTOR] Inherited `PreserveEDNS0` utility to systematically guarantee 
          RFC 6891 bounds natively on structural LAN returns without redundant arrays.
*/

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// handleLocalIdentity searches local hostfiles and DHCP leases for the requested
// domain name and securely builds a synthetic DNS response if a match is found.
// Returns true if the query was successfully handled locally, natively preventing upstream leaks.
func handleLocalIdentity(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientID, clientIP, protocol, routeName, routeOriginType string, bypassLocal bool, cacheKey DNSCacheKey, parentalForcedTTL uint32, originalQName, spoofedAlias string) bool {
	if bypassLocal {
		return false
	}

	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		if addrs, match := LookupIPsByNameLower(qNameTrimmed); len(addrs) > 0 {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{} // Zero fields safely
			resp.SetReply(r)
			resp.Authoritative = true
			resp.Answer = make([]dns.RR, 0, len(addrs))
			
			for _, addr := range addrs {
				switch {
				case addr.Is4() && q.Qtype == dns.TypeA:
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
							Class: dns.ClassINET, Ttl: syntheticTTL},
						A: addr.AsSlice(),
					})
				case addr.Is6() && !addr.Is4In6() && q.Qtype == dns.TypeAAAA:
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA,
							Class: dns.ClassINET, Ttl: syntheticTTL},
						AAAA: addr.AsSlice(),
					})
				}
			}
			
			if len(resp.Answer) > 0 {
				if cacheLocalIdentity {
					CacheSetSynth(cacheKey, resp)
				}
				if parentalForcedTTL > 0 {
					CapResponseTTL(resp, parentalForcedTTL)
				}
				
				PreserveEDNS0(r, resp)

				isNullIP := responseContainsNullIP(resp)
				if isNullIP {
					IncrPolicyBlock()
					RecordBlockEvent(clientIP, qNameTrimmed, "Local Hosts (NULL-IP)")
				}

				IncrReturnCode(resp.Rcode, isNullIP)

				w.WriteMsg(resp)
				msgPool.Put(resp)

				if logQueries {
					matchInfo := ""
					if match != qNameTrimmed {
						matchInfo = " (matched " + match + ")"
					}
					
					statusLog := "LOCAL"
					if isNullIP { statusLog = "LOCAL BLOCK" }
					
					if spoofedAlias != "" {
						statusLog = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusLog)
					}

					if isNullIP {
						log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s%s | NOERROR (NULL-IP)",
							protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
							routeName, routeOriginType, statusLog, matchInfo)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s%s | NOERROR",
							protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
							routeName, routeOriginType, statusLog, matchInfo)
					}
				}
				return true
			}
			
			// [SECURITY/FIX] LAN Privacy Leakage Protection
			// The requested localized domain definitely exists within our internal routing 
			// boundaries (e.g., Hosts file, DHCP), but it lacks the exact IP family being 
			// queried (e.g., AAAA queried, but only IPv4 is bound).
			// We MUST intercept this natively and explicitly construct a NODATA 
			// (NOERROR + 0 Answers) envelope instead of falling through to upstream providers.
			// This completely neutralizes internal metadata architectures from leaking outward.
			SetNegativeSOA(resp, q.Name, syntheticTTL)
			PreserveEDNS0(r, resp)
			
			if cacheLocalIdentity {
				CacheSetSynth(cacheKey, resp)
			}
			
			w.WriteMsg(resp)
			msgPool.Put(resp)
			
			if logQueries {
				statusLog := "LOCAL"
				if spoofedAlias != "" {
					statusLog = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusLog)
				}
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s | NOERROR (NODATA)",
					protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
					routeName, routeOriginType, statusLog)
			}
			
			return true // Authoritative localized capture complete
		}

	case dns.TypePTR:
		if names := LookupNamesByARPA(qNameTrimmed); len(names) > 0 {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{} // Zero fields safely
			resp.SetReply(r)
			resp.Authoritative = true
			resp.Answer = make([]dns.RR, 0, len(names))
			for _, name := range names {
				resp.Answer = append(resp.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR,
						Class: dns.ClassINET, Ttl: syntheticTTL},
					Ptr: dns.Fqdn(name),
				})
			}
			
			PreserveEDNS0(r, resp)
			
			if cacheLocalIdentity {
				CacheSetSynth(cacheKey, resp)
			}
			w.WriteMsg(resp)
			msgPool.Put(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s PTR | ROUTE: %s (%s) | LOCAL | NOERROR",
					protocol, clientID, originalQName, routeName, routeOriginType)
			}
			return true
		}

	default:
		// [SECURITY/FIX] LAN Privacy Leakage Protection
		// If the name exists in our local identity maps, but the query type is not A/AAAA/PTR (e.g., HTTPS, TXT, SRV),
		// we MUST intercept it and return NODATA. Do not leak internal local hostnames to public upstreams!
		if addrs, _ := LookupIPsByNameLower(qNameTrimmed); len(addrs) > 0 {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{} // Zero fields safely
			resp.SetReply(r)
			resp.Authoritative = true
			resp.Rcode = dns.RcodeSuccess

			SetNegativeSOA(resp, q.Name, syntheticTTL)
			PreserveEDNS0(r, resp)

			if cacheLocalIdentity {
				CacheSetSynth(cacheKey, resp)
			}

			w.WriteMsg(resp)
			msgPool.Put(resp)

			if logQueries {
				statusLog := "LOCAL"
				if spoofedAlias != "" {
					statusLog = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusLog)
				}
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s | NOERROR (NODATA)",
					protocol, clientID, originalQName, dns.TypeToString[q.Qtype],
					routeName, routeOriginType, statusLog)
			}
			return true
		}
	}
	return false
}

