/*
File:    process_local.go
Version: 1.4.0
Updated: 07-May-2026 10:23 CEST

Description:
  Intercepts queries for locally known hosts or DHCP leases and "spoofs"
  responses to serve them directly without upstream forwarding.
  Extracted from process.go to improve modularity.

Changes:
  1.4.0 - [SECURITY/FIX] Propagated `originalQName` and `spoofedAlias` parameters natively 
          to ensure internal LAN query resolutions correctly honor reporting 
          transparency when chained beneath a custom `rrs:` Spoofed Record engine.
  1.3.0 - [PERF] Wired synthetic response instantiation natively into the zero-allocation 
          `msgPool`. Eradicates severe Garbage Collection (GC) thrashing if the 
          router is flooded with excessive internal LAN queries (e.g., IoT scanning).
  1.2.0 - [FIX] Addressed pointer aliasing boundaries. Explicitly allocates and copies 
          IP byte arrays to completely prevent memory-sharing regressions and heap 
          corruption when iterating across identity maps.
*/

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

// handleLocalIdentity searches local hostfiles and DHCP leases for the requested
// domain name and securely builds a synthetic DNS response if a match is found.
// Returns true if the query was successfully handled locally.
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
					a := addr.As4()
					ip := make(net.IP, 4)
					copy(ip, a[:])
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
							Class: dns.ClassINET, Ttl: syntheticTTL},
						A: ip,
					})
				case addr.Is6() && !addr.Is4In6() && q.Qtype == dns.TypeAAAA:
					a := addr.As16()
					ip := make(net.IP, 16)
					copy(ip, a[:])
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA,
							Class: dns.ClassINET, Ttl: syntheticTTL},
						AAAA: ip,
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
				
				// [FIX] EDNS0 Preservation
				if opt := r.IsEdns0(); opt != nil {
					resp.Extra = append(resp.Extra, dns.Copy(opt))
				}

				isNullIP := responseContainsNullIP(resp)
				if isNullIP {
					IncrPolicyBlock()
					IncrBlockedDomain(qNameTrimmed, "Local Hosts (NULL-IP)")
					recordRecentBlock(clientIP, qNameTrimmed, "Local Hosts (NULL-IP)")
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
			msgPool.Put(resp) // In case Answer array was empty
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
			
			// [FIX] EDNS0 Preservation
			if opt := r.IsEdns0(); opt != nil {
				resp.Extra = append(resp.Extra, dns.Copy(opt))
			}
			
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
	}
	return false
}

