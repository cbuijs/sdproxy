/*
File:    process_local.go
Version: 1.7.0
Updated: 25-May-2026 08:57 CEST

Description:
  Intercepts queries for locally known hosts or DHCP leases and "spoofs"
  responses to serve them directly without upstream forwarding.
  Extracted from process.go to improve modularity.

Changes:
  1.7.0 - [SECURITY/FIX] Eradicated a critical LAN Privacy Leakage vulnerability natively.
          When queried for an incompatible IP family (e.g., AAAA queried on an IPv4 host), 
          the identity router now explicitly traps the query and emits an authoritative 
          `NODATA` (NOERROR + 0 Answers) response. This definitively prevents the pipeline 
          from maliciously or inadvertently forwarding internal LAN hostnames to external 
          upstream providers for public resolution.
  1.6.0 - [REFACTOR] Inherited `PreserveEDNS0` utility to systematically guarantee 
          RFC 6891 bounds natively on structural LAN returns without redundant arrays.
  1.5.0 - [REFACTOR] Adopted the centralized `RecordBlockEvent` telemetry function 
          to securely align internal domain blocks (NULL-IP tracking) across 
          the analytical outputs naturally.
  1.4.0 - [SECURITY/FIX] Propagated `originalQName` and `spoofedAlias` parameters natively 
          to ensure internal LAN query resolutions correctly honor reporting 
          transparency when chained beneath a custom `rrs:` Spoofed Record engine.
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
	}
	return false
}

