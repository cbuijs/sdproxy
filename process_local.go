/*
File:    process_local.go
Version: 1.17.0
Last Updated: 18-Nov-2026 16:50 CET

Description:
  Intercepts queries for locally known hosts or DHCP leases and "spoofs"
  responses to serve them directly without upstream forwarding.
  Extracted from process.go to improve modularity.

Changes:
  1.17.0 - [FIX] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.42.0) on
           positive local identity `A`, `AAAA`, and `PTR` responses before
           `CacheSetSynth` and client transmission so local identity answers
           also honor `min_ttl` and `max_ttl` bounds when configured.
  1.16.0 - [FEAT] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.36.0) on
           local identity `NODATA` responses before `CacheSetSynth` and client
           transmission so local `NODATA` SOA wire TTLs match `CacheSetSynth`
           when `rcode_ttl`, `rcode_min_ttl`, or `rcode_max_ttl` is configured.
  1.15.0 - [FIX] Added missing `IncrReturnCode(resp.Rcode, false)` calls on
           local `NODATA` and `PTR` responses so all local identity answers
           are accurately counted in `Top Return Codes` telemetry.
  1.14.0 - [SECURITY/FIX] Enforced UDP truncation and EDNS0 normalization via
           `enforceUDPDefenses` and used `originalQNameTrimmed` in
           `RecordBlockEvent` when a local hosts entry resolves to a NULL-IP.
  1.13.0 - [FEAT] Added `protoEndpoint` and Simple Logging Mode (`logSimple` /
           `logQuerySimple`) support across all local identity resolution branches.
  1.12.0 - [SECURITY/FIX] Resolved a msgPool leak when `spoofedAlias` is non-empty
           and a local hostname has no matching address family.
  1.11.1 - [SECURITY/FIX] Prevented `handleLocalIdentity` from erroneously hijacking 
           unsupported queries with a `NODATA` response when an active `spoofedAlias`
           is present.
  1.11.0 - [LOGGING/FIX] Included `matchInfo` within `NODATA` responses.
  1.10.0 - [PERF] Inlined `responseContainsNullIP` evaluation within `handleLocalIdentity`.
  1.9.0  - [SECURITY/FIX] Eradicated a critical LAN Privacy Leakage vulnerability natively.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/miekg/dns"
)

// handleLocalIdentity searches local hostfiles and DHCP leases for the requested
// domain name and securely builds a synthetic DNS response if a match is found.
// Returns true if the query was successfully handled locally, natively preventing upstream leaks.
func handleLocalIdentity(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientID, clientIP, protocol, protoEndpoint, routeName, routeOriginType string, bypassLocal bool, cacheKey DNSCacheKey, parentalForcedTTL uint32, originalQName, spoofedAlias string) bool {
	if bypassLocal {
		return false
	}

	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		if addrs, match := LookupIPsByNameLower(qNameTrimmed); len(addrs) > 0 {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{}
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
				applyRcodeOnlyWireTTL(resp)
				if cacheLocalIdentity {
					CacheSetSynth(cacheKey, resp)
				}
				if parentalForcedTTL > 0 {
					CapResponseTTL(resp, parentalForcedTTL)
				}

				isNullIP := false
				for _, rr := range resp.Answer {
					switch r := rr.(type) {
					case *dns.A:
						if r.A.IsUnspecified() {
							isNullIP = true
							break
						}
					case *dns.AAAA:
						if r.AAAA.IsUnspecified() {
							isNullIP = true
							break
						}
					}
					if isNullIP {
						break
					}
				}

				if isNullIP {
					IncrPolicyBlock()
					RecordBlockEvent(clientIP, lowerTrimDot(originalQName), "Local Hosts (NULL-IP)")
				}

				IncrReturnCode(resp.Rcode, isNullIP)

				enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

				w.WriteMsg(resp)
				msgPool.Put(resp)

				if logQueries {
					if logSimple {
						rcStr := "NOERROR"
						polStr := "Local Identity"
						if isNullIP {
							rcStr = "NOERROR (NULL-IP)"
							polStr = "Local Identity Block"
						}
						logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), rcStr, polStr, false)
					} else {
						matchInfo := ""
						if match != qNameTrimmed {
							matchInfo = " (matched " + match + ")"
						}

						statusLog := "LOCAL"
						if isNullIP {
							statusLog = "LOCAL BLOCK"
						}

						if spoofedAlias != "" {
							statusLog = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusLog)
						}

						if isNullIP {
							log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s%s | NOERROR (NULL-IP)",
								protocol, clientID, originalQName, qtypeName(q.Qtype),
								routeName, routeOriginType, statusLog, matchInfo)
						} else {
							log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s%s | NOERROR",
								protocol, clientID, originalQName, qtypeName(q.Qtype),
								routeName, routeOriginType, statusLog, matchInfo)
						}
					}
				}
				return true
			}

			if spoofedAlias != "" {
				msgPool.Put(resp)
				return false
			}

			SetNegativeSOA(resp, q.Name, syntheticTTL)
			applyRcodeOnlyWireTTL(resp)

			if cacheLocalIdentity {
				CacheSetSynth(cacheKey, resp)
			}

			IncrReturnCode(resp.Rcode, false)
			enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

			w.WriteMsg(resp)
			msgPool.Put(resp)

			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), "NOERROR (NODATA)", "Local Identity", false)
				} else {
					matchInfo := ""
					if match != qNameTrimmed {
						matchInfo = " (matched " + match + ")"
					}
					statusLog := "LOCAL"
					if spoofedAlias != "" {
						statusLog = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusLog)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s%s | NOERROR (NODATA)",
						protocol, clientID, originalQName, qtypeName(q.Qtype),
						routeName, routeOriginType, statusLog, matchInfo)
				}
			}

			return true
		}

	case dns.TypePTR:
		if names := LookupNamesByARPA(qNameTrimmed); len(names) > 0 {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{}
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

			applyRcodeOnlyWireTTL(resp)
			if cacheLocalIdentity {
				CacheSetSynth(cacheKey, resp)
			}
			if parentalForcedTTL > 0 {
				CapResponseTTL(resp, parentalForcedTTL)
			}

			IncrReturnCode(resp.Rcode, false)
			enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

			w.WriteMsg(resp)
			msgPool.Put(resp)
			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQName, "PTR", "NOERROR", "Local Identity", false)
				} else {
					log.Printf("[DNS] [%s] %s -> %s PTR | ROUTE: %s (%s) | LOCAL | NOERROR",
						protocol, clientID, originalQName, routeName, routeOriginType)
				}
			}
			return true
		}

	default:
		if spoofedAlias != "" {
			return false
		}

		if addrs, match := LookupIPsByNameLower(qNameTrimmed); len(addrs) > 0 {
			resp := msgPool.Get().(*dns.Msg)
			*resp = dns.Msg{}
			resp.SetReply(r)
			resp.Authoritative = true
			resp.Rcode = dns.RcodeSuccess

			SetNegativeSOA(resp, q.Name, syntheticTTL)
			applyRcodeOnlyWireTTL(resp)

			if cacheLocalIdentity {
				CacheSetSynth(cacheKey, resp)
			}

			IncrReturnCode(resp.Rcode, false)
			enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)

			w.WriteMsg(resp)
			msgPool.Put(resp)

			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQName, qtypeName(q.Qtype), "NOERROR (NODATA)", "Local Identity", false)
				} else {
					matchInfo := ""
					if match != qNameTrimmed {
						matchInfo = " (matched " + match + ")"
					}
					statusLog := "LOCAL"
					if spoofedAlias != "" {
						statusLog = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusLog)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s (%s) | %s%s | NOERROR (NODATA)",
						protocol, clientID, originalQName, qtypeName(q.Qtype),
						routeName, routeOriginType, statusLog, matchInfo)
				}
			}
			return true
		}
	}
	return false
}
