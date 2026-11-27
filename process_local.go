/*
File:    process_local.go
Version: 1.18.0
Last Updated: 27-Nov-2026 13:30 CET

Description:
  Intercepts queries for locally known hosts or DHCP leases and "spoofs"
  responses to serve them directly without upstream forwarding.

Changes:
  1.18.0 - [FIX] Switched local-identity caching from `CacheSetSynth` to
           `CacheSetLocal` (`routeLocalTag`) so `LoadCache`, `DumpCache`, and
           `serveFromCache` cleanly separate local-identity entries from
           synthetic policy blocks without re-probing `identSnap` on cache hits.
  1.17.0 - [FIX] Applied `applyRcodeOnlyWireTTL` on positive local identity
           `A`, `AAAA`, and `PTR` responses before caching and client write.
  1.16.0 - [FEAT] Applied `applyRcodeOnlyWireTTL` on local identity `NODATA`.
  1.15.0 - [FIX] Added `IncrReturnCode` calls on local `NODATA` and `PTR`.
  1.14.0 - [SECURITY/FIX] Enforced `enforceUDPDefenses` and used
           `originalQNameTrimmed` in `RecordBlockEvent`.
  1.13.0 - [FEAT] Added `protoEndpoint` and Simple Logging Mode support.
  1.12.0 - [SECURITY/FIX] Resolved msgPool leak when `spoofedAlias` is non-empty.
  1.11.1 - [SECURITY/FIX] Prevented `NODATA` hijack on active `spoofedAlias`.
  1.11.0 - [LOGGING/FIX] Included `matchInfo` within `NODATA` responses.
  1.10.0 - [PERF] Inlined `responseContainsNullIP` evaluation.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/miekg/dns"
)

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
					CacheSetLocal(cacheKey, resp)
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
				CacheSetLocal(cacheKey, resp)
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
				CacheSetLocal(cacheKey, resp)
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
				CacheSetLocal(cacheKey, resp)
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
