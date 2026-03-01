/*
File: process.go
Version: 1.17.0
Last Updated: 2026-03-01 14:00 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.17.0 - [PERF] resolveLocalIdentity now calls LookupIPsByName (O(1) pre-computed
           reverse map) instead of ranging over ipNameMap on every query. Same for
           resolveLocalPTR -> LookupNamesByARPA. Both were previously O(n) where n
           is the number of DHCP leases — a significant hot-path bottleneck.
           [PERF] Cache key is now a DNSCacheKey struct instead of a fmt.Sprintf
           string. Removes reflection, heap allocation, and string building from
           every non-cached DNS query.
           [PERF] Short hostname extraction in resolveLocalIdentity uses
           strings.IndexByte instead of strings.Split — zero allocation.
           [FIX]  Removed unused "fmt" import (no longer needed after Sprintf removal).
  1.16.0 - Added DDR interception, PTR resolution, domain route matching.
*/

package main

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// getDomainRoute performs ultra-fast zero-allocation suffix matching.
// Walks the domain label by label using index arithmetic — avoids the
// []string allocation that strings.Split or strings.Join would incur.
// e.g. "server.corp.internal" -> checks full name, then "corp.internal", then "internal".
func getDomainRoute(qname string) (string, bool) {
	search := qname
	for {
		if upstream, ok := domainRoutes[search]; ok {
			return upstream, true
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:] // Zero allocation: reslice, no copy
	}
	return "", false
}

// resolveLocalIdentity returns all IPs matching the given hostname via the
// pre-computed nameToIPs reverse map — O(1) instead of the previous O(n) scan.
// IndexByte extracts the short name without allocating a []string slice.
func resolveLocalIdentity(qname string) []net.IP {
	name := qname
	if idx := strings.IndexByte(qname, '.'); idx > 0 {
		name = qname[:idx]
	}
	return LookupIPsByName(name) // O(1) via pre-computed reverse map in identity.go
}

// resolveLocalPTR returns all hostnames for an ARPA address via the pre-computed
// arpaToNames map — O(1) instead of the previous O(n) scan with per-query ReverseAddr.
func resolveLocalPTR(arpa string) []string {
	return LookupNamesByARPA(arpa) // O(1) via pre-computed reverse map in identity.go
}

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q          := r.Question[0]
	originalID := r.Id
	qNameLower   := strings.ToLower(q.Name)
	qNameTrimmed := strings.TrimSuffix(qNameLower, ".")

	// --- 1. DDR Spoofing & Interception ---
	if q.Qtype == dns.TypeSVCB && qNameTrimmed == "_dns.resolver.arpa" {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		if cfg.Server.DDR.Enabled {
			for host := range ddrHostnames {
				target := dns.Fqdn(host)

				svcbHTTPS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 1,
					Target:   target,
				}
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBPort{Port: 443})
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
				if ddrIPv4 != nil {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ddrIPv4.To4()}})
				}
				if ddrIPv6 != nil {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ddrIPv6.To16()}})
				}
				resp.Answer = append(resp.Answer, svcbHTTPS)

				svcbTLS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 2,
					Target:   target,
				}
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBAlpn{Alpn: []string{"dot", "doq"}})
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBPort{Port: 853})
				if ddrIPv4 != nil {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ddrIPv4.To4()}})
				}
				if ddrIPv6 != nil {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ddrIPv6.To16()}})
				}
				resp.Answer = append(resp.Answer, svcbTLS)

				if ddrIPv4 != nil {
					resp.Extra = append(resp.Extra, &dns.A{
						Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ddrIPv4.To4(),
					})
				}
				if ddrIPv6 != nil {
					resp.Extra = append(resp.Extra, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: target, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ddrIPv6.To16(),
					})
				}
			}
		}

		w.WriteMsg(resp)
		log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		return
	}

	if cfg.Server.DDR.Enabled && ddrHostnames[qNameTrimmed] {
		resp    := new(dns.Msg)
		handled := false
		resp.SetReply(r)

		if q.Qtype == dns.TypeA && ddrIPv4 != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ddrIPv4.To4(),
			}
			resp.Answer = append(resp.Answer, rr)
			handled = true
		} else if q.Qtype == dns.TypeAAAA && ddrIPv6 != nil {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: ddrIPv6.To16(),
			}
			resp.Answer = append(resp.Answer, rr)
			handled = true
		}

		if handled {
			w.WriteMsg(resp)
			log.Printf("[DNS] [%s] %s -> %s %s | DDR SPOOF", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			return
		}
	}

	// --- 2. Local Hosts/Leases Interception (A, AAAA, PTR) ---
	// resolveLocalIdentity and resolveLocalPTR are now O(1) map lookups —
	// see identity.go for the pre-computed reverse maps.
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		if localIPs := resolveLocalIdentity(qNameTrimmed); len(localIPs) > 0 {
			resp     := new(dns.Msg)
			answered := false
			resp.SetReply(r)
			resp.Authoritative = true

			for _, localIP := range localIPs {
				isIPv4 := localIP.To4() != nil
				if q.Qtype == dns.TypeA && isIPv4 {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   localIP.To4(),
					})
					answered = true
				} else if q.Qtype == dns.TypeAAAA && !isIPv4 {
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: localIP.To16(),
					})
					answered = true
				}
			}

			if answered {
				w.WriteMsg(resp)
				log.Printf("[DNS] [%s] %s -> %s %s | LOCAL IDENTITY", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
				return
			}
		}
	} else if q.Qtype == dns.TypePTR {
		if localNames := resolveLocalPTR(qNameTrimmed); len(localNames) > 0 {
			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Authoritative = true
			for _, name := range localNames {
				resp.Answer = append(resp.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: dns.Fqdn(name),
				})
			}
			w.WriteMsg(resp)
			log.Printf("[DNS] [%s] %s -> %s %s | LOCAL PTR", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			return
		}
	}

	// --- 3. Identity Extraction (Client Base Routing) ---
	mac        := LookupMAC(clientIP)
	routeName  := "default"
	clientName := ""

	// 3a. Explicit MAC override from config routes
	if mac != "" {
		if routeInfo, exists := macRoutes[mac]; exists {
			if routeInfo.Upstream != "" {
				routeName = routeInfo.Upstream
			}
			if routeInfo.ClientName != "" {
				clientName = routeInfo.ClientName
			}
		}
	}
	// 3b. Dynamic: resolve name via MAC (dnsmasq leases)
	if clientName == "" && mac != "" {
		if name, ok := LookupNameByMAC(mac); ok {
			clientName = name
		}
	}
	// 3c. Dynamic: resolve name via IP (hosts files / leases)
	if clientName == "" {
		if name, ok := LookupNameByIP(clientIP); ok {
			clientName = name
		}
	}
	// 3d. Fallback: hyphenated MAC or IP
	if clientName == "" {
		if mac != "" {
			clientName = strings.ReplaceAll(mac, ":", "-")
		} else {
			clientName = strings.ReplaceAll(strings.ReplaceAll(clientIP, ".", "-"), ":", "-")
		}
	}

	// --- 4. Domain Route Interception ---
	// Overrides the client route if the queried domain matches a configured suffix.
	routeOriginType := "CLIENT"
	if domainUpstream, matched := getDomainRoute(qNameTrimmed); matched {
		routeName        = domainUpstream
		routeOriginType  = "DOMAIN"
	}

	// --- 5. Cache Lookup ---
	// DNSCacheKey struct — zero allocation, no fmt.Sprintf, no reflection.
	// Route is part of the key to prevent cross-contamination between upstream groups.
	cacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, Route: routeName}
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		w.WriteMsg(cachedResp)
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | CACHE HIT",
			protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName)
		return
	}

	// --- 6. Upstream Selection ---
	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	// --- 7. Upstream Forwarding ---
	var finalResp  *dns.Msg
	var lastErr    error
	var upstreamUsed string

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fwdReq    := r.Copy()
	fwdReq.Id  = dns.Id()

	for _, up := range upstreams {
		resp, actualURL, err := up.Exchange(ctx, fwdReq, clientName)
		if err == nil && resp != nil {
			finalResp    = resp
			upstreamUsed = actualURL
			break
		}
		lastErr = err
	}

	// --- 8. Handle Error ---
	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v",
			protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 9. Cache & Reply ---
	CacheSet(cacheKey, finalResp)
	finalResp.Id = originalID
	w.WriteMsg(finalResp)

	log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | UPSTREAM: %s | OK",
		protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, upstreamUsed)
}

