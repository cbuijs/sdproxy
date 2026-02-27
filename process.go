/*
File: process.go
Version: 1.16.0
Last Updated: 2026-02-27 21:55 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR Discovery queries unconditionally,
             resolves local hostnames (A/AAAA) and reverse lookups (PTR) 
             directly from hosts/leases files returning all matches,
             executes zero-allocation domain route matching for local domains,
             resolves {client-name} dynamically, and executes upstream forwarding.
*/

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// getDomainRoute performs an ultra-fast, zero-allocation suffix lookup.
// By manipulating the slice pointer via index math, we avoid the heavy memory 
// allocation tax of strings.Split() or strings.Join().
// e.g., "server.internal.lan" -> checks "server.internal.lan", then "internal.lan", then "lan".
func getDomainRoute(qname string) (string, bool) {
	search := qname
	for {
		if upstream, ok := domainRoutes[search]; ok {
			return upstream, true
		}
		
		// Find the next dot separator
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		// Move the window past the dot (Zero Allocation)
		search = search[idx+1:]
	}
	return "", false
}

// resolveLocalIdentity scans the populated ipNameMap (managed by identity.go)
// to find ALL matching IPs for the given requested hostname.
func resolveLocalIdentity(qname string) []net.IP {
	// Extract the short hostname (e.g., "my-laptop.lan" -> "my-laptop")
	shortName := strings.Split(qname, ".")[0]
	var foundIPs []net.IP
	
	ipNameMap.Range(func(key, value any) bool {
		ipStr := key.(string)
		name := value.(string)
		
		// Check against both the full query name and the extracted shortname
		if strings.EqualFold(name, qname) || strings.EqualFold(name, shortName) {
			if parsedIP := net.ParseIP(ipStr); parsedIP != nil {
				foundIPs = append(foundIPs, parsedIP)
			}
		}
		return true // Continue iteration to find all matches
	})
	
	return foundIPs
}

// resolveLocalPTR scans the populated ipNameMap to find ALL matching hostnames
// for a given reverse DNS (PTR) ARPA query.
func resolveLocalPTR(qname string) []string {
	var foundNames []string
	
	ipNameMap.Range(func(key, value any) bool {
		ipStr := key.(string)
		name := value.(string)
		
		if arpa, err := dns.ReverseAddr(ipStr); err == nil {
			arpaTrimmed := strings.TrimSuffix(strings.ToLower(arpa), ".")
			if arpaTrimmed == qname {
				foundNames = append(foundNames, name)
			}
		}
		return true // Continue iteration to find all matches
	})
	
	return foundNames
}

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	originalID := r.Id

	qNameLower := strings.ToLower(q.Name)
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
						Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ddrIPv6.To16(),
					})
				}
			}
		}

		w.WriteMsg(resp)
		log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY (Answered Local)", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		return
	}

	if cfg.Server.DDR.Enabled && ddrHostnames[qNameTrimmed] {
		handled := false
		resp := new(dns.Msg)
		resp.SetReply(r)

		if q.Qtype == dns.TypeA && ddrIPv4 != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
			rr.A = ddrIPv4.To4()
			resp.Answer = append(resp.Answer, rr)
			handled = true
		} else if q.Qtype == dns.TypeAAAA && ddrIPv6 != nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}
			rr.AAAA = ddrIPv6.To16()
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
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		if localIPs := resolveLocalIdentity(qNameTrimmed); len(localIPs) > 0 {
			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Authoritative = true
			answered := false

			for _, localIP := range localIPs {
				isIPv4 := localIP.To4() != nil

				if q.Qtype == dns.TypeA && isIPv4 {
					rr := new(dns.A)
					rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
					rr.A = localIP.To4()
					resp.Answer = append(resp.Answer, rr)
					answered = true
				} else if q.Qtype == dns.TypeAAAA && !isIPv4 {
					rr := new(dns.AAAA)
					rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}
					rr.AAAA = localIP.To16()
					resp.Answer = append(resp.Answer, rr)
					answered = true
				}
			}

			if answered {
				w.WriteMsg(resp)
				log.Printf("[DNS] [%s] %s -> %s %s | LOCAL IDENTITY (Answered Local)", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
				return
			}
		}
	} else if q.Qtype == dns.TypePTR {
		if localNames := resolveLocalPTR(qNameTrimmed); len(localNames) > 0 {
			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Authoritative = true

			for _, name := range localNames {
				rr := new(dns.PTR)
				rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}
				rr.Ptr = dns.Fqdn(name) // Ensure valid trailing dot formatting
				resp.Answer = append(resp.Answer, rr)
			}

			w.WriteMsg(resp)
			log.Printf("[DNS] [%s] %s -> %s %s | LOCAL IDENTITY PTR (Answered Local)", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			return
		}
	}

	// --- 3. Identity Extraction (Client Base Routing) ---
	mac := LookupMAC(clientIP)

	routeName := "default"
	clientName := ""

	// Waterfall Logic for Identity Resolution
	// 3.a Check explicit configuration overrides first
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

	// 3.b Dynamic Discovery: Try to resolve name via MAC from Dnsmasq Leases
	if clientName == "" && mac != "" {
		if name, ok := LookupNameByMAC(mac); ok {
			clientName = name
		}
	}

	// 3.c Dynamic Discovery: Try to resolve name via IP from Hosts files / Leases
	if clientName == "" {
		if name, ok := LookupNameByIP(clientIP); ok {
			clientName = name
		}
	}

	// 3.d Fallback: Hyphenated MAC or IP Address
	if clientName == "" {
		if mac != "" {
			clientName = strings.ReplaceAll(mac, ":", "-")
		} else {
			clientName = strings.ReplaceAll(clientIP, ".", "-")
			clientName = strings.ReplaceAll(clientName, ":", "-")
		}
	}

	// --- 4. Domain Route Interception ---
	// Overrides the Client Route if the user is asking for a targeted domain suffix
	routeOriginType := "CLIENT" // Log tracking
	if domainUpstream, matched := getDomainRoute(qNameTrimmed); matched {
		routeName = domainUpstream
		routeOriginType = "DOMAIN"
	}

	// --- 5. Cache Lookup ---
	// The routeName is baked into the Cache Key to prevent cross-contamination 
	// of local zone answers into global upstream partitioned requests.
	cacheKey := fmt.Sprintf("%s|%d|%d|%s", q.Name, q.Qtype, q.Qclass, routeName)
	
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID 
		w.WriteMsg(cachedResp)
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | CACHE HIT", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName)
		return
	}

	// --- 6. Upstream Retrieval ---
	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	// --- 7. Upstream Forwarding ---
	var finalResp *dns.Msg
	var lastErr error
	var upstreamUsed string

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fwdReq := r.Copy()
	fwdReq.Id = dns.Id()

	for _, up := range upstreams {
		resp, actualURL, err := up.Exchange(ctx, fwdReq, clientName)
		if err == nil && resp != nil {
			finalResp = resp
			upstreamUsed = actualURL
			break
		}
		lastErr = err
	}

	// --- 8. Handle Error or Response ---
	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 9. Cache Insertion ---
	CacheSet(cacheKey, finalResp)

	// --- 10. Reply to Client ---
	finalResp.Id = originalID 
	w.WriteMsg(finalResp)

	log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | UPSTREAM: %s | OK", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, upstreamUsed)
}

