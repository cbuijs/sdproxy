/*
File: process.go
Version: 1.25.0
Last Updated: 2026-03-02 12:00 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.25.0 - [FEAT] Strict PTR validation now also syntax-checks the address
           portion of the query, not just the suffix. IPv4: 1-4 dot-separated
           labels each 0-255, no leading zeros. IPv6: exactly 32 single hex
           nibble labels. Malformed addresses rejected with NXDOMAIN.
  1.24.0 - [FEAT] Added strict PTR validation (step 0b). When cfg.Server.StrictPTR
           is true, PTR queries not ending in ".in-addr.arpa" or ".ip6.arpa" are
           rejected with NXDOMAIN before touching anything else in the pipeline.
  1.23.0 - [FEAT] Added AAAA filter (step 0a). When cfg.Server.FilterAAAA is true,
           all AAAA queries are answered immediately with empty NOERROR before
           touching DDR, cache, identity maps, or upstream.
  1.22.0 - [FIX]  Local identity and PTR answers (from hosts/leases) were never
           cached — the cache check and store both sat after the early-return
           block. Cache is now checked before local resolution and populated on
           a local hit. Route key "local" partitions these from upstream responses.
  1.21.0 - [FEAT] resolveLocalIdentity falls back to LookupIPsBySuffix for
           subdomain matching. "1.2.3.4 company.com" now also answers for
           "www.company.com" etc.
  1.20.0 - [FIX]  resolveLocalIdentity exact full-name lookup only. Short names
           are exclusively for {client-name} resolution, never DNS answers.
  1.19.0 - [FIX]  DDR SVCB ports now use ddrDoHPort/ddrDoTPort globals.
  1.18.0 - [FIX]  DDR glue records deduplicated. ALPN updated with "http/1.1".
  1.17.0 - [PERF] O(1) identity lookups via pre-computed reverse maps.
           Struct-based DNS cache key replaces fmt.Sprintf.
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

// resolveLocalIdentity returns IPs for a queried hostname — O(1) exact match
// first, then a label-walk suffix match so that a hosts entry "1.2.3.4 company.com"
// also answers for "www.company.com" or "bla.amsterdam.company.com".
func resolveLocalIdentity(qname string) []net.IP {
	if ips := LookupIPsByName(qname); len(ips) > 0 {
		return ips
	}
	return LookupIPsBySuffix(qname)
}

// resolveLocalPTR returns all hostnames for an ARPA address via the pre-computed
// arpaToNames map — O(1).
func resolveLocalPTR(arpa string) []string {
	return LookupNamesByARPA(arpa)
}

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q            := r.Question[0]
	originalID   := r.Id
	qNameLower   := strings.ToLower(q.Name)
	qNameTrimmed := strings.TrimSuffix(qNameLower, ".")

	// --- 0a. AAAA Filter ---
	// When filter_aaaa is enabled, respond immediately with an empty NOERROR.
	// Prevents clients on IPv4-only networks from stalling on AAAA timeouts
	// before falling back to A records. Fires before everything else.
	if q.Qtype == dns.TypeAAAA && cfg.Server.FilterAAAA {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		w.WriteMsg(resp)
		log.Printf("[DNS] [%s] %s -> %s AAAA | FILTERED", protocol, clientIP, q.Name)
		return
	}

	// --- 0b. Strict PTR Validation ---
	// When strict_ptr is enabled, PTR queries are validated in two steps:
	//   1. Suffix must be ".in-addr.arpa" (IPv4) or ".ip6.arpa" (IPv6).
	//   2. Address portion must be syntactically correct for that family.
	// Both checks must pass — an invalid address with a valid suffix (e.g.
	// "999.256.banana.0.in-addr.arpa") is rejected just as firmly as a
	// non-reverse PTR query. Fires before DDR, routing, cache, and upstream.
	if q.Qtype == dns.TypePTR && cfg.Server.StrictPTR {
		if !isValidReversePTR(qNameTrimmed) {
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			w.WriteMsg(resp)
			log.Printf("[DNS] [%s] %s -> %s PTR | STRICT PTR REJECTED", protocol, clientIP, q.Name)
			return
		}
	}

	// --- 1. DDR Spoofing & Interception ---
	if q.Qtype == dns.TypeSVCB && qNameTrimmed == "_dns.resolver.arpa" {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		if cfg.Server.DDR.Enabled {
			// SVCB answer records — one DoH record and one DoT/DoQ record per hostname.
			for host := range ddrHostnames {
				target := dns.Fqdn(host)

				// Priority 1: DoH — HTTP/1.1, HTTP/2, HTTP/3 on the configured DoH port.
				svcbHTTPS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 1,
					Target:   target,
				}
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3", "http/1.1"}})
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBPort{Port: ddrDoHPort})
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
				if ddrIPv4 != nil {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ddrIPv4.To4()}})
				}
				if ddrIPv6 != nil {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ddrIPv6.To16()}})
				}
				resp.Answer = append(resp.Answer, svcbHTTPS)

				// Priority 2: DoT + DoQ on the configured DoT/DoQ port.
				svcbTLS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 2,
					Target:   target,
				}
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBAlpn{Alpn: []string{"dot", "doq"}})
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBPort{Port: ddrDoTPort})
				if ddrIPv4 != nil {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ddrIPv4.To4()}})
				}
				if ddrIPv6 != nil {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ddrIPv6.To16()}})
				}
				resp.Answer = append(resp.Answer, svcbTLS)
			}

			// Glue records in Additional — separate pass after the SVCB loop so we
			// emit exactly one A and one AAAA per hostname, no duplicates.
			if ddrIPv4 != nil {
				for host := range ddrHostnames {
					resp.Extra = append(resp.Extra, &dns.A{
						Hdr: dns.RR_Header{Name: dns.Fqdn(host), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ddrIPv4.To4(),
					})
				}
			}
			if ddrIPv6 != nil {
				for host := range ddrHostnames {
					resp.Extra = append(resp.Extra, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: dns.Fqdn(host), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ddrIPv6.To16(),
					})
				}
			}
		}

		w.WriteMsg(resp)
		log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		return
	}

	// DDR hostname A/AAAA spoof — answers direct lookups for the DDR hostnames
	// so clients can resolve them without hitting an upstream.
	if cfg.Server.DDR.Enabled && ddrHostnames[qNameTrimmed] {
		resp    := new(dns.Msg)
		handled := false
		resp.SetReply(r)

		if q.Qtype == dns.TypeA && ddrIPv4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ddrIPv4.To4(),
			})
			handled = true
		} else if q.Qtype == dns.TypeAAAA && ddrIPv6 != nil {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: ddrIPv6.To16(),
			})
			handled = true
		}

		if handled {
			w.WriteMsg(resp)
			log.Printf("[DNS] [%s] %s -> %s %s | DDR SPOOF", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			return
		}
	}

	// --- 2. Local Hosts/Leases Interception (A, AAAA, PTR) ---
	// Cache is checked first — repeated queries for local names are served from
	// the cache without touching the identity maps at all. Route key "local"
	// partitions these entries from upstream-routed responses in the cache.
	localCacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, Route: "local"}
	if cachedResp := CacheGet(localCacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		w.WriteMsg(cachedResp)
		log.Printf("[DNS] [%s] %s -> %s %s | LOCAL CACHE HIT", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		return
	}

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
				CacheSet(localCacheKey, resp)
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
			CacheSet(localCacheKey, resp)
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
		routeName       = domainUpstream
		routeOriginType = "DOMAIN"
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
	var (
		finalResp    *dns.Msg
		lastErr      error
		upstreamUsed string
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fwdReq   := r.Copy()
	fwdReq.Id = dns.Id()

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

// --- PTR Validation Helpers ---

// isValidReversePTR returns true if qname is a syntactically correct reverse
// lookup address — either a valid IPv4 in-addr.arpa or IPv6 ip6.arpa form.
func isValidReversePTR(qname string) bool {
	if addr, ok := strings.CutSuffix(qname, ".in-addr.arpa"); ok {
		return isValidIPv4PTR(addr)
	}
	if addr, ok := strings.CutSuffix(qname, ".ip6.arpa"); ok {
		return isValidIPv6PTR(addr)
	}
	return false
}

// isValidIPv4PTR validates the address portion of an in-addr.arpa query.
//
// Format: 1–4 dot-separated decimal labels in reverse octet order.
// Each label must be a decimal integer 0–255 with no leading zeros.
// 1–3 labels are valid for classless delegation zones (RFC 2317).
//
// Examples:
//   "42.1.168.192"   -> valid (full /32 reverse)
//   "1.168.192"      -> valid (partial, e.g. /24 zone)
//   "999.1.168.192"  -> invalid (999 > 255)
//   "01.1.168.192"   -> invalid (leading zero)
//   "a.1.168.192"    -> invalid (non-decimal)
func isValidIPv4PTR(addr string) bool {
	labels := 0
	for {
		dot := strings.IndexByte(addr, '.')
		var label string
		if dot < 0 {
			label = addr
		} else {
			label = addr[:dot]
		}

		if len(label) == 0 {
			return false // empty label
		}
		// Reject leading zeros on multi-digit labels ("01", "001")
		if len(label) > 1 && label[0] == '0' {
			return false
		}
		// Parse decimal value — must be 0–255
		val := 0
		for _, c := range []byte(label) {
			if c < '0' || c > '9' {
				return false
			}
			val = val*10 + int(c-'0')
			if val > 255 {
				return false
			}
		}

		labels++
		if labels > 4 {
			return false // too many octets
		}
		if dot < 0 {
			break
		}
		addr = addr[dot+1:]
	}
	return labels >= 1
}

// isValidIPv6PTR validates the address portion of an ip6.arpa query.
//
// Format: exactly 32 single lowercase hex-digit labels in reverse nibble order.
// Each label must be exactly one character: [0-9a-f].
// Uppercase is rejected — qname is already lowercased before this call.
//
// Example (for 2001:db8::1):
//   "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
func isValidIPv6PTR(addr string) bool {
	nibbles := 0
	for {
		dot := strings.IndexByte(addr, '.')
		var label string
		if dot < 0 {
			label = addr
		} else {
			label = addr[:dot]
		}

		// Each nibble label must be exactly one hex character
		if len(label) != 1 {
			return false
		}
		c := label[0]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}

		nibbles++
		if dot < 0 {
			break
		}
		addr = addr[dot+1:]
	}
	// IPv6 reverse address is always exactly 32 nibbles
	return nibbles == 32
}

