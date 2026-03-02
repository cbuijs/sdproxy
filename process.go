/*
File: process.go
Version: 1.27.0
Last Updated: 2026-03-02 17:00 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.27.0 - [PERF] Domain route check moved before identity extraction. MAC/IP
           lookups and name resolution fired on every query regardless of whether
           the upstream needed them. Now: if a domain route matches and its
           upstream group has no {client-name} upstreams (groupNeedsClientName
           computed once at startup), all identity work is skipped entirely —
           zero mutex cycles for the majority of .lan/.local/.home.arpa traffic.
           MAC-based routing is also skipped for domain-matched queries since
           domain routes always take priority over MAC routes anyway.
           [PERF] resolveClientName helper extracted from the inline identity
           block, keeping ProcessDNS readable and the name-resolution logic
           testable in isolation.
           [PERF] Added cfg.Logging.LogQueries guard around per-query log lines.
           At high QPS, log.Printf with string formatting is a measurable CPU
           cost (format parse + argument boxing + log mutex). Setting
           logging.log_queries: false suppresses query-level lines while keeping
           error and upstream-failure logs unconditional. Defaults to true to
           preserve existing behaviour.
  1.26.0 - [FEAT] Added transformResponse, flattenCNAMEChain, and minimizeAnswer
           helpers. CNAME flattening and answer minimization applied before
           CacheSet so cached entries are already in transformed form.
  1.25.0 - [FEAT] Strict PTR address syntax validation.
  1.23.0 - [FEAT] Added AAAA filter (step 0a).
  1.22.0 - [FIX]  Local identity and PTR answers now cached.
  1.21.0 - [FEAT] resolveLocalIdentity falls back to LookupIPsBySuffix.
  1.17.0 - [PERF] O(1) identity lookups via pre-computed reverse maps.
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
		search = search[idx+1:]
	}
	return "", false
}

// resolveLocalIdentity returns IPs for a queried hostname — O(1) exact match
// first, then a label-walk suffix match.
func resolveLocalIdentity(qname string) []net.IP {
	if ips := LookupIPsByName(qname); len(ips) > 0 {
		return ips
	}
	return LookupIPsBySuffix(qname)
}

// resolveLocalPTR returns all hostnames for an ARPA address — O(1).
func resolveLocalPTR(arpa string) []string {
	return LookupNamesByARPA(arpa)
}

// resolveClientName returns the best available display name for a client.
// Resolution order: MAC lease lookup → IP lookup → hyphenated MAC → hyphenated IP.
// Only called when the selected upstream actually uses {client-name}.
func resolveClientName(mac, clientIP string) string {
	if mac != "" {
		if name, ok := LookupNameByMAC(mac); ok {
			return name
		}
	}
	if name, ok := LookupNameByIP(clientIP); ok {
		return name
	}
	if mac != "" {
		return strings.ReplaceAll(mac, ":", "-")
	}
	return strings.ReplaceAll(strings.ReplaceAll(clientIP, ".", "-"), ":", "-")
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
	if q.Qtype == dns.TypeAAAA && cfg.Server.FilterAAAA {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		w.WriteMsg(resp)
		if cfg.Logging.LogQueries {
			log.Printf("[DNS] [%s] %s -> %s AAAA | FILTERED", protocol, clientIP, q.Name)
		}
		return
	}

	// --- 0b. Strict PTR Validation ---
	if q.Qtype == dns.TypePTR && cfg.Server.StrictPTR {
		if !isValidReversePTR(qNameTrimmed) {
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(resp)
			if cfg.Logging.LogQueries {
				log.Printf("[DNS] [%s] %s -> %s PTR | STRICT PTR REJECTED", protocol, clientIP, q.Name)
			}
			return
		}
	}

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
		if cfg.Logging.LogQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		}
		return
	}

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
			if cfg.Logging.LogQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | DDR SPOOF", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			}
			return
		}
	}

	// --- 2. Local Hosts/Leases Interception (A, AAAA, PTR) ---
	localCacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, Route: "local"}
	if cachedResp := CacheGet(localCacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		w.WriteMsg(cachedResp)
		if cfg.Logging.LogQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | LOCAL CACHE HIT", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		}
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
				if cfg.Logging.LogQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | LOCAL IDENTITY", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
				}
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
			if cfg.Logging.LogQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | LOCAL PTR", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			}
			return
		}
	}

	// --- 3. Routing & Identity Extraction ---
	//
	// Domain routes are checked FIRST, before any MAC/IP lookups.
	// This is safe because domain routes always take priority over MAC-based
	// client routing anyway (domain match overwrote routeName in the old code
	// regardless of what MAC routing had set).
	//
	// The identity work (MAC lookup, name resolution) is expensive relative to
	// the rest of the fast path — two RLock cycles plus map reads. It is now
	// skipped entirely when:
	//   a) A domain route matches, AND
	//   b) No upstream in that group uses {client-name} (groupNeedsClientName).
	//
	// For the common case — .lan/.local/.home.arpa routed to a local resolver —
	// this means zero identity work on those queries.
	//
	// When a domain route matches but the upstream DOES use {client-name},
	// only clientName resolution is performed; MAC-based upstream routing is
	// still skipped (domain wins).
	//
	// When no domain route matches, the full client-routing path runs as before:
	// MAC routes may override the upstream group, then clientName is resolved if
	// the selected upstream needs it.

	mac             := ""
	routeName       := "default"
	clientName      := ""
	routeOriginType := "CLIENT"

	if domainUpstream, matched := getDomainRoute(qNameTrimmed); matched {
		// Domain route: skip MAC-based upstream selection entirely.
		routeName       = domainUpstream
		routeOriginType = "DOMAIN"
		// Only resolve client identity if the upstream actually uses {client-name}.
		if groupNeedsClientName[routeName] {
			mac        = LookupMAC(clientIP)
			clientName = resolveClientName(mac, clientIP)
		}
	} else {
		// Client-based routing.
		// 3a. MAC override from config routes (only if any are configured).
		if len(macRoutes) > 0 {
			mac = LookupMAC(clientIP)
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
		}
		// 3b. Resolve clientName only if upstream needs it and it wasn't set by MAC route.
		if groupNeedsClientName[routeName] && clientName == "" {
			if mac == "" {
				mac = LookupMAC(clientIP) // may not have been looked up yet if len(macRoutes)==0
			}
			clientName = resolveClientName(mac, clientIP)
		}
	}

	// --- 4. Cache Lookup ---
	cacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, Route: routeName}
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		w.WriteMsg(cachedResp)
		if cfg.Logging.LogQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | CACHE HIT",
				protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName)
		}
		return
	}

	// --- 5. Upstream Selection ---
	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	// --- 6. Upstream Forwarding ---
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

	// --- 7. Handle Error ---
	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v",
			protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 8. Response Transforms ---
	finalResp = transformResponse(finalResp, q.Qtype)

	// --- 9. Cache & Reply ---
	CacheSet(cacheKey, finalResp)
	finalResp.Id = originalID
	w.WriteMsg(finalResp)

	if cfg.Logging.LogQueries {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | UPSTREAM: %s | OK",
			protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, upstreamUsed)
	}
}

// --- Response Transform Helpers ---

func transformResponse(msg *dns.Msg, qtype uint16) *dns.Msg {
	if msg == nil || (!cfg.Server.FlattenCNAME && !cfg.Server.MinimizeAnswer) {
		return msg
	}

	out := msg.Copy()

	if cfg.Server.FlattenCNAME {
		out = flattenCNAMEChain(out, qtype)
	}

	if cfg.Server.MinimizeAnswer {
		out.Ns    = nil
		out.Extra = nil
	}

	return out
}

// flattenCNAMEChain collapses a CNAME chain in an A or AAAA response.
//
// Transforms:
//   "name CNAME a; a CNAME b; b A 1.2.3.4"  ->  "name A 1.2.3.4"
//
// TTL is set to the minimum across every record in the chain.
// Returns the message unchanged for non-A/AAAA queries, NXDOMAIN, or responses
// without CNAMEs, and for degenerate chains with no final address records.
func flattenCNAMEChain(msg *dns.Msg, qtype uint16) *dns.Msg {
	if msg.Rcode != dns.RcodeSuccess {
		return msg
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return msg
	}

	hasCNAME := false
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME {
			hasCNAME = true
			break
		}
	}
	if !hasCNAME {
		return msg
	}

	minTTL     := ^uint32(0)
	var addrRRs []dns.RR

	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		if rr.Header().Rrtype == qtype {
			addrRRs = append(addrRRs, rr)
		}
	}

	if len(addrRRs) == 0 {
		return msg
	}
	if minTTL == ^uint32(0) {
		minTTL = 0
	}

	qname := msg.Question[0].Name
	flat  := make([]dns.RR, 0, len(addrRRs))
	for _, rr := range addrRRs {
		c              := dns.Copy(rr)
		c.Header().Name = qname
		c.Header().Ttl  = minTTL
		flat = append(flat, c)
	}

	msg.Answer = flat
	return msg
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
// Format: 1–4 dot-separated decimal labels, each 0–255, no leading zeros.
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
			return false
		}
		if len(label) > 1 && label[0] == '0' {
			return false
		}
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
			return false
		}
		if dot < 0 {
			break
		}
		addr = addr[dot+1:]
	}
	return labels >= 1
}

// isValidIPv6PTR validates the address portion of an ip6.arpa query.
// Format: exactly 32 single lowercase hex-digit labels in reverse nibble order.
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
	return nibbles == 32
}

