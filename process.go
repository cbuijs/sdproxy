/*
File: process.go
Version: 1.39.0
Last Updated: 2026-03-04 00:00 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.38.0 - [FEAT] Unassigned qtype filter (step 0a): when blockUnknownQtypes is
           set, type numbers that miekg/dns doesn't recognise — IANA unassigned
           gaps — are blocked with NOTIMP at query time. Named obsolete types are
           handled earlier via rtypePolicy injection in main.go (step 0), so the
           runtime cost here is one map lookup only for truly unknown numbers.
  1.37.0 - [FIX]  CacheSet is now called on the raw upstream response BEFORE
           transformResponse runs. This guarantees that the full response —
           including the Ns SOA record used for negative TTL calculation — is
           visible to CacheSet even when minimize_answer is enabled (which strips
           the Ns section). Without this fix, negative responses would always
           fall back to min_ttl because the SOA had already been stripped.
           [FIX]  transformResponse is now also applied on cache-hit paths (steps
           2 and 4) so clients receive a consistent transformed view regardless of
           whether the response came from cache or live from upstream. Previously,
           flatten_cname and minimize_answer only applied on the first query for a
           name; cache hits returned the raw upstream response. transformResponse
           already has a fast early-return when both transforms are disabled, so
           the cost on cache hits is one nil/bool check when transforms are off.
  1.36.0 - [FEAT] DDR spoofed records now support multiple IP addresses per
           address family and automatic interface-IP fallback when no addresses
           are configured. ddrIPv4/ddrIPv6 are now []net.IP (set in main.go).
  1.35.1 - [FEAT] HTTPS response for DDR hostnames includes glue A/AAAA records
           in the additional section.
  1.35.0 - [FEAT] DDR hostname spoofing extended with HTTPS record support.
  1.34.0 - [PERF] Feature-gated hot-path skipping via startup bool flags.
  1.33.0 - [FEAT] Upstream forwarding now uses raceExchange (upstream.go v1.18.0).
  1.32.0 - [PERF] lowerTrimDot: zero-alloc single-pass lowercase + dot trim.
  1.31.0 - [PERF] Single LookupNameByMACOrIP call, routeIdx uint8 tracking.
  1.30.0 - [FEAT] RType Policy (step 0): immediate RCODE by query type.
  1.28.0 - [FEAT] Per-query log lines include resolved client name.
  1.27.0 - [PERF] Eliminated redundant dns.Msg.Copy() on forwarding path.
  1.26.0 - [FEAT] Added transformResponse, flattenCNAMEChain, and minimizeAnswer.
  1.25.0 - [FEAT] Strict PTR address syntax validation.
  1.23.0 - [FEAT] Added AAAA filter (step 0a).
  1.22.0 - [FIX]  Local identity and PTR answers now cached with route key "local".
  1.21.0 - [FEAT] resolveLocalIdentity falls back to LookupIPsBySuffix.
  1.17.0 - [PERF] O(1) identity lookups via pre-computed reverse maps.
*/

package main

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// logQueries is the hot-path logging gate. Set once at startup from config.
// When false, per-query log lines are suppressed entirely — no mutex, no
// fmt.Sprintf, no I/O. Errors and startup messages always log regardless.
var logQueries bool

// getRouteIdx returns the uint8 index for a route name, falling back to
// routeIdxDefault when the name isn't in the table.
func getRouteIdx(name string) uint8 {
	if idx, ok := routeIdxByName[name]; ok {
		return idx
	}
	return routeIdxDefault
}

// lowerTrimDot lowercases a DNS name and strips a trailing dot in a single pass.
//
// Fast path (zero allocation): when the input is already all-lowercase — which
// is the case for ~95% of DNS wire names — returns a substring of the original
// string (just adjusts the length to trim the dot). No []byte, no copy.
//
// Slow path (one allocation): when an uppercase byte is found, allocates a
// []byte of the trimmed length and lowercases in one forward pass from that
// point onward. Everything before the first uppercase byte is bulk-copied.
//
// Replaces the previous strings.ToLower() + strings.TrimSuffix() which always
// allocated twice regardless of input case.
func lowerTrimDot(s string) string {
	end := len(s)
	if end > 0 && s[end-1] == '.' {
		end--
	}
	for i := 0; i < end; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			buf := make([]byte, end)
			copy(buf, s[:i])
			for j := i; j < end; j++ {
				c := s[j]
				if c >= 'A' && c <= 'Z' {
					c += 0x20
				}
				buf[j] = c
			}
			return string(buf)
		}
	}
	return s[:end]
}

// getDomainRoute performs zero-allocation suffix matching via label walk.
// Only called from ProcessDNS when hasDomainRoutes is true.
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
// first, then a label-walk suffix match so that a hosts entry "1.2.3.4 company.com"
// also answers for "www.company.com" or "bla.amsterdam.company.com".
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

// localAddrIP extracts the listener IP from a ResponseWriter's local address.
//
// For miekg/dns UDP/TCP/DoT writers the local address is always populated.
// For the custom dohResponseWriter and doqResponseWriter in server.go, it relies
// on the localIP field added in v1.16.0 — without that field LocalAddr() returns
// nil and no interface fallback is available for those protocols.
//
// Returns nil when the address is unavailable, unresolvable, or unspecified
// (0.0.0.0 / ::) — callers must handle nil gracefully.
func localAddrIP(w dns.ResponseWriter) net.IP {
	addr := w.LocalAddr()
	if addr == nil {
		return nil
	}
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		// Generic fallback for any other net.Addr implementation.
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			ip = net.ParseIP(addr.String())
		} else {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}

// ddrAddrs returns the effective IPv4 and IPv6 address slices for all DDR
// spoofed responses (SVCB hints, HTTPS hints, A, AAAA, and glue records).
//
// When a configured slice (ddrIPv4 / ddrIPv6) is non-empty it is used as-is.
// When empty, the local interface address of the incoming query is used as a
// single-entry fallback — but only for the matching address family.
func ddrAddrs(w dns.ResponseWriter) (ipv4s, ipv6s []net.IP) {
	ipv4s = ddrIPv4
	ipv6s = ddrIPv6
	if len(ipv4s) > 0 && len(ipv6s) > 0 {
		return // both families configured — skip the LocalAddr() call entirely
	}
	local := localAddrIP(w)
	if local == nil {
		return
	}
	if len(ipv4s) == 0 {
		if v4 := local.To4(); v4 != nil {
			ipv4s = []net.IP{v4}
		}
	}
	if len(ipv6s) == 0 {
		if local.To4() == nil { // pure IPv6, not an IPv4-mapped address
			ipv6s = []net.IP{local}
		}
	}
	return
}

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	// --- OpCode guard ---
	// Only QUERY (0) is supported. All other opcodes — IQUERY (1, obsolete RFC 3425),
	// STATUS (2), NOTIFY (4 RFC 1996), UPDATE (5 RFC 2136), DSO (6 RFC 8490) etc. —
	// require authoritative server semantics. Forwarding them would be semantically
	// wrong and could cause unintended mutations on upstream authoritative servers.
	// SetRcode mirrors the opcode back in the response header, which is correct per RFC.
	if r.Opcode != dns.OpcodeQuery {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(resp)
		if logQueries {
			// clientID isn't built yet at this point — use raw clientIP.
			log.Printf("[DNS] [%s] %s -> OPCODE %d | UNSUPPORTED OPCODE: NOTIMP",
				protocol, clientIP, r.Opcode)
		}
		return
	}

	q          := r.Question[0]
	originalID := r.Id

	// --- QClass guard ---
	// Only class IN (Internet, 1) is supported. CH (Chaosnet, 3) is sometimes used
	// to query server identity (e.g. "hostname.bind CH TXT") — we don't expose that.
	// HS (Hesiod, 4), NONE (254), and ANY (255) have no meaning on a forwarding
	// resolver. Returning NOTIMP is correct per RFC 1035 §4.1.2.
	if q.Qclass != dns.ClassINET {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s CLASS %d | UNSUPPORTED CLASS: NOTIMP",
				protocol, clientIP, q.Name, q.Qclass)
		}
		return
	}

	// lowerTrimDot: single pass, zero-alloc when already lowercase (~95% of queries).
	qNameTrimmed := lowerTrimDot(q.Name)

	// --- Identity & Routing ---
	// needsClientName collapses two independent conditions into one flag check.
	// When both logQueries and hasClientNameUpstream are false — the common case
	// in production with log_queries: false and no ControlD-style per-device URLs —
	// we skip the entire identity lookup + string building block.
	needsClientName := logQueries || hasClientNameUpstream

	routeName := "default"
	routeIdx  := routeIdxDefault
	var mac, clientName string

	// MAC lookup and MAC-based routing — only when cfg.Routes has valid entries.
	if hasMACRoutes {
		mac = LookupMAC(clientIP)
		if mac != "" {
			if routeInfo, exists := macRoutes[mac]; exists {
				if routeInfo.Upstream != "" {
					routeName = routeInfo.Upstream
					routeIdx  = getRouteIdx(routeName)
				}
				if routeInfo.ClientName != "" {
					clientName = routeInfo.ClientName
				}
			}
		}
	}

	// Identity name resolution and clientName fallback string building.
	if needsClientName {
		if identityName := LookupNameByMACOrIP(mac, clientIP); identityName != "" && clientName == "" {
			clientName = identityName
		}
		if clientName == "" {
			if mac != "" {
				clientName = strings.ReplaceAll(mac, ":", "-")
			} else {
				clientName = strings.ReplaceAll(strings.ReplaceAll(clientIP, ".", "-"), ":", "-")
			}
		}
	}

	// Pre-format client identifier for log lines — only when per-query logging is on.
	var clientID string
	if logQueries {
		clientID = clientIP + " (" + clientName + ")"
	}

	// --- 0. RType Policy ---
	if hasRtypePolicy {
		if rcode, blocked := rtypePolicy[q.Qtype]; blocked {
			resp := new(dns.Msg)
			resp.SetRcode(r, rcode)
			w.WriteMsg(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | RTYPE POLICY: %s",
					protocol, clientID, q.Name, dns.TypeToString[q.Qtype], dns.RcodeToString[rcode])
			}
			return
		}
	}

	// --- 0a. Unassigned Qtype Filter ---
	// Named obsolete types are already handled above via rtypePolicy (injected at
	// startup by main.go). This check catches purely numeric IANA gaps — type
	// values that miekg/dns has no name for, meaning they are either unassigned in
	// the IANA registry or so new that the library predates their allocation.
	// A forwarding resolver has nothing useful to do with either case.
	// Cost: one uint16 map lookup, skipped entirely when blockUnknownQtypes is false.
	if blockUnknownQtypes {
		if _, known := dns.TypeToString[q.Qtype]; !known {
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeNotImplemented)
			w.WriteMsg(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s TYPE%d | UNASSIGNED QTYPE: NOTIMP",
					protocol, clientID, q.Name, q.Qtype)
			}
			return
		}
	}

	// --- 0b. AAAA Filter ---
	if q.Qtype == dns.TypeAAAA && cfg.Server.FilterAAAA {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		w.WriteMsg(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s AAAA | FILTERED", protocol, clientID, q.Name)
		}
		return
	}

	// --- 0c. Strict PTR Validation ---
	if q.Qtype == dns.TypePTR && cfg.Server.StrictPTR {
		if !isValidReversePTR(qNameTrimmed) {
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s PTR | STRICT PTR REJECTED", protocol, clientID, q.Name)
			}
			return
		}
	}

	// --- 1. DDR Spoofing & Interception ---

	// 1a. _dns.resolver.arpa SVCB — RFC 9462 discovery endpoint.
	if q.Qtype == dns.TypeSVCB && qNameTrimmed == "_dns.resolver.arpa" {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		if cfg.Server.DDR.Enabled {
			ipv4s, ipv6s := ddrAddrs(w)

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
				if len(ipv4s) > 0 {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
				}
				if len(ipv6s) > 0 {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
				}
				resp.Answer = append(resp.Answer, svcbHTTPS)

				svcbTLS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 2,
					Target:   target,
				}
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBAlpn{Alpn: []string{"dot", "doq"}})
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBPort{Port: ddrDoTPort})
				if len(ipv4s) > 0 {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
				}
				if len(ipv6s) > 0 {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
				}
				resp.Answer = append(resp.Answer, svcbTLS)
			}

			for _, ip := range ipv4s {
				for host := range ddrHostnames {
					resp.Extra = append(resp.Extra, &dns.A{
						Hdr: dns.RR_Header{Name: dns.Fqdn(host), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ip.To4(),
					})
				}
			}
			for _, ip := range ipv6s {
				for host := range ddrHostnames {
					resp.Extra = append(resp.Extra, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: dns.Fqdn(host), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ip.To16(),
					})
				}
			}
		}

		w.WriteMsg(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
		}
		return
	}

	// 1b. DDR hostname spoofing — A, AAAA, and HTTPS records for configured resolver
	// hostnames. All other query types return NXDOMAIN immediately; never forwarded.
	if cfg.Server.DDR.Enabled && ddrHostnames[qNameTrimmed] {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		label := "DDR SPOOF"

		ipv4s, ipv6s := ddrAddrs(w)

		switch q.Qtype {
		case dns.TypeA:
			for _, ip := range ipv4s {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.To4(),
				})
			}

		case dns.TypeAAAA:
			for _, ip := range ipv6s {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip.To16(),
				})
			}

		case dns.TypeHTTPS:
			svcb := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
				Priority: 1,
				Target:   ".",
			}
			svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3", "http/1.1"}})
			svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: ddrDoHPort})
			svcb.Value = append(svcb.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
			if len(ipv4s) > 0 {
				svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
			}
			if len(ipv6s) > 0 {
				svcb.Value = append(svcb.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
			}
			resp.Answer = append(resp.Answer, svcb)
			for _, ip := range ipv4s {
				resp.Extra = append(resp.Extra, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.To4(),
				})
			}
			for _, ip := range ipv6s {
				resp.Extra = append(resp.Extra, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip.To16(),
				})
			}

		default:
			resp.SetRcode(r, dns.RcodeNameError)
			label = "DDR NXDOMAIN"
		}

		w.WriteMsg(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], label)
		}
		return
	}

	// --- 2. Local Hosts/Leases Interception ---
	localCacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdxLocal}
	if cachedResp := CacheGet(localCacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		// Apply transforms on cache hits for consistent client-facing behaviour.
		// transformResponse fast-returns when both transforms are disabled (no-op cost).
		cachedResp = transformResponse(cachedResp, q.Qtype)
		w.WriteMsg(cachedResp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | LOCAL CACHE HIT", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
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
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | LOCAL IDENTITY", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
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
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | LOCAL PTR", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
			}
			return
		}
	} else {
		// Any other query type for a locally-known name: return NXDOMAIN immediately.
		if localIPs := resolveLocalIdentity(qNameTrimmed); len(localIPs) > 0 {
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeNameError)
			resp.Authoritative = true
			CacheSet(localCacheKey, resp)
			w.WriteMsg(resp)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | LOCAL NXDOMAIN (name is local-only)",
					protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
			}
			return
		}
	}

	// --- 3. Domain Route Interception ---
	routeOriginType := "CLIENT"
	if hasDomainRoutes {
		if domainUpstream, matched := getDomainRoute(qNameTrimmed); matched {
			routeName       = domainUpstream
			routeIdx        = getRouteIdx(domainUpstream)
			routeOriginType = "DOMAIN"
		}
	}

	// --- 4. Cache Lookup ---
	cacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdx}
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		// Apply transforms on cache hits — same reasoning as the local cache hit
		// path above. Ensures flatten_cname and minimize_answer are applied
		// consistently whether the response is fresh from upstream or from cache.
		cachedResp = transformResponse(cachedResp, q.Qtype)
		w.WriteMsg(cachedResp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | CACHE HIT",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName)
		}
		return
	}

	// --- 5. Upstream Selection ---
	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	// --- 6. Upstream Forwarding ---
	finalResp, upstreamUsed, lastErr := raceExchange(upstreams, r, clientName)

	// --- 7. Handle Error ---
	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v",
			protocol, clientIP+" ("+clientName+")", q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 8. Cache (before transforms) ---
	// CacheSet receives the raw upstream response so it can read the full Ns
	// section — in particular any SOA record for correct negative TTL calculation.
	// If we cached after transformResponse, minimize_answer would have stripped
	// the Ns section and CacheSet would always fall back to min_ttl for negative
	// responses. min_ttl and max_ttl clamping are applied inside CacheSet.
	CacheSet(cacheKey, finalResp)

	// --- 9. Response Transforms ---
	// Applied after caching. The stored entry is always the raw upstream response;
	// transforms are presentation-layer concerns applied on the way out to the
	// client — both here (live path) and on cache hits (step 4 above).
	finalResp = transformResponse(finalResp, q.Qtype)

	// --- 10. Reply ---
	finalResp.Id = originalID
	w.WriteMsg(finalResp)

	if logQueries {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | UPSTREAM: %s | OK",
			protocol, clientID, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, upstreamUsed)
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

	minTTL      := ^uint32(0)
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

func isValidReversePTR(qname string) bool {
	if addr, ok := strings.CutSuffix(qname, ".in-addr.arpa"); ok {
		return isValidIPv4PTR(addr)
	}
	if addr, ok := strings.CutSuffix(qname, ".ip6.arpa"); ok {
		return isValidIPv6PTR(addr)
	}
	return false
}

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

