/*
File: process.go
Version: 1.45.0
Last Updated: 2026-03-06 19:40 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.45.0 - [LOG] Added responseContainsNullIP helper to detect and log sinkholed
           responses (0.0.0.0 or ::) from upstream resolvers, cache, and local
           overrides. Modified log lines to include a "(NULL-IP)" tag when an
           A/AAAA response points to an unspecified address.
  1.44.0 - [FEAT] IncrQueryTotal() called after AcquireQuery to feed the
           miss-rate signal in throttle.go. IncrUpstreamCall() called at
           step 6 (just before raceExchange) to count cache misses. Together
           these let the throttler compute Δupstream/Δqueries per 500 ms
           window — a leading indicator of upstream saturation.
  1.43.0 - [FEAT] Adaptive admission control: AcquireQuery/ReleaseQuery calls
           added at ProcessDNS entry point (after the question-count guard).
           Queries exceeding the pressure-adjusted queryLimit are silently
           dropped — no response is written so the client retries after its
           own timeout. Zero hot-path overhead on the happy path: two CAS
           ops per query.
           [FIX]  Cache keys now use qNameTrimmed (lowercase, no trailing dot)
           instead of q.Name (raw wire name). Previously "GOOGLE.COM." and
           "google.com." produced separate cache entries and separate upstream
           queries. Using the already-computed normalised name fixes the hit rate
           at zero cost — lowerTrimDot was already being called earlier in the
           same function.
           [PERF] transformResponse now accepts an inPlace bool. When true, the
           function mutates the message directly instead of calling msg.Copy().
           Cache hits return a fresh caller-owned copy from CacheGet (cache.go
           v1.17.0 changed CacheGet to return msg.Copy()), so all cache-hit call
           sites pass inPlace=true — one allocation instead of two. The live
           upstream path passes inPlace=false because the original finalResp is
           still needed by CacheSet before transforms run.
           [PERF] resolveLocalIdentity now calls LookupIPsByNameLower instead of
           LookupIPsByName. qNameTrimmed is already lowercase after lowerTrimDot,
           so the strings.ToLower call inside LookupIPsByName was redundant on
           every A/AAAA query that reaches the local-identity check.
           [PERF] Pre-built policy RCODE responses: at startup, policyRespCache
           maps each configured RCODE to a pre-packed []byte template. Policy hits
           (rtype_policy, domain_policy, AAAA filter, strict PTR, opcode/class
           guards) unpack the template, patch the ID and question, and write —
           avoiding new(dns.Msg) + SetRcode + WriteMsg allocations on every hit.
           [PERF] clientID string building now uses a pooled strings.Builder
           (clientIDPool). Previously clientIP + " (" + clientName + ")" caused
           two allocations per logged query via string concatenation. The pooled
           builder pays one allocation for the final String() call only.
  1.42.0 - [PERF] Merged domain label walk: walkDomainMaps checks both
           domainPolicy and domainRoutes in a single O(labels) pass.
           [PERF] flattenCNAMEChain: two passes collapsed into one.
           [PERF] sanitizeID: single in-place byte loop, one allocation.
  1.41.0 - [FEAT] Domain Policy (step 0d): suffix-based name blocking.
  1.40.0 - [FEAT] Unassigned qtype filter (step 0a).
  1.38.0 - [FIX]  CacheSet called before transformResponse.
           [FIX]  transformResponse applied on cache-hit paths.
  1.37.0 - [FEAT] DDR spoofed records support multiple IPs + interface fallback.
  1.36.0 - [FEAT] DDR hostname spoofing extended with HTTPS record support.
  1.35.0 - [FEAT] DDR hostname spoofing extended with HTTPS record support.
  1.34.0 - [PERF] Feature-gated hot-path skipping via startup bool flags.
  1.33.0 - [FEAT] Upstream forwarding uses raceExchange.
  1.32.0 - [PERF] lowerTrimDot: zero-alloc single-pass lowercase + dot trim.
  1.31.0 - [PERF] Single LookupNameByMACOrIP call, routeIdx uint8 tracking.
  1.30.0 - [FEAT] RType Policy (step 0): immediate RCODE by query type.
*/

package main

import (
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// logQueries is the hot-path logging gate. Set once at startup from config.
// When false, per-query log lines are suppressed entirely — no mutex, no
// fmt.Sprintf, no I/O. Errors and startup messages always log regardless.
var logQueries bool

// clientIDPool holds reusable strings.Builder values for building the
// "ip (name)" client identifier that appears in every log line.
// Previously two string concatenations caused two allocations per logged query;
// the pooled builder pays only one (the final sb.String() call).
var clientIDPool = sync.Pool{New: func() any { return new(strings.Builder) }}

// policyRespCache maps DNS RCODE integers to a pre-packed *dns.Msg template.
// Built at startup by buildPolicyRespCache(). Policy fast-paths (rtype_policy,
// domain_policy, opcode guard, class guard, AAAA filter, strict PTR) unpack
// a copy of the template and patch the transaction ID + question section —
// avoiding new(dns.Msg) + SetRcode + WriteMsg allocations on every hit.
//
// Each template is a minimal, valid DNS response: QR=1, AA=0, the original
// RCODE, and an empty question/answer. The caller patches Id and Question[0]
// before writing.
var policyRespCache map[int][]byte

// buildPolicyRespCache pre-packs a minimal response template for every RCODE
// that can be returned by a policy check. Called once from main() after all
// policy maps are populated.
//
// RCODEs covered: NOTIMP, REFUSED, NXDOMAIN, NOERROR (AAAA filter returns
// NOERROR/empty). Additional RCODEs found in rtypePolicy or domainPolicy are
// also included so the map is complete regardless of configuration.
func buildPolicyRespCache() {
	rcodes := map[int]struct{}{
		dns.RcodeNotImplemented: {},
		dns.RcodeRefused:        {},
		dns.RcodeNameError:      {},
		dns.RcodeSuccess:        {},
	}
	for _, rc := range rtypePolicy {
		rcodes[rc] = struct{}{}
	}
	for _, rc := range domainPolicy {
		rcodes[rc] = struct{}{}
	}

	policyRespCache = make(map[int][]byte, len(rcodes))
	for rc := range rcodes {
		tmpl := new(dns.Msg)
		tmpl.Response = true
		tmpl.Rcode    = rc
		tmpl.Question = []dns.Question{{}}
		packed, err := tmpl.Pack()
		if err != nil {
			log.Printf("[WARN] buildPolicyRespCache: failed to pack RCODE %d: %v", rc, err)
			continue
		}
		policyRespCache[rc] = packed
	}
}

// writePolicyResp writes a pre-packed policy RCODE response, patching the
// transaction ID and question from the incoming request before sending.
// Falls back to the traditional new(dns.Msg)+SetRcode path if the template is
// not available (e.g. an unusual RCODE added at runtime).
func writePolicyResp(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	if tmpl, ok := policyRespCache[rcode]; ok {
		resp := new(dns.Msg)
		if err := resp.Unpack(tmpl); err == nil {
			resp.Id       = r.Id
			resp.Question = r.Question
			w.WriteMsg(resp)
			return
		}
	}
	resp := new(dns.Msg)
	resp.SetRcode(r, rcode)
	w.WriteMsg(resp)
}

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
// Fast path (zero allocation): when the input is already all-lowercase — ~95%
// of DNS wire names — returns a substring of the original (no copy).
//
// Slow path (one allocation): when an uppercase byte is found, allocates a
// []byte of the trimmed length and lowercases in one forward pass.
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

// sanitizeID replaces every '.' and ':' in s with '-' in a single in-place byte
// pass — one allocation instead of two chained strings.ReplaceAll calls.
func sanitizeID(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '.' || c == ':' {
			b[i] = '-'
		}
	}
	return string(b)
}

// walkDomainMaps performs a single label walk over qname and checks both
// domainPolicy and domainRoutes simultaneously — one strings.IndexByte loop
// instead of two separate walks.
//
// Policy is checked before routes at every label, consistent with domain_policy
// firing at step 0d (before domain_routes at step 3) in ProcessDNS.
func walkDomainMaps(qname string) (rcode int, blocked bool, upstream string, matched bool) {
	search := qname
	for {
		if r, ok := domainPolicy[search]; ok {
			return r, true, "", false
		}
		if u, ok := domainRoutes[search]; ok {
			return 0, false, u, true
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}
	return 0, false, "", false
}

// resolveLocalIdentity returns IPs for a queried hostname.
// qname must already be lowercase (output of lowerTrimDot). Uses
// LookupIPsByNameLower to skip the redundant strings.ToLower call that
// LookupIPsByName would apply.
func resolveLocalIdentity(qname string) []net.IP {
	if ips := LookupIPsByNameLower(qname); len(ips) > 0 {
		return ips
	}
	return LookupIPsBySuffix(qname)
}

// resolveLocalPTR returns all hostnames for an ARPA address — O(1).
func resolveLocalPTR(arpa string) []string {
	return LookupNamesByARPA(arpa)
}

// localAddrIP extracts the listener IP from a ResponseWriter's local address.
// Returns nil when the address is unavailable, unresolvable, or unspecified.
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

// ddrAddrs returns the effective IPv4 and IPv6 address slices for DDR spoofed
// responses. Falls back to the local interface address when configured slices
// are empty.
func ddrAddrs(w dns.ResponseWriter) (ipv4s, ipv6s []net.IP) {
	ipv4s = ddrIPv4
	ipv6s = ddrIPv6
	if len(ipv4s) > 0 && len(ipv6s) > 0 {
		return
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
		if local.To4() == nil {
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

	// Adaptive admission control — silently drop the query when the
	// pressure-adjusted concurrency limit is reached. No response is written,
	// so the client times out normally and retries. This avoids triggering any
	// SERVFAIL-based failure state in the client's resolver.
	if !AcquireQuery() {
		return
	}
	defer ReleaseQuery()
	IncrQueryTotal() // feeds miss-rate signal in throttle.go

	// --- OpCode guard ---
	// Only QUERY (0) is supported. All other opcodes require authoritative server
	// semantics — forwarding them would be semantically wrong and could cause
	// unintended mutations on upstream authoritative servers.
	if r.Opcode != dns.OpcodeQuery {
		writePolicyResp(w, r, dns.RcodeNotImplemented)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> OPCODE %d | UNSUPPORTED OPCODE: NOTIMP",
				protocol, clientIP, r.Opcode)
		}
		return
	}

	q          := r.Question[0]
	originalID := r.Id

	// --- QClass guard ---
	// Only class IN (Internet, 1) is supported.
	if q.Qclass != dns.ClassINET {
		writePolicyResp(w, r, dns.RcodeNotImplemented)
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
	needsClientName := logQueries || hasClientNameUpstream

	routeName := "default"
	routeIdx  := routeIdxDefault
	var mac, clientName string

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

	if needsClientName {
		if identityName := LookupNameByMACOrIP(mac, clientIP); identityName != "" && clientName == "" {
			clientName = identityName
		}
		if clientName == "" {
			if mac != "" {
				clientName = sanitizeID(mac)
			} else {
				clientName = sanitizeID(clientIP)
			}
		}
	}

	// Pre-format client identifier for log lines using a pooled strings.Builder.
	var clientID string
	if logQueries {
		sb := clientIDPool.Get().(*strings.Builder)
		sb.Reset()
		sb.WriteString(clientIP)
		sb.WriteString(" (")
		sb.WriteString(clientName)
		sb.WriteByte(')')
		clientID = sb.String()
		clientIDPool.Put(sb)
	}

	// --- 0. RType Policy ---
	if hasRtypePolicy {
		if rcode, blocked := rtypePolicy[q.Qtype]; blocked {
			writePolicyResp(w, r, rcode)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | RTYPE POLICY: %s",
					protocol, clientID, q.Name, dns.TypeToString[q.Qtype], dns.RcodeToString[rcode])
			}
			return
		}
	}

	// --- 0a. Unassigned Qtype Filter ---
	if blockUnknownQtypes {
		if _, known := dns.TypeToString[q.Qtype]; !known {
			writePolicyResp(w, r, dns.RcodeNotImplemented)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s TYPE%d | UNASSIGNED QTYPE: NOTIMP",
					protocol, clientID, q.Name, q.Qtype)
			}
			return
		}
	}

	// --- 0b. AAAA Filter ---
	if q.Qtype == dns.TypeAAAA && cfg.Server.FilterAAAA {
		writePolicyResp(w, r, dns.RcodeSuccess)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s AAAA | FILTERED", protocol, clientID, q.Name)
		}
		return
	}

	// --- 0c. Strict PTR Validation ---
	if q.Qtype == dns.TypePTR && cfg.Server.StrictPTR {
		if !isValidReversePTR(qNameTrimmed) {
			writePolicyResp(w, r, dns.RcodeNameError)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s PTR | STRICT PTR REJECTED", protocol, clientID, q.Name)
			}
			return
		}
	}

	// --- Domain maps pre-computation ---
	// Single label walk checks both domainPolicy and domainRoutes. Result consumed
	// at step 0d (policy) and step 3 (routing) — one walk instead of two.
	var (
		walkPolicyRcode   int
		walkPolicyBlocked bool
		walkRouteUpstream string
		walkRouteMatched  bool
	)
	if hasDomainPolicy || hasDomainRoutes {
		walkPolicyRcode, walkPolicyBlocked, walkRouteUpstream, walkRouteMatched = walkDomainMaps(qNameTrimmed)
	}

	// --- 0d. Domain Policy ---
	if walkPolicyBlocked {
		writePolicyResp(w, r, walkPolicyRcode)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DOMAIN POLICY: %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], dns.RcodeToString[walkPolicyRcode])
		}
		return
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
	// hostnames. All other query types return NXDOMAIN immediately.
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
	localCacheKey := DNSCacheKey{Name: qNameTrimmed, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdxLocal}
	if cachedResp := CacheGet(localCacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		cachedResp = transformResponse(cachedResp, q.Qtype, true)
		w.WriteMsg(cachedResp)
		if logQueries {
			status := "LOCAL CACHE HIT"
			if responseContainsNullIP(cachedResp) {
				status = "LOCAL CACHE HIT (NULL-IP)"
			}
			log.Printf("[DNS] [%s] %s -> %s %s | %s", protocol, clientID, q.Name, dns.TypeToString[q.Qtype], status)
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
					status := "LOCAL IDENTITY"
					if responseContainsNullIP(resp) {
						status = "LOCAL IDENTITY (NULL-IP)"
					}
					log.Printf("[DNS] [%s] %s -> %s %s | %s", protocol, clientID, q.Name, dns.TypeToString[q.Qtype], status)
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
	if walkRouteMatched {
		routeName       = walkRouteUpstream
		routeIdx        = getRouteIdx(walkRouteUpstream)
		routeOriginType = "DOMAIN"
	}

	// --- 4. Cache Lookup ---
	cacheKey := DNSCacheKey{Name: qNameTrimmed, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdx}
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		cachedResp = transformResponse(cachedResp, q.Qtype, true)
		w.WriteMsg(cachedResp)
		if logQueries {
			status := "CACHE HIT"
			if responseContainsNullIP(cachedResp) {
				status = "CACHE HIT (NULL-IP)"
			}
			log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, status)
		}
		return
	}

	// --- 5. Upstream Selection ---
	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	// --- 6. Upstream Forwarding ---
	// IncrUpstreamCall counts this as a cache miss for the throttle miss-rate
	// signal. Called here rather than inside Exchange() so stagger races
	// (which call Exchange() multiple times per query) count as one miss, not
	// several — keeping the ratio meaningful as "queries needing upstream".
	IncrUpstreamCall()
	finalResp, upstreamUsed, lastErr := raceExchange(upstreams, r, clientName)

	// --- 7. Handle Error ---
	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v",
			protocol, clientIP+" ("+clientName+")", q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 8. Cache (before transforms) ---
	CacheSet(cacheKey, finalResp)

	// --- 9. Response Transforms ---
	finalResp = transformResponse(finalResp, q.Qtype, false)

	// --- 10. Reply ---
	finalResp.Id = originalID
	w.WriteMsg(finalResp)

	if logQueries {
		status := "OK"
		if responseContainsNullIP(finalResp) {
			status = "OK (NULL-IP)"
		}
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | UPSTREAM: %s | %s",
			protocol, clientID, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, upstreamUsed, status)
	}
}

// --- Response Transform Helpers ---

// transformResponse optionally flattens CNAME chains and/or strips the authority
// and additional sections.
//
// inPlace=true:  mutates msg directly — no extra allocation. Use when the caller
//                already owns a fresh copy (e.g. all CacheGet return values).
// inPlace=false: calls msg.Copy() before mutating — use when the original must
//                be preserved (e.g. the live upstream path, where finalResp is
//                needed by CacheSet before transforms run).
func transformResponse(msg *dns.Msg, qtype uint16, inPlace bool) *dns.Msg {
	if msg == nil || (!cfg.Server.FlattenCNAME && !cfg.Server.MinimizeAnswer) {
		return msg
	}

	out := msg
	if !inPlace {
		out = msg.Copy()
	}

	if cfg.Server.FlattenCNAME {
		out = flattenCNAMEChain(out, qtype)
	}

	if cfg.Server.MinimizeAnswer {
		out.Ns    = nil
		out.Extra = nil
	}

	return out
}

// flattenCNAMEChain collapses a CNAME chain in A/AAAA responses into synthesized
// records directly under the original query name. Single pass: detects CNAME
// presence, tracks minimum TTL, and collects address RRs simultaneously.
func flattenCNAMEChain(msg *dns.Msg, qtype uint16) *dns.Msg {
	if msg.Rcode != dns.RcodeSuccess {
		return msg
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return msg
	}

	minTTL   := ^uint32(0)
	hasCNAME := false
	var addrRRs []dns.RR

	for _, rr := range msg.Answer {
		h := rr.Header()
		if h.Ttl < minTTL {
			minTTL = h.Ttl
		}
		switch h.Rrtype {
		case dns.TypeCNAME:
			hasCNAME = true
		case qtype:
			addrRRs = append(addrRRs, rr)
		}
	}

	if !hasCNAME || len(addrRRs) == 0 {
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

// --- Sinkhole Detection Helpers ---

// responseContainsNullIP checks if the DNS response contains an A or AAAA record
// pointing to an unspecified (NULL) IP address (0.0.0.0 or ::). This is a common
// indicator of an ad-blocked or sinkholed domain returned by upstream resolvers
// (or local overrides/blocklists).
//
// Zero allocations: iterates over the Answer section and uses net.IP.IsUnspecified()
// which checks the underlying byte slice directly. Loopback addresses (127.0.0.1, ::1)
// are intentionally excluded as they are technically "specified".
func responseContainsNullIP(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if r.A.IsUnspecified() {
				return true
			}
		case *dns.AAAA:
			if r.AAAA.IsUnspecified() {
				return true
			}
		}
	}
	return false
}

