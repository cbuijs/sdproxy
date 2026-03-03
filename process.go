/*
File: process.go
Version: 1.33.0
Last Updated: 2026-03-03 20:00 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.33.0 - [FEAT] Upstream forwarding now uses raceExchange (upstream.go v1.18.0):
           staggered parallel queries with health-aware stagger skipping. Replaces
           the sequential for-loop that waited for a full timeout on each upstream
           before trying the next. Eliminates "context deadline exceeded" in practice.
           [CLEAN] Removed "context" import — no longer used directly in process.go.
           context.WithCancel is now managed inside raceExchange (upstream.go).
  1.32.0 - [PERF] lowerTrimDot: replaces strings.ToLower + strings.TrimSuffix with
           a single pass that is zero-allocation when the name is already lowercase
           (the ~95% case for DNS wire names). Only allocates on the rare slow path
           where uppercase bytes are found. Eliminates two heap allocations per query.
           [PERF] Dropped context.WithTimeout wrapper on the upstream forwarding path.
  1.31.0 - [PERF] Single LookupNameByMACOrIP call, routeIdx uint8 tracking.
  1.30.0 - [FEAT] RType Policy (step 0): immediate RCODE by query type.
           Local-only names get NXDOMAIN for non-A/AAAA/PTR types.
  1.28.0 - [FEAT] Per-query log lines include resolved client name.
  1.27.0 - [PERF] Eliminated redundant dns.Msg.Copy() on forwarding path.
           [PERF] All per-query log.Printf calls gated behind logQueries bool.
  1.26.0 - [FEAT] Added transformResponse, flattenCNAMEChain, and minimizeAnswer.
  1.25.0 - [FEAT] Strict PTR address syntax validation.
  1.23.0 - [FEAT] Added AAAA filter (step 0a).
  1.22.0 - [FIX]  Local identity and PTR answers now cached with route key "local".
  1.21.0 - [FEAT] resolveLocalIdentity falls back to LookupIPsBySuffix.
  1.20.0 - [FIX]  resolveLocalIdentity exact full-name lookup only.
  1.19.0 - [FIX]  DDR SVCB ports now use ddrDoHPort/ddrDoTPort globals.
  1.18.0 - [FIX]  DDR glue records deduplicated. ALPN updated with "http/1.1".
  1.17.0 - [PERF] O(1) identity lookups via pre-computed reverse maps.
           Struct-based DNS cache key replaces fmt.Sprintf.
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
	// Fast path: scan for any uppercase byte
	for i := 0; i < end; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			// Slow path: found uppercase — allocate and finish the rest
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
	// Fast path: already lowercase, just trim — zero allocation
	return s[:end]
}

// getDomainRoute performs ultra-fast zero-allocation suffix matching.
// Walks the domain label by label using index arithmetic.
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

func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q          := r.Question[0]
	originalID := r.Id

	// lowerTrimDot: single pass, zero-alloc when already lowercase (~95% of queries).
	// Replaces the old strings.ToLower + strings.TrimSuffix pair (2 allocs per query).
	qNameTrimmed := lowerTrimDot(q.Name)

	// --- Identity Extraction (early — so every log line can show the client name) ---
	// All lookups are now lock-free via atomic.Pointer snapshots:
	//   LookupMAC        -> (*arpSnap.Load())[ip]           (was arpMu.RLock)
	//   LookupNameByMACOrIP -> identSnap.Load() + 2 map reads (was identMu.RLock)
	mac          := LookupMAC(clientIP)
	identityName := LookupNameByMACOrIP(mac, clientIP)
	routeName    := "default"
	routeIdx     := routeIdxDefault
	clientName   := ""

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
	if clientName == "" {
		clientName = identityName
	}
	if clientName == "" {
		if mac != "" {
			clientName = strings.ReplaceAll(mac, ":", "-")
		} else {
			clientName = strings.ReplaceAll(strings.ReplaceAll(clientIP, ".", "-"), ":", "-")
		}
	}

	// Pre-format client identifier for log lines — only when logging is enabled
	var clientID string
	if logQueries {
		clientID = clientIP + " (" + clientName + ")"
	}

	// --- 0. RType Policy ---
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

	// --- 0a. AAAA Filter ---
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

	// --- 0b. Strict PTR Validation ---
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
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
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
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | DDR SPOOF", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
			}
			return
		}
	}

	// --- 2. Local Hosts/Leases Interception (A, AAAA, PTR — and NXDOMAIN for everything else) ---
	localCacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdxLocal}
	if cachedResp := CacheGet(localCacheKey); cachedResp != nil {
		cachedResp.Id = originalID
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
		// Any other query type (MX, TXT, SRV, NS, CNAME, HTTPS, …):
		// If the name is known locally — return NXDOMAIN immediately.
		// See v1.30.0 changelog for the RFC rationale.
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
	if domainUpstream, matched := getDomainRoute(qNameTrimmed); matched {
		routeName        = domainUpstream
		routeIdx         = getRouteIdx(domainUpstream)
		routeOriginType  = "DOMAIN"
	}

	// --- 4. Cache Lookup ---
	cacheKey := DNSCacheKey{Name: q.Name, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdx}
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID
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
	// raceExchange: staggered parallel queries when upstream_stagger_ms > 0.
	// First successful response wins, losers are canceled via context.
	// Falls back to sequential when stagger is 0 or single upstream.
	// Health tracking automatically skips stagger delay for broken upstreams.
	finalResp, upstreamUsed, lastErr := raceExchange(upstreams, r, clientName)

	// --- 7. Handle Error ---
	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v",
			protocol, clientIP+" ("+clientName+")", q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 8. Response Transforms ---
	finalResp = transformResponse(finalResp, q.Qtype)

	// --- 9. Cache & Reply ---
	CacheSet(cacheKey, finalResp)
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

