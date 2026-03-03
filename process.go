/*
File: process.go
Version: 1.36.0
Last Updated: 2026-03-03 23:00 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR discovery queries, resolves local hostnames and PTR
             records, executes zero-allocation domain route matching, resolves
             {client-name} dynamically, and forwards to upstream DNS.

Changes:
  1.36.0 - [FEAT] DDR spoofed records now support multiple IP addresses per
           address family and automatic interface-IP fallback when no addresses
           are configured. ddrIPv4/ddrIPv6 are now []net.IP (set in main.go).
           localAddrIP(w) extracts the listener IP from the ResponseWriter's
           LocalAddr — works natively for UDP, TCP, and DoT; DoH and DoQ
           require the localIP field added to their ResponseWriter adapters in
           server.go v1.16.0 which populates LocalAddr() from the HTTP request
           context and the QUIC connection respectively.
           ddrAddrs(w) combines the configured slices with the per-query
           interface fallback and returns the effective (ipv4s, ipv6s) pair
           used for hints, glue, and spoofed A/AAAA records across all DDR
           paths. When both slices are non-empty the fallback is never invoked.
  1.35.1 - [FEAT] HTTPS response for DDR hostnames includes glue A/AAAA records
           in the additional section.
  1.35.0 - [FEAT] DDR hostname spoofing extended with HTTPS record support.
           Any query type other than A, AAAA, or HTTPS for a DDR hostname now
           returns NXDOMAIN immediately — never forwarded upstream.
  1.34.0 - [PERF] Feature-gated hot-path skipping via startup bool flags (set in main.go):
             hasMACRoutes:         skips LookupMAC() + MAC route lookup entirely when
                                   cfg.Routes is empty. Saves one atomic load + map read
                                   per query on purely IP-routed deployments.
             hasClientNameUpstream: combined with logQueries to gate the entire
                                   LookupNameByMACOrIP() call and all clientName string
                                   building. When both are false (log_queries: false and
                                   no {client-name} upstream) saves an atomic load +
                                   2 map reads + up to 2 string allocs per query.
             hasRtypePolicy:       skips the rtypePolicy map lookup when rtype_policy
                                   section is absent from config.
             hasDomainRoutes:      skips the getDomainRoute() label walk entirely when
                                   domain_routes section is absent.
           These flags are set once at startup in main.go and are read-only after that —
           no synchronisation needed.
  1.33.0 - [FEAT] Upstream forwarding now uses raceExchange (upstream.go v1.18.0).
           [CLEAN] Removed "context" import.
  1.32.0 - [PERF] lowerTrimDot: zero-alloc single-pass lowercase + dot trim.
           [PERF] Dropped context.WithTimeout on the upstream forwarding path.
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
// single-entry fallback — but only for the matching address family:
//   - IPv4 fallback only when LocalAddr() returns an IPv4 address.
//   - IPv6 fallback only when LocalAddr() returns a pure IPv6 address.
//
// If LocalAddr() is nil (e.g. DoH/DoQ without server.go v1.16.0) or returns an
// unspecified address, no fallback is added for that family. In that case the
// caller should have explicit IPs configured in the DDR config section.
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

	q          := r.Question[0]
	originalID := r.Id

	// lowerTrimDot: single pass, zero-alloc when already lowercase (~95% of queries).
	qNameTrimmed := lowerTrimDot(q.Name)

	// --- Identity & Routing ---
	// needsClientName collapses two independent conditions into one flag check.
	// When both logQueries and hasClientNameUpstream are false — the common case
	// in production with log_queries: false and no ControlD-style per-device URLs —
	// we skip the entire identity lookup + string building block, saving:
	//   - one LookupNameByMACOrIP call (atomic load + up to 2 map reads)
	//   - up to 2 strings.ReplaceAll calls for the MAC/IP fallback
	// per query across all UDP workers.
	needsClientName := logQueries || hasClientNameUpstream

	routeName := "default"
	routeIdx  := routeIdxDefault
	var mac, clientName string

	// MAC lookup and MAC-based routing — only when cfg.Routes has valid entries.
	// Skipping LookupMAC entirely avoids an atomic pointer load + map read per query
	// on deployments that rely solely on IP/hostname-based routing. Also skips
	// the ARP goroutine being started at all (see main.go InitARP guard).
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
	// Both are skipped when neither per-query logging nor {client-name} upstream
	// substitution needs them.
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
	// Entire map lookup skipped when rtype_policy section is absent from config,
	// which is the most common case on a plain forwarding resolver.
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

	// 1a. _dns.resolver.arpa SVCB — RFC 9462 discovery endpoint.
	if q.Qtype == dns.TypeSVCB && qNameTrimmed == "_dns.resolver.arpa" {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		if cfg.Server.DDR.Enabled {
			// Resolve effective addresses once for this query — applies configured
			// lists or falls back to the interface IP for any unconfigured family.
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

			// Glue records — one A/AAAA per configured (or derived) IP per hostname.
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

	// 1b. DDR hostname spoofing — A, AAAA, and HTTPS records for the configured
	// resolver hostnames (e.g. dns.local.net). All other query types return
	// NXDOMAIN immediately and are never forwarded upstream. These hostnames are
	// virtual — they exist only as resolver discovery glue, so leaking MX, TXT,
	// or other queries upstream serves no purpose and may confuse upstreams.
	//
	// HTTPS (TypeHTTPS, RFC 9460): synthesised SVCB-style record with the DoH
	// endpoint details. Priority 1, target "." (ServiceMode self-reference),
	// same ALPN/port/path/hints as the SVCB answer on _dns.resolver.arpa.
	//
	// NODATA vs NXDOMAIN: A with no effective IPv4, or AAAA with no effective
	// IPv6, returns NOERROR/empty (NODATA) because the name itself exists.
	// Unknown types return NXDOMAIN because there is genuinely no such data.
	if cfg.Server.DDR.Enabled && ddrHostnames[qNameTrimmed] {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		label := "DDR SPOOF"

		// Resolve effective addresses once — respects multi-IP config and
		// falls back to the query's interface address when slices are empty.
		ipv4s, ipv6s := ddrAddrs(w)

		switch q.Qtype {
		case dns.TypeA:
			for _, ip := range ipv4s {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.To4(),
				})
			}
			// len(ipv4s) == 0 → NOERROR/empty (NODATA). The name exists, just
			// no A record for this address family. resp already has Rcode NOERROR.

		case dns.TypeAAAA:
			for _, ip := range ipv6s {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip.To16(),
				})
			}
			// len(ipv6s) == 0 → NOERROR/empty (NODATA), same rationale as A.

		case dns.TypeHTTPS:
			// HTTPS RR uses the same wire format as SVCB (RFC 9460 §2.1).
			// miekg/dns represents it as dns.SVCB with Rrtype = TypeHTTPS.
			// Priority 1 + Target "." = ServiceMode self-reference: the HTTPS
			// parameters apply to the hostname itself, no further CNAME needed.
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
			// Glue records in the additional section — saves the client a
			// separate A/AAAA lookup for the same hostname.
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
			// MX, TXT, PTR, NS, CAA, … — these names are synthetic resolver glue,
			// not real hostnames. Return NXDOMAIN and stop here. Never forward.
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
	// getDomainRoute does a label walk on every call. Skip entirely when no
	// domain_routes are configured — the common case on simple setups.
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
		// This log line always fires regardless of logQueries. clientName may be ""
		// when needsClientName was false — that's fine, the IP alone is sufficient
		// for diagnosing upstream failures.
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

