/*
File:    process.go
Version: 1.41.0
Updated: 2026-03-14 15:00 CET

Description:
  Per-query DNS processing pipeline. Receives a parsed dns.Msg from server.go
  and routes it through policy checks, DDR spoofing, local identity resolution,
  cache lookup, upstream forwarding, and response transforms.

Changes:
  1.41.0 - [FIX] Bug 1: sfKey no longer includes clientName when
           hasClientNameUpstream=false. Previously every uniquely-named device
           on the LAN produced a separate singleflight key, causing N upstream
           calls instead of 1 for a shared cache miss. Now clientName is only
           included in the key when the upstream URL itself varies per client
           (i.e., when hasClientNameUpstream=true). Same fix applied to the
           backgroundRevalidate sfKey for consistency.
           [FIX] Bug 2: DDR hostname spoofing (step 1b) default case now returns
           NODATA (NOERROR + empty answer) instead of NXDOMAIN. NXDOMAIN means
           "this name does not exist", which is wrong — we actively answer
           A/AAAA/HTTPS for it. The incorrect NXDOMAIN was cached by clients and
           broke subsequent A/AAAA lookups for DDR hostnames until expiry.
           [FIX] Bug 3: DDR SVCB discovery (step 1a) now emits separate records
           for DoT (priority 2) and DoQ (priority 3), each referencing its own
           port from ddrDoTPort and ddrDoQPort respectively. Previously DoT and
           DoQ were bundled into one record sharing ddrDoTPort, so DoQ clients
           could not find the service when the ports differed.
           [FIX] Bug 5: backgroundRevalidate is now guarded by a non-blocking
           semaphore (revalSem, capacity 32). During a stale storm, excess
           goroutines are silently dropped instead of accumulating — the next
           client hit for the same stale key will either get the result of an
           in-flight revalidation (via sfGroup coalescing) or retry the semaphore.
           This keeps the goroutine count from inflating the throttle pressure
           signal and triggering unnecessary AIMD back-off on real client traffic.
  1.40.0 - [FEAT] bypass_local support: route selection (step 2) now runs BEFORE
           local identity A/AAAA/PTR resolution (step 3).
  1.39.0 - [FEAT] Singleflight coalescing and serve-stale support.
  1.38.0 - [FIX] walkDomainMaps: most-specific-wins semantics enforced.
  1.37.0 - [FIX] DDR step 1a gated on cfg.Server.DDR.Enabled.
  1.36.0 - [FEAT] DDR hostname spoofing extended with HTTPS record support.
  1.34.0 - [PERF] Feature-gated hot-path skipping via startup bool flags.
  1.33.0 - [FEAT] Upstream forwarding uses raceExchange.
  1.32.0 - [PERF] lowerTrimDot: zero-alloc single-pass lowercase + dot trim.
  1.31.0 - [PERF] Single LookupNameByMACOrIP call, routeIdx uint8 tracking.
  1.30.0 - [FEAT] RType Policy (step 0): immediate RCODE by query type.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// logQueries is the hot-path logging gate. Set once at startup from config.
// When false, per-query log lines are suppressed entirely — no mutex, no
// fmt.Sprintf, no I/O on the happy path.
var logQueries bool

// clientIDPool holds reusable strings.Builder values for building the
// "ip (name)" client identifier that appears in every log line.
var clientIDPool = sync.Pool{New: func() any { return new(strings.Builder) }}

// sfGroup coalesces concurrent cache-miss queries for the same
// (qname, qtype, routeIdx, [clientName]) tuple into a single upstream call.
// All waiters receive the same *dns.Msg and call .Copy() to get their own
// mutable instance before patching the transaction ID.
//
// The group is also used by backgroundRevalidate, so an in-flight
// revalidation and a simultaneous fresh-miss for the same key merge
// automatically — no duplicate upstream call, no race on CacheSet.
var sfGroup singleflight.Group

// sfResult carries the upstream response and the server address that served it.
// Wrapped in a struct because singleflight.Do returns (any, error, bool).
type sfResult struct {
	msg  *dns.Msg
	addr string
}

// revalSem is a non-blocking semaphore that caps simultaneous background
// revalidation goroutines at 32.
//
// Without this guard, a stale storm (many unique entries expiring at the same
// moment) can spawn hundreds of goroutines at once. Those goroutines are not
// counted against queryLimit, but they DO inflate runtime.NumGoroutine(), which
// feeds the throttler's goroutine-spike signal and can trigger AIMD back-off on
// perfectly healthy client traffic. 32 is a deliberately generous cap — on a
// home router with stale_ttl enabled, simultaneous stale entries in the dozens
// is already a very busy scenario.
//
// When the semaphore is full the goroutine is simply dropped. The stale response
// was already written to the client. sfGroup coalescing ensures that the next
// client hit for the same stale key will either coalesce with an already-running
// revalidation or, if all semaphore slots are free again, start a fresh one.
const revalSemCap = 32

var revalSem = make(chan struct{}, revalSemCap)

// policyRespCache maps DNS RCODE integers to a pre-packed *dns.Msg template.
// Built at startup by buildPolicyRespCache(). Policy fast-paths unpack a copy
// of the template and patch the transaction ID + question section — avoiding
// new(dns.Msg) + SetRcode + WriteMsg allocations on every policy hit.
var policyRespCache map[int][]byte

// buildPolicyRespCache pre-packs a minimal response template for every RCODE
// that can be returned by a policy check. Called once from main().
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
func writePolicyResp(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	tmpl, ok := policyRespCache[rcode]
	if !ok {
		dns.HandleFailed(w, r)
		return
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(tmpl); err != nil {
		dns.HandleFailed(w, r)
		return
	}
	resp.Id = r.Id
	if len(r.Question) > 0 {
		resp.Question = r.Question[:1]
	}
	w.WriteMsg(resp)
}

// lowerTrimDot converts a DNS name to lowercase and strips any trailing dot
// in a single pass. Zero allocations when the input is already lowercase.
func lowerTrimDot(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			clean = false
			break
		}
	}
	if clean {
		return strings.TrimSuffix(s, ".")
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return strings.TrimSuffix(string(b), ".")
}

// isValidReversePTR reports whether name is a valid reverse-lookup PTR label.
func isValidReversePTR(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa") ||
		strings.HasSuffix(name, ".ip6.arpa")
}

// walkDomainMaps performs a single label-by-label suffix walk over qname,
// checking both domainPolicy and domainRoutes simultaneously.
//
// Most-specific-wins semantics: once a match is found in either map, further
// suffix iterations cannot overwrite it.
func walkDomainMaps(qname string) (policyRcode int, policyBlocked bool, routeUpstream string, routeBypassLocal bool, routeMatched bool) {
	search := qname
	for {
		if hasDomainPolicy && !policyBlocked {
			if rc, ok := domainPolicy[search]; ok {
				policyRcode   = rc
				policyBlocked = true
			}
		}
		if hasDomainRoutes && !routeMatched {
			if entry, ok := domainRoutes[search]; ok {
				routeUpstream    = entry.upstream
				routeBypassLocal = entry.bypassLocal
				routeMatched     = true
			}
		}
		if policyBlocked && routeMatched {
			return
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}
	return
}

// getRouteIdx returns the precomputed uint8 index for a named upstream group.
func getRouteIdx(name string) uint8 {
	if idx, ok := routeIdxByName[name]; ok {
		return idx
	}
	return routeIdxDefault
}

// resolveLocalIdentity returns IPs for a queried hostname from the identity tables.
// qname must already be lowercase (output of lowerTrimDot).
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
// Returns nil when the address is unavailable or unspecified.
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

// ddrAddrs returns the effective IPv4 and IPv6 address slices for DDR responses.
// Falls back to the local interface address when configured slices are empty.
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

// responseContainsNullIP reports whether any A or AAAA record in msg carries
// an unspecified address (0.0.0.0 or ::) — a common blocklist sentinel.
func responseContainsNullIP(msg *dns.Msg) bool {
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

// transformResponse optionally flattens CNAME chains and/or strips authority
// and additional sections (minimize_answer).
// inPlace=true:  mutates msg directly (caller owns the copy).
// inPlace=false: calls msg.Copy() first (legacy callers, if any).
func transformResponse(msg *dns.Msg, qtype uint16, inPlace bool) *dns.Msg {
	if !cfg.Server.FlattenCNAME && !cfg.Server.MinimizeAnswer {
		return msg
	}
	out := msg
	if !inPlace {
		out = msg.Copy()
	}
	if cfg.Server.FlattenCNAME && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		flattenCNAME(out)
	}
	if cfg.Server.MinimizeAnswer {
		out.Ns    = nil
		out.Extra = nil
	}
	return out
}

// flattenCNAME collapses a CNAME chain in out.Answer into a single synthesised
// address record under the original query name. TTL is set to the chain minimum.
func flattenCNAME(out *dns.Msg) {
	if len(out.Answer) < 2 {
		return
	}
	first, ok := out.Answer[0].(*dns.CNAME)
	if !ok {
		return
	}
	queryName := first.Hdr.Name
	minTTL    := first.Hdr.Ttl
	finalIPs  := make([]dns.RR, 0, len(out.Answer)-1)

	for _, rr := range out.Answer[1:] {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
		switch r := rr.(type) {
		case *dns.A:
			cp := *r
			cp.Hdr.Name = queryName
			cp.Hdr.Ttl  = minTTL
			finalIPs = append(finalIPs, &cp)
		case *dns.AAAA:
			cp := *r
			cp.Hdr.Name = queryName
			cp.Hdr.Ttl  = minTTL
			finalIPs = append(finalIPs, &cp)
		}
	}
	if len(finalIPs) == 0 {
		return
	}
	for _, rr := range finalIPs {
		rr.Header().Ttl = minTTL
	}
	out.Answer = finalIPs
}

// backgroundRevalidate refreshes a stale cache entry in the background.
// Called from ProcessDNS after the stale response has already been written
// to the client — zero additional latency for the end-user.
//
// Bug 5 fix: a non-blocking semaphore (revalSem) caps the number of concurrent
// revalidation goroutines at revalSemCap. When the cap is reached the goroutine
// exits immediately; the stale response has already been served and the next
// client hit will retry. This prevents goroutine accumulation during stale storms
// from inflating the throttler's goroutine-spike pressure signal.
//
// Bug 1 fix: the sfKey only includes clientName when hasClientNameUpstream=true.
// Without this, every uniquely-named device missing the same cache entry would
// generate its own upstream call, bypassing singleflight coalescing entirely.
//
// sfGroup coalesces simultaneous stale hits on the same key into a single
// upstream call. The sfKey format matches the hot-path key in ProcessDNS so
// that a background revalidation and a concurrent fresh-miss coalesce too.
//
// routeUpstreams is read-only after startup — no lock needed.
func backgroundRevalidate(key DNSCacheKey, routeName, clientName string) {
	// Non-blocking acquire — drop the goroutine if the semaphore is full.
	select {
	case revalSem <- struct{}{}:
	default:
		return
	}
	defer func() { <-revalSem }()

	upstreams := routeUpstreams[routeName]
	if len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}
	if len(upstreams) == 0 {
		return
	}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(key.Name), key.Qtype)
	req.Question[0].Qclass = key.Qclass
	req.RecursionDesired    = true

	// Bug 1 fix: only vary the key by clientName when the upstream URL actually
	// differs per client. Otherwise all clients share the same revalidation call.
	sfClientName := ""
	if hasClientNameUpstream {
		sfClientName = clientName
	}
	sfKey := fmt.Sprintf("%s\x00%d\x00%d\x00%s", key.Name, key.Qtype, key.RouteIdx, sfClientName)

	sfGroup.Do(sfKey, func() (any, error) { //nolint:errcheck — revalidation errors are silent
		IncrUpstreamCall()
		msg, _, err := raceExchange(upstreams, req, clientName)
		if err == nil && msg != nil {
			CacheSet(key, msg, routeName)
		}
		return nil, nil
	})
}

// ProcessDNS is the main query handler. Called by all server transports.
func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	// Adaptive admission control — silently drop when pressure limit is reached.
	if !AcquireQuery() {
		return
	}
	defer ReleaseQuery()
	IncrQueryTotal()

	// Only QUERY (opcode 0) is supported.
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

	// Only class IN (Internet, 1) is supported.
	if q.Qclass != dns.ClassINET {
		writePolicyResp(w, r, dns.RcodeNotImplemented)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s CLASS%d | UNSUPPORTED CLASS: NOTIMP",
				protocol, clientIP, q.Name, q.Qclass)
		}
		return
	}

	qNameTrimmed := lowerTrimDot(q.Name)

	// --- 0a. RType Policy ---
	if hasRtypePolicy {
		if rcode, ok := rtypePolicy[q.Qtype]; ok {
			writePolicyResp(w, r, rcode)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | RTYPE POLICY: %s",
					protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], dns.RcodeToString[rcode])
			}
			return
		}
	}

	// --- 0b. Unassigned Qtype Filter ---
	if blockUnknownQtypes {
		if _, known := dns.TypeToString[q.Qtype]; !known {
			writePolicyResp(w, r, dns.RcodeNotImplemented)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s TYPE%d | UNASSIGNED QTYPE: NOTIMP",
					protocol, clientIP, q.Name, q.Qtype)
			}
			return
		}
	}

	// --- 0c. AAAA Filter ---
	if q.Qtype == dns.TypeAAAA && cfg.Server.FilterAAAA {
		writePolicyResp(w, r, dns.RcodeSuccess)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s AAAA | FILTERED", protocol, clientIP, q.Name)
		}
		return
	}

	// --- 0d. Strict PTR Validation ---
	if q.Qtype == dns.TypePTR && cfg.Server.StrictPTR {
		if !isValidReversePTR(qNameTrimmed) {
			writePolicyResp(w, r, dns.RcodeNameError)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s PTR | STRICT PTR REJECTED", protocol, clientIP, q.Name)
			}
			return
		}
	}

	// --- Domain maps pre-computation ---
	// Single label walk checks both domainPolicy and domainRoutes at once.
	var (
		walkPolicyRcode      int
		walkPolicyBlocked    bool
		walkRouteUpstream    string
		walkRouteBypassLocal bool
		walkRouteMatched     bool
	)
	if hasDomainPolicy || hasDomainRoutes {
		walkPolicyRcode, walkPolicyBlocked, walkRouteUpstream, walkRouteBypassLocal, walkRouteMatched = walkDomainMaps(qNameTrimmed)
	}

	// --- 0e. Domain Policy ---
	if walkPolicyBlocked {
		writePolicyResp(w, r, walkPolicyRcode)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DOMAIN POLICY: %s",
				protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], dns.RcodeToString[walkPolicyRcode])
		}
		return
	}

	// --- 1. DDR Spoofing & Interception ---
	// Both sub-steps are gated on cfg.Server.DDR.Enabled. When DDR is disabled,
	// all queries fall through to the normal cache + upstream pipeline.

	// 1a. _dns.resolver.arpa SVCB — RFC 9462 discovery endpoint.
	//
	// Bug 3 fix: DoT and DoQ now get separate SVCB records with their own ports.
	// RFC 9460 §2.4.1 states that each SVCB record describes a single service
	// endpoint; combining protocols with different port numbers in one record is
	// incorrect and prevents DoQ clients from connecting when ports differ.
	//
	// Priority layout (lowest = preferred):
	//   1 — DoH  (h2/h3/http1.1)
	//   2 — DoT  (dot, RFC 7858)
	//   3 — DoQ  (doq, RFC 9250)
	if cfg.Server.DDR.Enabled && q.Qtype == dns.TypeSVCB && qNameTrimmed == "_dns.resolver.arpa" {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		ipv4s, ipv6s := ddrAddrs(w)

		for host := range ddrHostnames {
			target := dns.Fqdn(host)

			// DoH record — priority 1.
			svcbDoH := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
				Priority: 1,
				Target:   target,
			}
			svcbDoH.Value = append(svcbDoH.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3", "http/1.1"}})
			svcbDoH.Value = append(svcbDoH.Value, &dns.SVCBPort{Port: ddrDoHPort})
			svcbDoH.Value = append(svcbDoH.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
			if len(ipv4s) > 0 {
				svcbDoH.Value = append(svcbDoH.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
			}
			if len(ipv6s) > 0 {
				svcbDoH.Value = append(svcbDoH.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
			}
			resp.Answer = append(resp.Answer, svcbDoH)

			// DoT record — priority 2. Separate from DoQ so each has its own port.
			svcbDoT := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
				Priority: 2,
				Target:   target,
			}
			svcbDoT.Value = append(svcbDoT.Value, &dns.SVCBAlpn{Alpn: []string{"dot"}})
			svcbDoT.Value = append(svcbDoT.Value, &dns.SVCBPort{Port: ddrDoTPort})
			if len(ipv4s) > 0 {
				svcbDoT.Value = append(svcbDoT.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
			}
			if len(ipv6s) > 0 {
				svcbDoT.Value = append(svcbDoT.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
			}
			resp.Answer = append(resp.Answer, svcbDoT)

			// DoQ record — priority 3. Own port (ddrDoQPort, set from listen_doq).
			svcbDoQ := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
				Priority: 3,
				Target:   target,
			}
			svcbDoQ.Value = append(svcbDoQ.Value, &dns.SVCBAlpn{Alpn: []string{"doq"}})
			svcbDoQ.Value = append(svcbDoQ.Value, &dns.SVCBPort{Port: ddrDoQPort})
			if len(ipv4s) > 0 {
				svcbDoQ.Value = append(svcbDoQ.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
			}
			if len(ipv6s) > 0 {
				svcbDoQ.Value = append(svcbDoQ.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
			}
			resp.Answer = append(resp.Answer, svcbDoQ)
		}

		// Glue records — one A/AAAA per configured DDR hostname.
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

		w.WriteMsg(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY",
				protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		}
		return
	}

	// 1b. DDR hostname spoofing — A, AAAA, and HTTPS for configured resolver hostnames.
	//
	// Bug 2 fix: the default case now returns NODATA (NOERROR + empty answer)
	// instead of NXDOMAIN. NXDOMAIN asserts "this name does not exist", which is
	// wrong — we actively answer A/AAAA/HTTPS for this name. An incorrect NXDOMAIN
	// gets cached by resolvers and breaks subsequent A/AAAA lookups for DDR
	// hostnames until the negative cache entry expires.
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
			// Bug 2 fix: this name exists (we serve A/AAAA/HTTPS for it), it just
			// has no records of this type. Return NODATA = NOERROR + empty answer.
			// Do NOT return NXDOMAIN — that would be cached and break A/AAAA lookups.
			resp.SetRcode(r, dns.RcodeSuccess)
			label = "DDR NODATA"
		}

		w.WriteMsg(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | %s",
				protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], label)
		}
		return
	}

	// --- 2. Client Identity ---
	// clientMAC is resolved first — used here for client naming and in step 3
	// for MAC-based route selection, avoiding a double ARP table read.
	// clientName is always resolved regardless of bypass_local: it is needed
	// for log lines and {client-name} upstream URL substitution.
	needsClientName := logQueries || hasClientNameUpstream
	var clientMAC, clientName string

	if hasMACRoutes {
		clientMAC = LookupMAC(clientIP)
	}
	if needsClientName {
		clientName = LookupNameByMACOrIP(clientMAC, clientIP)
	}

	// Build the "ip (name)" string used in every log line.
	// Only allocated when logQueries is true.
	var clientID string
	if logQueries {
		if clientName != "" {
			sb := clientIDPool.Get().(*strings.Builder)
			sb.Reset()
			sb.WriteString(clientIP)
			sb.WriteString(" (")
			sb.WriteString(clientName)
			sb.WriteByte(')')
			clientID = sb.String()
			clientIDPool.Put(sb)
		} else {
			clientID = clientIP
		}
	}

	// --- 3. Route Selection (runs BEFORE local identity resolution) ---
	// Route selection must precede the local identity step so that the route's
	// bypass_local flag is known in time to conditionally skip local answers.
	routeName   := "default"
	routeIdx    := routeIdxDefault
	bypassLocal := false

	// MAC-based route — highest priority.
	if hasMACRoutes && clientMAC != "" {
		if route, ok := macRoutes[clientMAC]; ok {
			if route.Upstream != "" {
				routeName = route.Upstream
				routeIdx  = getRouteIdx(route.Upstream)
			}
			if route.ClientName != "" {
				clientName = route.ClientName
			}
			bypassLocal = route.BypassLocal
		}
	}

	// Domain-based route — overrides MAC route for domain-specific queries.
	routeOriginType := "CLIENT"
	if walkRouteMatched {
		routeName       = walkRouteUpstream
		routeIdx        = getRouteIdx(walkRouteUpstream)
		routeOriginType = "DOMAIN"
		bypassLocal     = walkRouteBypassLocal
	}

	// --- 4. Local A/AAAA/PTR responses from identity tables ---
	// Skipped entirely when the selected route has bypass_local: true.
	if !bypassLocal {
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			if ips := resolveLocalIdentity(qNameTrimmed); len(ips) > 0 {
				resp := new(dns.Msg)
				resp.SetReply(r)
				resp.Authoritative = true
				for _, ip := range ips {
					v4 := ip.To4()
					if q.Qtype == dns.TypeA && v4 != nil {
						resp.Answer = append(resp.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   v4,
						})
					} else if q.Qtype == dns.TypeAAAA && v4 == nil {
						resp.Answer = append(resp.Answer, &dns.AAAA{
							Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
							AAAA: ip,
						})
					}
				}
				if len(resp.Answer) > 0 {
					w.WriteMsg(resp)
					if logQueries {
						log.Printf("[DNS] [%s] %s -> %s %s | LOCAL IDENTITY",
							protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
					}
					return
				}
			}
		case dns.TypePTR:
			if names := resolveLocalPTR(qNameTrimmed); len(names) > 0 {
				resp := new(dns.Msg)
				resp.SetReply(r)
				resp.Authoritative = true
				for _, name := range names {
					resp.Answer = append(resp.Answer, &dns.PTR{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
						Ptr: dns.Fqdn(name),
					})
				}
				w.WriteMsg(resp)
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s PTR | LOCAL PTR",
						protocol, clientID, q.Name)
				}
				return
			}
		}
	}

	// --- 5. Cache Lookup ---
	cacheKey := DNSCacheKey{Name: qNameTrimmed, Qtype: q.Qtype, Qclass: q.Qclass, RouteIdx: routeIdx}
	if cachedResp, isStale := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID
		cachedResp = transformResponse(cachedResp, q.Qtype, true) // inPlace OK — we own the copy
		w.WriteMsg(cachedResp)
		if isStale {
			go backgroundRevalidate(cacheKey, routeName, clientName)
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | STALE (revalidating)",
					protocol, clientID, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName)
			}
		} else {
			if logQueries {
				status := "CACHE HIT"
				if responseContainsNullIP(cachedResp) {
					status = "CACHE HIT (NULL-IP)"
				}
				log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | %s",
					protocol, clientID, q.Name, dns.TypeToString[q.Qtype], routeOriginType, routeName, status)
			}
		}
		return
	}

	// --- 6. Upstream Selection ---
	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	// --- 7. Upstream Forwarding — coalesced via singleflight ---
	//
	// Bug 1 fix: only include clientName in the key when the upstream URL
	// actually varies per client (hasClientNameUpstream=true). When false, all
	// clients with different names would produce distinct sfKeys and each miss
	// a separate upstream call, defeating coalescing entirely.
	sfClientName := ""
	if hasClientNameUpstream {
		sfClientName = clientName
	}
	sfKey := fmt.Sprintf("%s\x00%d\x00%d\x00%s", qNameTrimmed, q.Qtype, routeIdx, sfClientName)

	v, sfErr, _ := sfGroup.Do(sfKey, func() (any, error) {
		IncrUpstreamCall()
		msg, addr, err := raceExchange(upstreams, r, clientName)
		if err != nil || msg == nil {
			return sfResult{}, err
		}
		CacheSet(cacheKey, msg, routeName)
		return sfResult{msg: msg, addr: addr}, nil
	})

	var finalResp *dns.Msg
	var upstreamUsed string
	if sfErr == nil {
		if res, ok := v.(sfResult); ok && res.msg != nil {
			finalResp    = res.msg.Copy()
			upstreamUsed = res.addr
		}
	}

	// --- 8. Handle Error ---
	if finalResp == nil {
		failLabel := clientIP
		if clientName != "" {
			failLabel = clientIP + " (" + clientName + ")"
		}
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE(%s): %s | FAILED: %v",
			protocol, failLabel, q.Name, dns.TypeToString[q.Qtype],
			routeOriginType, routeName, sfErr)
		dns.HandleFailed(w, r)
		return
	}

	// --- 9. Response Transforms ---
	finalResp = transformResponse(finalResp, q.Qtype, true)

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

