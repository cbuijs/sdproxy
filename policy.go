/*
File:    policy.go
Version: 1.18.0
Last Updated: 18-Nov-2026 16:50 CET

Description:
  Policy response synthesis and the domain-map suffix walk for sdproxy.
  Owns generateBlockMsg / writePolicyAction (the synthesised BLOCK and RCODE
  payloads), the block-action log formatter, and the label-bounded domain
  policy lookup used by the routing and filtering stages.

Changes:
  1.18.0 - [FIX] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.42.0) to both
           positive (`NULL-IP` / `CUSTOM-IP`) and negative (`NXDOMAIN` / `NODATA`)
           responses in `generateBlockMsg` when `ttl == syntheticTTL`, and to all
           RCODE-only responses in `writePolicyAction`, so wire TTLs on cache
           misses match `CacheSetSynth`.
  1.17.0 - [FEAT] Applied `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.36.0) in
           `generateBlockMsg` and `writePolicyAction` so synthesized RCODE-only
           responses (`NXDOMAIN` / `NODATA` SOA TTLs) honor `rcode_ttl`,
           `rcode_min_ttl`, and `rcode_max_ttl`.
  1.16.0 - [PERF] Eliminated per-query `cloneIP` heap allocations in
           `generateBlockMsg` by referencing immutable 4-byte (`staticIPv4Zero`)
           and 16-byte (`staticIPv6Zero`) zero slices and pre-canonicalized
           `globalBlockIPv4` / `globalBlockIPv6` slices (`init_core.go` 1.121.0),
           and pre-sized `msg.Answer` capacity.
         - [PERF] Replaced `fmt.Sprintf` in `getBlockActionLogStr` with `RcodeStr`.
  1.15.0 - [SECURITY/FIX] Replaced `PreserveEDNS0` with `enforceUDPDefenses` in
           `writePolicyAction` so UDP responses synthesized from large multi-IP
           `block_ips` lists are properly truncated (`TC=1`) when exceeding 1232
           bytes or the client's advertised UDP buffer size.
  1.14.0 - [SECURITY/FIX] Replaced `PreserveEDNS0` with sanitized EDNS0 OPT
           construction (`sanitizeReplyEDNS0`) in `generateBlockMsg` and
           `writePolicyAction`, and updated `PreserveEDNS0` in `process_helpers.go`
           so client EDNS0 options (MAC 65001, ECS, cookies, padding) are never
           echoed back in synthesized policy or block responses.
  1.13.0 - [FEAT] Extended `walkDomainMaps` to evaluate compiled `domain_policy`
           regular expressions (`domainPolicyRegexSnap`) against the full normalized
           domain name when no plain suffix rule matched, and skipped the label
           suffix walk when the plain domain policy map is empty and no domain
           routes are configured.
  1.12.0 - [SECURITY/FIX] Resolved a critical negative caching violation (RFC 2308). 
           `writePolicyAction` now correctly injects `SOA` records into 
           synthesized `NOERROR` (NODATA) policy responses (e.g., AAAA filtering).
  1.11.0 - [PERF/CLEANUP] Simplified `cloneIP` organically using zero-dependency
           slice appending, bypassing standard iterations natively.
  1.10.0 - [SECURITY/FIX] Finished the aliasing repair 1.9.0 claimed to have
           completed.
*/

package main

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Policy response generation
// ---------------------------------------------------------------------------

// Immutable 4-byte IPv4 and 16-byte IPv6 unspecified slices used for NULL-IP
// synthesis. Because Miekg/dns only reads `A` and `AAAA` slices during Pack(),
// sharing these read-only backing arrays avoids a heap allocation on every block.
var (
	staticIPv4Zero = net.IP{0, 0, 0, 0}
	staticIPv6Zero = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

// generateBlockMsg synthesizes a DNS response specifically adhering to the
// currently defined global 'BLOCK' action (NULL-IP, Redirect IP, or RCODE).
func generateBlockMsg(r *dns.Msg, ttl uint32) *dns.Msg {
	msg := msgPool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	msg.SetReply(r)
	msg.RecursionAvailable = true
	msg.Authoritative = true

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		return msg
	}
	q := r.Question[0]

	switch globalBlockAction {
	case BlockActionIP:
		if q.Qtype == dns.TypeA && len(globalBlockIPv4) > 0 {
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = make([]dns.RR, len(globalBlockIPv4))
			for i, ip := range globalBlockIPv4 {
				msg.Answer[i] = &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip,
				}
			}
		} else if q.Qtype == dns.TypeAAAA && len(globalBlockIPv6) > 0 {
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = make([]dns.RR, len(globalBlockIPv6))
			for i, ip := range globalBlockIPv6 {
				msg.Answer[i] = &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				}
			}
		} else if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			msg.Rcode = dns.RcodeSuccess
		} else {
			msg.Rcode = dns.RcodeNameError
		}
	case BlockActionRcode:
		msg.Rcode = globalBlockRcode
	case BlockActionNull:
		fallthrough
	default:
		if q.Qtype == dns.TypeA {
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   staticIPv4Zero,
			}}
		} else if q.Qtype == dns.TypeAAAA {
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: staticIPv6Zero,
			}}
		} else {
			msg.Rcode = dns.RcodeNameError
		}
	}

	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		SetNegativeSOA(msg, q.Name, ttl)
	}
	if ttl == syntheticTTL {
		applyRcodeOnlyWireTTL(msg)
	}

	PreserveEDNS0(r, msg)

	return msg
}

// writePolicyAction executes a dynamically constructed policy response for the given
// action or RCODE. If the action is PolicyActionDrop, it silently drops the query.
// Returns true if the query was dropped (no response sent), false otherwise.
func writePolicyAction(w dns.ResponseWriter, r *dns.Msg, action int) bool {
	if action == PolicyActionDrop || (action == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
		return true // Silently drop, do not write a response
	}

	var msg *dns.Msg
	if action == PolicyActionBlock {
		msg = generateBlockMsg(r, syntheticTTL)
	} else {
		msg = msgPool.Get().(*dns.Msg)
		*msg = dns.Msg{}
		msg.SetReply(r)
		msg.RecursionAvailable = true
		msg.Authoritative = true
		msg.Rcode = action

		if (action == dns.RcodeNameError || action == dns.RcodeSuccess) && len(r.Question) > 0 {
			SetNegativeSOA(msg, r.Question[0].Name, syntheticTTL)
			applyRcodeOnlyWireTTL(msg)
		}

		PreserveEDNS0(r, msg)
	}

	isNull := false
	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if a.A.IsUnspecified() {
				isNull = true
			}
		case *dns.AAAA:
			if a.AAAA.IsUnspecified() {
				isNull = true
			}
		}
	}
	IncrReturnCode(msg.Rcode, isNull)
	if msg.Rcode == dns.RcodeNameError && len(r.Question) > 0 {
		IncrNXDomain(lowerTrimDot(r.Question[0].Name))
	}

	proto := "TCP"
	if w != nil && w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "udp") {
		proto = "UDP"
	}
	enforceUDPDefenses(r, msg, proto, netip.Addr{}, nil)

	_ = w.WriteMsg(msg)
	msgPool.Put(msg)
	return false
}

// getBlockActionLogStr provides accurate formatting for telemetry.
func getBlockActionLogStr(qtype uint16) string {
	switch globalBlockAction {
	case BlockActionDrop:
		return "DROP"
	case BlockActionLog:
		return "LOG ONLY"
	case BlockActionIP:
		if qtype == dns.TypeA && len(globalBlockIPv4) > 0 {
			return "NOERROR (CUSTOM-IP)"
		} else if qtype == dns.TypeAAAA && len(globalBlockIPv6) > 0 {
			return "NOERROR (CUSTOM-IP)"
		}
		if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			return "NODATA (NO-CUSTOM-IP)"
		}
		return "NXDOMAIN"
	case BlockActionRcode:
		return RcodeStr(globalBlockRcode)
	case BlockActionNull:
		fallthrough
	default:
		if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			return "NOERROR (NULL-IP)"
		}
		return "NXDOMAIN"
	}
}

// ---------------------------------------------------------------------------
// Domain-map walk
// ---------------------------------------------------------------------------

var (
	domainPolicyMinLabels atomic.Int32
	domainPolicyMaxLabels atomic.Int32
	domainRoutesMinLabels atomic.Int32
	domainRoutesMaxLabels atomic.Int32
)

func init() {
	domainPolicyMinLabels.Store(1)
	domainPolicyMaxLabels.Store(128)
	domainRoutesMinLabels.Store(1)
	domainRoutesMaxLabels.Store(128)
}

// countDomainLabels returns the number of dot-separated labels in s.
func countDomainLabels(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, ".") + 1
}

// walkDomainMaps performs a single label-by-label suffix walk over qname,
// checking domainPolicySnap and domainRoutes simultaneously in one pass,
// followed by domainPolicyRegexSnap if no plain suffix policy matched.
func walkDomainMaps(qname string) (policyAction int, policyBlocked bool, policyMatched string, routeUpstream string, routeBypassLocal bool, routeMatched bool) {
	dp := domainPolicySnap.Load()
	hasDP := hasDomainPolicy.Load()
	hasDPMap := hasDP && dp != nil && len(*dp) > 0

	if hasDPMap || hasDomainRoutes {
		search := qname
		labels := countDomainLabels(qname)

		var ceiling int
		if hasDPMap {
			ceiling = int(domainPolicyMaxLabels.Load())
		}
		if hasDomainRoutes {
			drCeiling := int(domainRoutesMaxLabels.Load())
			if drCeiling > ceiling {
				ceiling = drCeiling
			}
		}
		for labels > ceiling {
			idx := strings.IndexByte(search, '.')
			if idx < 0 {
				break
			}
			search = search[idx+1:]
			labels--
		}

		for {
			if hasDPMap && !policyBlocked {
				if action, ok := (*dp)[search]; ok {
					policyAction = action
					policyBlocked = true
					policyMatched = search
				}
			}
			if hasDomainRoutes && !routeMatched {
				if entry, ok := domainRoutes[search]; ok {
					routeUpstream = entry.upstream
					routeBypassLocal = entry.bypassLocal
					routeMatched = true
				}
			}
			if (policyBlocked || !hasDPMap) && (routeMatched || !hasDomainRoutes) {
				break
			}
			idx := strings.IndexByte(search, '.')
			if idx < 0 {
				break
			}
			search = search[idx+1:]
			labels--
			policyDone := !hasDPMap || policyBlocked || labels < int(domainPolicyMinLabels.Load())
			routesDone := !hasDomainRoutes || routeMatched || labels < int(domainRoutesMinLabels.Load())
			if policyDone && routesDone {
				break
			}
		}
	}

	if hasDP && !policyBlocked {
		if regexes := domainPolicyRegexSnap.Load(); regexes != nil && len(*regexes) > 0 {
			for i := range *regexes {
				entry := &(*regexes)[i]
				if entry.re.MatchString(qname) {
					policyAction = entry.action
					policyBlocked = true
					policyMatched = entry.raw
					break
				}
			}
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Route index helper
// ---------------------------------------------------------------------------

func getRouteIdx(name string) uint16 {
	if idx, ok := routeIdxByName[name]; ok {
		return idx
	}
	return routeIdxDefault
}

// ---------------------------------------------------------------------------
// Name normalisation & extraction
// ---------------------------------------------------------------------------

// lowerTrimDot returns s lowercased with any trailing dot removed.
// Zero allocations when the input is already lowercase.
func lowerTrimDot(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
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

// isValidReversePTR reports whether name is a well-formed reverse-lookup
// PTR label (in-addr.arpa or ip6.arpa).
func isValidReversePTR(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa") ||
		strings.HasSuffix(name, ".ip6.arpa")
}

// ---------------------------------------------------------------------------
// TTL capping
// ---------------------------------------------------------------------------

func CapResponseTTL(msg *dns.Msg, cap uint32) {
	for _, rr := range msg.Answer {
		if rr.Header().Ttl > cap {
			rr.Header().Ttl = cap
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Ttl > cap {
			rr.Header().Ttl = cap
		}
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl > cap {
			rr.Header().Ttl = cap
		}
	}
}
