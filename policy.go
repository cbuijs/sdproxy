/*
File:    policy.go
Version: 1.18.0
Updated: 23-Jul-2026 13:05 CEST

Description:
  DNS query policy enforcement and domain-map lookup for sdproxy.

  Contains distinct but tightly related responsibilities:
    1. Policy response generation — dynamically constructs policy exits
       respecting the global BlockAction settings.
    2. walkDomainMaps — single label-by-label suffix walk that checks both
       domainPolicy and domainRoutes in one pass.
    3. Routing helper — getRouteIdx.
    4. Name normalisation — lowerTrimDot, isValidReversePTR.
    5. TTL capping — CapResponseTTL.

Changes:
  1.18.0 - [SECURITY/FIX] Hardened synthesized DNS block responses organically. 
           Injected the `Authoritative = true` (AA) bit into `generateBlockMsg` 
           payloads natively. This definitively prevents strict OS stub resolvers 
           from discarding the block as an unverified cache-injection attempt 
           and bypassing the firewall by querying secondary resolver targets.
  1.17.0 - [CODE SMELL/FIX] Removed obsolete `extractIPFromPTR` declaration previously 
           migrated to `process_helpers.go` natively. Resolves a build redeclaration 
           collision causing compilation failures.
  1.16.0 - [SECURITY/FIX] Eradicated a scalar tracking regression where telemetry 
           counters recorded duplicate intercepts. Disentangled `IncrPolicyBlock` 
           from the generalized `writePolicyAction` execution to ensure 
           single-origin accounting natively across the pipeline boundaries.
  1.15.0 - [SECURITY/FIX] Addressed an RFC 8020 violation during IP sinkhole blocks. 
           When `block_action: IP` is executed for an IP family missing a target 
           (e.g., missing IPv6 sinkhole on AAAA query), the system now organically 
           returns a `NODATA` (NOERROR) response instead of an `NXDOMAIN`. This ensures 
           modern OS stub resolvers correctly fallback to requesting the valid A record 
           instead of assuming the entire domain does not exist natively.
*/

package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Policy response generation
// ---------------------------------------------------------------------------

// generateBlockMsg synthesizes a DNS response specifically adhering to the 
// currently defined global 'BLOCK' action (NULL-IP, Redirect IP, or RCODE).
func generateBlockMsg(r *dns.Msg, ttl uint32) *dns.Msg {
	msg := msgPool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	msg.SetReply(r)
	msg.RecursionAvailable = true
	
	// [SECURITY/FIX] Set the Authoritative Answer (AA) bit natively on all generated blocks.
	// Strict OS stub resolvers and downstream enterprise firewalls often discard non-authoritative 
	// negative responses to prevent cache poisoning, which causes them to circumvent 
	// local blocks by querying their secondary fallback resolvers.
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
			for _, ip := range globalBlockIPv4 {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip,
				})
			}
		} else if q.Qtype == dns.TypeAAAA && len(globalBlockIPv6) > 0 {
			msg.Rcode = dns.RcodeSuccess
			for _, ip := range globalBlockIPv6 {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			}
		} else if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			// [SECURITY/FIX] Return NODATA (NOERROR + 0 Answers) instead of NXDOMAIN
			// if a block IP is missing for a specific family.
			// RFC 8020 strictly states NXDOMAIN means the entire domain does not exist.
			// Returning NXDOMAIN for an AAAA query critically breaks A-record 
			// sinkhole fallbacks organically.
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
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.IPv4zero,
			})
		} else if q.Qtype == dns.TypeAAAA {
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: net.IPv6unspecified,
			})
		} else {
			msg.Rcode = dns.RcodeNameError
		}
	}

	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		SetNegativeSOA(msg, q.Name, ttl)
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
		msg.Authoritative = true // Ensures explicit RCODE exits are also respected by strict stubs
		msg.Rcode = action

		if action == dns.RcodeNameError {
			SetNegativeSOA(msg, r.Question[0].Name, syntheticTTL)
		}
		
		PreserveEDNS0(r, msg)
	}

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
		str := dns.RcodeToString[globalBlockRcode]
		if str == "" {
			return fmt.Sprintf("RCODE:%d", globalBlockRcode)
		}
		return str
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

// domainPolicyMinLabels / domainPolicyMaxLabels bound the suffix walk for
// domainPolicySnap. Set by computeDomainLabelBounds() in init_core.go after 
// the maps are fully populated.
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
// checking domainPolicySnap and domainRoutes simultaneously in one pass.
//
// Pre-skip: leading labels are stripped until search depth ≤ max ceiling so
// sub-domain levels deeper than any configured entry are never probed.
// Floor: the walk stops before a bare TLD when no entry lives that shallow.
//
// For a pure eTLD+1 block-list (min=max=2) this results in exactly one map
// probe per query regardless of how many sub-domain labels the query has.
func walkDomainMaps(qname string) (policyAction int, policyBlocked bool, policyMatched string, routeUpstream string, routeBypassLocal bool, routeMatched bool) {
	search := qname
	labels := countDomainLabels(qname)

	dp := domainPolicySnap.Load()
	hasDP := hasDomainPolicy.Load()

	ceiling := int(domainPolicyMaxLabels.Load())
	drCeiling := int(domainRoutesMaxLabels.Load())
	if drCeiling > ceiling {
		ceiling = drCeiling
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
		if hasDP && !policyBlocked && dp != nil {
			if action, ok := (*dp)[search]; ok {
				policyAction  = action
				policyBlocked = true
				policyMatched = search
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
		labels--
		policyDone := !hasDP || policyBlocked || labels < int(domainPolicyMinLabels.Load())
		routesDone := !hasDomainRoutes || routeMatched  || labels < int(domainRoutesMinLabels.Load())
		if policyDone && routesDone {
			break
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Route index helper
// ---------------------------------------------------------------------------

// getRouteIdx returns the uint16 route index for the named upstream group.
// Falls back to routeIdxDefault when the name is not in the map.
// routeIdxDefault and routeIdxByName are declared in globals.go.
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

// CapResponseTTL sets the TTL of every RR in msg (Answer, Ns, Extra) to
// min(rr.Ttl, cap). Used by the parental control path to enforce a heartbeat
// TTL on categorised domains so TTL-compliant clients re-query frequently.
// OPT records (EDNS0) carry flags, not a TTL — always skipped.
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

