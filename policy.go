/*
File:    policy.go
Version: 1.10.0
Last Updated: 07-Aug-2026 21:30 CEST

Description:
  Policy response synthesis and the domain-map suffix walk for sdproxy.
  Owns generateBlockMsg / writePolicyAction (the synthesised BLOCK and RCODE
  payloads), the block-action log formatter, and the label-bounded domain
  policy lookup used by the routing and filtering stages.

Changes:
  1.10.0 - [SECURITY/FIX] Finished the aliasing repair 1.9.0 claimed to have
          completed. 1.9.0 correctly cloned the operator-configured sinkhole
          addresses in the BlockActionIP branch, and its comment asserted that
          this was "the only place sdproxy embeds config-owned IPs into a wire
          response". It was not. The BlockActionNull branch — which is the
          DEFAULT block action, and therefore the overwhelmingly common one —
          continued to embed `net.IPv4zero` and `net.IPv6unspecified` directly.

          Those are not local literals: they are package-level variables inside
          the standard library's `net` package, and net.IP is a []byte. Every
          synthesised NULL-IP block therefore handed the caller a live alias of
          stdlib global state, which the response then carried into
          filterResponseIPs, transformResponse, enforceUDPDefenses and the cache
          packer. A single in-place rewrite anywhere in that chain would not
          merely corrupt sdproxy's own block address — it would corrupt
          net.IPv4zero for the entire process, including every unrelated
          consumer of the standard library.

          The exposure is strictly worse than the one 1.9.0 fixed (process-wide
          rather than config-wide) and sits on the more common code path, which
          is exactly the shape of defect that survives review: the branch that
          got the attention was the one that was already less dangerous.
          Both records now carry a copy, via the same cloneIP helper.
  1.9.0 - [SECURITY/FIX] generateBlockMsg embedded the global block IP slices
          directly into the synthesised answer records (`A: ip` /
          `AAAA: ip`, where ip is an element of globalBlockIPv4 /
          globalBlockIPv6). net.IP is a slice, so every block response handed
          the caller a live alias of process-global configuration state. No
          current code path writes through it, but the response is subsequently
          passed to filterResponseIPs, transformResponse and enforceUDPDefenses,
          and it is also placed in the cache — a single future in-place rewrite
          anywhere in that chain would silently corrupt the configured sinkhole
          address for every client from that point on. The records now carry a
          copy. Cost is one small allocation on the block path only, which is
          already synthesising an entire dns.Msg.
        - [ROBUSTNESS] writePolicyAction indexed r.Question[0] unguarded when
          synthesising the NXDOMAIN SOA. It is currently safe only because
          ProcessDNS rejects any message without exactly one question before
          this is reachable — but generateBlockMsg, ten lines above, already
          guards the identical access. The inconsistency was the bug: one of the
          two was wrong, and the unguarded one is a panic waiting for the first
          caller that does not share ProcessDNS's precondition. Now guarded, and
          the reason the guard exists is recorded so it is not "tidied" away.
  1.8.0 - [SECURITY/FIX] Set the Authoritative Answer (AA) bit natively on all
          generated blocks so strict stub resolvers and downstream firewalls do
          not discard the negative response and fall back to a secondary resolver.
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

// cloneIP returns an independent copy of ip.
//
// [SECURITY 1.9.0] net.IP is a []byte. Handing a caller an element of a
// process-global slice means handing it write access to configuration state
// shared by every subsequent query. The synthesised block path is the only
// place sdproxy embeds config-owned IPs into a wire response, so this is the
// only place the copy is required — but there it is not optional.
//
// [SECURITY 1.10.0] "config-owned" above understated the problem. The NULL-IP
// branch aliased net.IPv4zero / net.IPv6unspecified, which are owned by the
// standard library rather than by sdproxy, so the blast radius of an in-place
// rewrite was the whole process rather than this daemon's configuration. Every
// IP that reaches a synthesised answer record now goes through here, whatever
// its origin, because "who owns this slice" is precisely the question a future
// editor should not have to answer correctly for the code to stay safe.
func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

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
					// [SECURITY/FIX 1.9.0] Copy, do not alias. net.IP is a slice;
					// embedding the global element directly would hand every
					// downstream mutator (filterResponseIPs, transformResponse,
					// enforceUDPDefenses, the cache packer) a live handle on the
					// operator's configured sinkhole address.
					A: cloneIP(ip),
				})
			}
		} else if q.Qtype == dns.TypeAAAA && len(globalBlockIPv6) > 0 {
			msg.Rcode = dns.RcodeSuccess
			for _, ip := range globalBlockIPv6 {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					// [SECURITY/FIX 1.9.0] See the A-record branch above.
					AAAA: cloneIP(ip),
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
				// [SECURITY/FIX 1.10.0] net.IPv4zero is a package-level variable
				// in the standard library's net package, and net.IP is a []byte.
				// Embedding it verbatim published a writable alias of stdlib
				// global state into every NULL-IP block response — the default
				// block action, so the hottest block path in the daemon.
				//
				// This is the same defect 1.9.0 fixed for the operator-configured
				// sinkhole addresses in the BlockActionIP branch above, except
				// with a process-wide blast radius instead of a config-wide one:
				// a single in-place rewrite by any downstream mutator would
				// corrupt net.IPv4zero for every consumer in the process, not
				// just for sdproxy.
				A: cloneIP(net.IPv4zero),
			})
		} else if q.Qtype == dns.TypeAAAA {
			msg.Rcode = dns.RcodeSuccess
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				// [SECURITY/FIX 1.10.0] See the A-record branch above.
				// net.IPv6unspecified carries the identical hazard.
				AAAA: cloneIP(net.IPv6unspecified),
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

		// [ROBUSTNESS 1.9.0] Guarded. ProcessDNS enforces exactly one question
		// before any policy exit is reachable, so this cannot currently fire —
		// but generateBlockMsg twenty lines above performs the same check, and
		// an unguarded slice index that is safe only by distant precondition is
		// a panic waiting for the first caller who does not share it. The SOA is
		// simply omitted rather than synthesised against a name we do not have;
		// a bare NXDOMAIN is still a valid response.
		if action == dns.RcodeNameError && len(r.Question) > 0 {
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
		routesDone := !hasDomainRoutes || routeMatched || labels < int(domainRoutesMinLabels.Load())
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
