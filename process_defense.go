/*
File:    process_defense.go
Version: 1.6.2
Updated: 07-May-2026 12:43 CEST

Description:
  UDP Fragmentation and Amplification Defense.
  Extracts RFC 8482 and DNS Flag Day constraints into a modular helper to 
  harden UDP connections from being abused for volumetric denial-of-service.

Changes:
  1.6.2   - [PERF] Eliminated a logic redundancy where the `resp.Extra` slice 
            was superfluously reassigned during active UDP truncation events.
  1.6.1   - [FIX] Resolved a compilation error where `extRcode` was incorrectly 
            cast as a `uint8` instead of `uint16` for EDNS0 parameter injection.
  1.6.0   - [SECURITY/FIX] Restored upstream Extended RCODE propagation within the 
            Cache Poisoning defense filters. Fulfills RFC 6891 requirements natively 
            to ensure DNSSEC and BADCOOKIE mechanics remain structurally intact.
  1.5.0   - [SECURITY] Hardened Cache Poisoning defenses. Completely strips ALL 
            non-OPT records from the `Extra` section to neutralize malicious 
            upstreams injecting poisoned A/AAAA payloads into downstream resolvers.
*/

package main

import "github.com/miekg/dns"

// enforceUDPDefenses applies RFC 8482 and DNS Flag Day 2020 constraints
// to UDP responses to mitigate amplification and fragmentation vectors.
// It simultaneously enforces strict EDNS0 normalization, nullifying cache-poisoning payloads.
// Returns the original upstream payload size and the client's advertised buffer size for telemetry.
func enforceUDPDefenses(r *dns.Msg, resp *dns.Msg, protocol string) (upstreamSize int, clientAdvertised int) {
	// RFC 1035 default fallback size if no EDNS0 constraints are present
	clientAdvertised = 512 
	limitApplied := 512

	// Parse EDNS0 options universally to ensure TCP/DoH/DoT queries accurately
	// log their advertised buffer capacities in the Web UI telemetry, rather than 
	// erroneously falling back to 512 bytes on non-UDP connections.
	if opt := r.IsEdns0(); opt != nil {
		clientAdvertised = int(opt.UDPSize())
		if clientAdvertised >= 512 {
			limitApplied = clientAdvertised
		}
	}

	// Truncation and Fragmentation limits apply strictly to stateless UDP payloads
	if protocol == "UDP" {
		// DNS Flag Day 2020 constraint: Cap UDP payloads at 1232 bytes natively to 
		// thwart IP fragmentation attacks and amplification reflection vectors.
		if limitApplied > 1232 {
			limitApplied = 1232 
		}
	}

	// [SECURITY] EDNS0 Normalization & Cache Poisoning Prevention
	// RFC 6891 §6.1.1 strictly dictates that OPT records must not be cached 
	// and returned verbatim. Furthermore, we must strip all unrelated records
	// from the Extra section to thwart downstream Cache Poisoning attacks.
	var respOpt *dns.OPT
	var extRcode uint16
	
	// Capture the upstream's Extended RCODE natively before stripping the payload
	if upOpt := resp.IsEdns0(); upOpt != nil {
		extRcode = uint16(upOpt.ExtendedRcode())
	}

	if opt := r.IsEdns0(); opt != nil {
		respOpt = new(dns.OPT)
		respOpt.Hdr.Name = "."
		respOpt.Hdr.Rrtype = dns.TypeOPT
		// Echo back the actual enforced buffer payload limit
		respOpt.SetUDPSize(uint16(limitApplied))
		if opt.Do() {
			respOpt.SetDo()
		}
		// [FIX] Preserve Extended RCODEs to maintain compatibility with 
		// advanced DNS mechanics (DNSSEC, BADCOOKIE) natively.
		if extRcode > 0 {
			respOpt.SetExtendedRcode(extRcode)
		}
	}
	
	// Preemptively isolate and restrict the Extra slice to strictly authorized limits
	if respOpt != nil {
		resp.Extra = []dns.RR{respOpt}
	} else {
		resp.Extra = nil
	}

	upstreamSize = resp.Len()

	if protocol == "UDP" && upstreamSize > limitApplied {
		resp.Truncated = true
		resp.Authoritative = false
		resp.Answer = nil
		resp.Ns = nil
		
		// The Extra slice is already strictly limited to the newly minted OPT record above,
		// guaranteeing Cache Poisoning and Payload Size limits are seamlessly respected without 
		// redundant slice re-allocations on the hot path.
	}

	return upstreamSize, clientAdvertised
}

