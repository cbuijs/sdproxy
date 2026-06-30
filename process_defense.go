/*
File:    process_defense.go
Version: 1.19.0
Updated: 04-Jun-2026 14:22 CEST

Description:
  UDP Fragmentation and Amplification Defense.
  Extracts RFC 8482 and DNS Flag Day constraints into a modular helper to 
  harden UDP connections from being abused for volumetric denial-of-service.

Changes:
  1.19.0  - [SECURITY/FIX] Restored `extRcode` bounds to `uint16` to correctly 
            satisfy the `SetExtendedRcode()` interface contract expected by `miekg/dns`.
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
	var clientSentECS bool

	// Parse EDNS0 options universally to ensure TCP/DoH/DoT queries accurately
	// log their advertised buffer capacities in the Web UI telemetry, rather than 
	// erroneously falling back to 512 bytes on non-UDP connections.
	if opt := r.IsEdns0(); opt != nil {
		clientAdvertised = int(opt.UDPSize())
		if clientAdvertised >= 512 {
			limitApplied = clientAdvertised
		}
		
		// Introspect the initial payload structurally to verify authentic ECS origins
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_SUBNET); ok {
				clientSentECS = true
				break
			}
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
	var extRcode uint16 // [FIX] Align exactly with miekg/dns bounds natively
	var edeOptions []*dns.EDNS0_EDE
	var ecsOption *dns.EDNS0_SUBNET
	
	// Capture the upstream's Extended RCODE, EDE, and ECS payloads natively before stripping the payload
	if upOpt := resp.IsEdns0(); upOpt != nil {
		// [SECURITY/FIX] Extract ExtendedRcode securely as uint16
		extRcode = uint16(upOpt.ExtendedRcode())
		for _, o := range upOpt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok {
				edeOptions = append(edeOptions, ede)
			}
			if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
				ecsOption = ecs
			}
		}
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
		// [FEAT] Preserve Extended DNS Errors (EDE - RFC 8914) natively to securely 
		// retain upstream block/filter notifications (e.g., from Quad9 or ControlD).
		if len(edeOptions) > 0 {
			for _, ede := range edeOptions {
				respOpt.Option = append(respOpt.Option, ede)
			}
		}
		// [FEAT] Preserve EDNS0 Client Subnet (ECS) scopes naturally to broadcast 
		// upstream network boundaries (RFC 7871) back to requesting clients securely.
		// Exclusively relayed if the originating client supplied an ECS footprint natively.
		if ecsOption != nil && clientSentECS {
			respOpt.Option = append(respOpt.Option, ecsOption)
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

