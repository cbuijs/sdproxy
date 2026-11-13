/*
File:    process_defense.go
Version: 1.21.0
Last Updated: 02-Nov-2026 19:35 CET

Description:
  UDP Fragmentation and Amplification Defense.
  Extracts RFC 8482 and DNS Flag Day constraints into a modular helper to 
  harden UDP connections from being abused for volumetric denial-of-service.

Changes:
  1.21.0  - [SECURITY/FIX] Restricted `EDNS0_SUBNET` (ECS) response echoing in
            `enforceUDPDefenses` to trusted forwarder proxies (`isTrustedProxy(clientAddr)`
            when `group.ECSAction == "pass"`). Prevents untrusted clients from sending
            an `EDNS0_SUBNET` option to probe or leak the `EDNS0_SUBNET` scope returned
            by an `ecs: add` upstream.
  1.20.0  - [SECURITY/FIX] Resolved a severe Payload Truncation Vulnerability.
            `enforceUDPDefenses` previously evaluated `upstreamSize > limitApplied` 
            before the response payload was cleanly repackaged without `Extra` bounds.
  1.19.0  - [SECURITY/FIX] Restored `extRcode` bounds to `uint16` to correctly 
            satisfy the `SetExtendedRcode()` interface contract expected by `miekg/dns`.
*/

package main

import (
	"net/netip"

	"github.com/miekg/dns"
)

// enforceUDPDefenses applies RFC 8482 and DNS Flag Day 2020 constraints
// to UDP responses to mitigate amplification and fragmentation vectors.
// It simultaneously enforces strict EDNS0 normalization, nullifying cache-poisoning payloads.
// Returns the original upstream payload size and the client's advertised buffer size for telemetry.
func enforceUDPDefenses(r *dns.Msg, resp *dns.Msg, protocol string, clientAddr netip.Addr, group *UpstreamGroup) (upstreamSize int, clientAdvertised int) {
	// RFC 1035 default fallback size if no EDNS0 constraints are present
	clientAdvertised = 512
	limitApplied := 512
	var clientSentTrustedECS bool

	// Parse EDNS0 options universally to ensure TCP/DoH/DoT queries accurately
	// log their advertised buffer capacities in the Web UI telemetry, rather than 
	// erroneously falling back to 512 bytes on non-UDP connections.
	if opt := r.IsEdns0(); opt != nil {
		clientAdvertised = int(opt.UDPSize())
		if clientAdvertised >= 512 {
			limitApplied = clientAdvertised
		}

		// Only echo upstream ECS scope back when the query arrived from a trusted proxy
		// and the upstream group is configured to pass ECS.
		if group != nil && group.ECSAction == "pass" && isTrustedProxy(clientAddr) {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_SUBNET); ok {
					clientSentTrustedECS = true
					break
				}
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
	var extRcode uint16
	var edeOptions []*dns.EDNS0_EDE
	var ecsOption *dns.EDNS0_SUBNET

	// Capture the upstream's Extended RCODE, EDE, and ECS payloads natively before stripping the payload
	if upOpt := resp.IsEdns0(); upOpt != nil {
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
		respOpt.SetUDPSize(uint16(limitApplied))
		if opt.Do() {
			respOpt.SetDo()
		}
		if extRcode > 0 {
			respOpt.SetExtendedRcode(extRcode)
		}
		if len(edeOptions) > 0 {
			for _, ede := range edeOptions {
				respOpt.Option = append(respOpt.Option, ede)
			}
		}
		// Exclusively relay ECS scope if the originating trusted proxy supplied an ECS option.
		if ecsOption != nil && clientSentTrustedECS {
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
	}

	return upstreamSize, clientAdvertised
}

