/*
File:    process_cache.go
Version: 1.22.0
Updated: 28-May-2026 13:24 CEST

Description:
  Background cache revalidation and synthetic message builders.
  Extracted from process.go to separate background worker logic and 
  message synthesis from the direct execution pipeline.

Changes:
  1.22.0 - [SECURITY/FIX] Eradicated a critical Cache Contamination regression 
           within the background revalidation worker natively. When an upstream 
           is configured to passively forward (`pass`) EDNS0 Client Subnets, 
           background workers generated fresh, isolated queries devoid of the 
           original client envelope, causing the upstream to return generic, 
           non-localized responses. The engine now organically reconstructs the 
           ECS parameter from the structural Cache Key and injects it back into 
           the background payload, guaranteeing regional CDN routing integrity 
           during asynchronous prefetch loops.
  1.21.0 - [SECURITY/FIX] Dynamically unmapped and reconstructed the `netip.Addr` 
           payload natively inside `backgroundRevalidate` utilizing the newly embedded 
           `ECS` string parameter bound to the Cache Key. Definitively ensures 
           background asynchronous prefetching loops accurately request localized, 
           subnet-specific configurations.
  1.20.0 - [DOCS] Injected verbose architectural documentation outlining the 
           `EDNS0 Client Subnet (ECS)` memory partitioning constraints natively. 
           Clarifies the zero-allocation cache mapping choices executed during 
           asynchronous prefetching.
  1.19.0 - [REFACTOR] Deduplicated the NXDOMAIN `SOA` injection payload within 
           `buildSynthCacheMsg` using the central `SetNegativeSOA` helper. Implemented 
           `RcodeStr` inside the background logger organically natively.
  1.18.0 - [SECURITY/FIX] Preserved `CheckingDisabled` (CD bit) flags natively within 
           `backgroundRevalidate` polling payloads. Neutralizes a cache-corruption 
           anomaly where asynchronous prefetching overwritten `CD=1` responses 
           with `CD=0` data, breaking downstream DNSSEC validation integrity.
*/

package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Synthetic Cache Response Builder
// ---------------------------------------------------------------------------

// buildSynthCacheMsg generates a fully compliant, self-contained DNS response
// corresponding to a local policy action (e.g., NULL-IP Blocks, NXDOMAIN). 
// These synthesized messages can be safely stored directly into the memory
// cache arrays to drastically improve repeat-query performance.
//
// [PERFORMANCE MANDATE]: Returns a `*dns.Msg` initialized from the `msgPool`. 
// The caller is strictly responsible for executing `msgPool.Put()` after caching 
// the payload to prevent severe memory leaks.
func buildSynthCacheMsg(q dns.Question, action int) *dns.Msg {
	if action == PolicyActionBlock {
		dummy := &dns.Msg{Question: []dns.Question{q}}
		return generateBlockMsg(dummy, syntheticTTL)
	}

	// [PERF] Prevent heap allocation and Garbage Collection thrashing
	msg := msgPool.Get().(*dns.Msg)
	*msg = dns.Msg{} // Zero-out dirty fields

	msg.Response           = true
	msg.RecursionAvailable = true
	msg.Question           = []dns.Question{q}
	
	if action >= 0 {
		msg.Rcode = action
		if action == dns.RcodeNameError {
			SetNegativeSOA(msg, q.Name, syntheticTTL)
		}
	}
	return msg
}

// ---------------------------------------------------------------------------
// Background Revalidation
// ---------------------------------------------------------------------------

// TriggerBackgroundRevalidate conditionally spawns the background worker.
// It strictly evaluates the revalSem semaphore BEFORE allocating a new goroutine,
// completely neutralizing GC thrashing and goroutine spikes during severe cache-miss floods.
func TriggerBackgroundRevalidate(key DNSCacheKey, routeName, clientName string, previousHits uint32, revertGate func()) {
	select {
	case revalSem <- struct{}{}:
		go func() {
			defer func() { <-revalSem }()
			backgroundRevalidate(key, routeName, clientName, previousHits, revertGate)
		}()
	default:
		// If the semaphore is fully saturated, revert the atomic prefetch lock
		// so subsequent queries can successfully retry the background operation instead
		// of letting the cache entry permanently stagnate.
		if revertGate != nil {
			revertGate()
		}
	}
}

// backgroundRevalidate operates asynchronously to refresh stale or expiring
// DNS entries natively in the background. It is shielded by `revalSem` through 
// the TriggerBackgroundRevalidate orchestrator.
func backgroundRevalidate(key DNSCacheKey, routeName, clientName string, previousHits uint32, revertGate func()) {
	// [SECURITY/FIX] Enforce boolean success flag tied to a robust defer sequence.
	// Guarantees that the atomic prefetch gate unrolls cleanly if the goroutine
	// panics natively during network exchanges or memory mapping operations.
	success := false
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in backgroundRevalidate: %v", r)
		}
		if !success && revertGate != nil {
			revertGate()
		}
	}()

	group, exists := routeUpstreams[routeName]
	if !exists || len(group.Servers) == 0 {
		group = routeUpstreams["default"]
	}
	if len(group.Servers) == 0 {
		return
	}

	req     := msgPool.Get().(*dns.Msg)
	*req     = dns.Msg{}
	req.SetQuestion(dns.Fqdn(key.Name), key.Qtype)
	req.RecursionDesired = true
	// [SECURITY/FIX] Inherit CheckingDisabled status to preserve DNSSEC integrity natively
	req.CheckingDisabled = key.CdBit 
	
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
	}
	opt.SetUDPSize(4096)

	// Ensure the DNSSEC `DO` bit matches the cached original query to accurately 
	// retrieve RRSIG and NSEC records if required.
	if key.DoBit {
		opt.SetDo()
	}

	// [ARCHITECTURE] ECS (EDNS0 Client Subnet) Cache Isolation
	// Reconstruct the client's subnet mapping natively to ensure 
	// background prefetching requests the identical localized payload.
	var bgAddr netip.Addr
	if key.ECS != "" && key.ECS != "passed-ecs" {
		if prefix, err := netip.ParsePrefix(key.ECS); err == nil {
			bgAddr = prefix.Addr()
			
			// [SECURITY/FIX] If the upstream group is configured to passively forward ('pass') 
			// the client's subnet, we MUST explicitly construct and inject the ECS parameter 
			// into the background query's EDNS0 payload natively. Since background workers 
			// generate fresh queries devoid of the original client's envelope, failing to 
			// inject this manually would result in a generic, non-subnet-optimized response 
			// violently overwriting the highly-targeted cache entry.
			if group.ECSAction == "pass" {
				var family uint16 = 1
				if bgAddr.Is6() {
					family = 2
				}
				
				ecsOpt := &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        family,
					SourceNetmask: uint8(prefix.Bits()),
					SourceScope:   0,
					Address:       bgAddr.AsSlice(),
				}
				opt.Option = append(opt.Option, ecsOpt)
			}
		}
	}

	req.Extra = append(req.Extra, opt)

	// Apply a mandatory hard timeout for background tasks to prevent stalled 
	// network connections from permanently trapping the goroutine and exhausting 
	// the revalSem semaphore.
	bgTimeout := 10 * time.Second
	if upstreamTimeout > 0 && upstreamTimeout < bgTimeout {
		bgTimeout = upstreamTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), bgTimeout)
	defer cancel()

	clientID := "background-worker"
	if clientName != "" {
		clientID = "background-worker (" + clientName + ")"
	}
	
	msg, addr, err := group.Exchange(ctx, req, clientID, clientName, bgAddr)
	
	if logCaching {
		var status string
		if err != nil {
			status = fmt.Sprintf("FAILED: %v", err)
		} else if msg != nil {
			status = RcodeStr(msg.Rcode)
		}
		
		// Log the asynchronous background query, including the popularity (HITS) of the entry
		log.Printf("[CACHE] [BG-REVAL] %s -> %s %s | ROUTE: %s | UPSTREAM: %s | HITS: %d | %s",
			clientID, key.Name, dns.TypeToString[key.Qtype], routeName, cleanUpstreamHost(addr), previousHits, status)
	}
	
	msgPool.Put(req)
	
	if err != nil || msg == nil {
		return
	}
	
	isNeg := msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
	if !isNeg || cacheUpstreamNeg {
		CacheSet(key, msg, routeName)
		
		// We mark the background task as 'successful' upon receiving and persisting 
		// any valid DNS response. This guarantees the prefetch gate remains locked naturally 
		// until the new record expires, preventing aggressive upstream query loops natively.
		success = true
	} else {
		// [SECURITY/FIX] Intentional cache decline for upstream negative responses 
		// when `cache_upstream_negative` is disabled globally.
		// We MUST unlock the prefetch gate by registering a failure, ensuring 
		// subsequent client queries can seamlessly attempt to fetch a fresh 
		// positive response instead of permanently marooning the domain.
		success = false 
	}
}

