/*
File:    process_cache.go
Version: 1.25.0
Last Updated: 28-Aug-2026 16:01 CEST

Description:
  Background cache revalidation and synthetic message builders.
  Extracted from process.go to separate background worker logic and 
  message synthesis from the direct execution pipeline.

Changes:
  1.25.0 - [FEAT/FIX] Injected `rotateAnswersInPlace` evaluation natively into 
           the `CacheGetExpired` infinite-stale fallback generator. Ensures 
           that Round-Robin and IP-Sort load-balancing permutations are rigorously 
           preserved during upstream server outages.
         - [SECURITY/FIX] Aligned `buildSynthCacheMsg` to inject `SOA` bounds 
           organically on `NOERROR` (NODATA) caching structures, honoring RFC 2308.
  1.24.0 - [SECURITY/FIX] backgroundRevalidate resolved its upstream group with
           a THIRD private copy of the routeUpstreams lookup. The other two were
           unified in process_cachehit.go / process_upstream.go 1.1.0 behind
           effectiveUpstreamGroup(); leaving this one behind would have
           reintroduced exactly the drift that release removed, and here it is
           worse than on the live path.
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
		// [SECURITY/FIX] Enforce strict SOA bounds for all Negative Caching instances natively
		if action == dns.RcodeNameError || action == dns.RcodeSuccess {
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

	// [SECURITY/FIX 1.24.0] One resolver, shared with the foreground path.
	//
	// This function is the most dangerous place to get the group wrong. It
	// reconstructs a query from the cache KEY and then writes the result back
	// under that same key, so if it dials a different group than the key was
	// derived from, it overwrites a subnet- and profile-partitioned entry with
	// a payload obtained under someone else's ECS action and client-name
	// template. There is no client query to correlate the damage against — it
	// simply appears in the cache later.
	group := effectiveUpstreamGroup(routeName)
	if group == nil {
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

		// [DOCS/FIX 1.23.0] Marking the task successful suppresses the deferred
		// revertGate — nothing more.
		//
		// It is specifically NOT the case that the prefetch gate stays locked
		// until the new record expires (as this comment previously asserted).
		// CacheSet constructs a fresh cacheItem and installs it through
		// storeItem, and that new item's `prefetched` flag is zero-valued, so
		// the gate is reset outright. The old item — the one whose gate
		// revertGate closes over — is simply discarded.
		//
		// That reset is the correct behaviour: a freshly revalidated entry
		// should become eligible to prefetch again as it approaches its OWN
		// expiry. revertGate exists only to unlock the gate on the OLD item when
		// revalidation fails, so a failed attempt does not strand the entry
		// permanently un-prefetchable.
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

