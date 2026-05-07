/*
File:    process_cache.go
Version: 1.14.0
Updated: 06-May-2026 10:28 CEST

Description:
  Background cache revalidation and synthetic message builders.
  Extracted from process.go to separate background worker logic and 
  message synthesis from the direct execution pipeline.

Changes:
  1.14.0 - [SECURITY/FIX] Addressed a background prefetch deadlocking flaw. 
           If `cache_upstream_negative` is disabled, intentional cache declines 
           (e.g., ignoring upstream NXDOMAIN replies) previously failed to execute 
           the `revertGate()` callback. This permanently marooned the domain from 
           future background prefetching loops. The gate now reliably unlocks natively.
  1.13.0 - [SECURITY/FIX] Resolved a severe infinite-loop vulnerability where 
           explicitly uncached negative upstream responses (e.g., NXDOMAIN) 
           erroneously executed the `revertGate()` callback. This permanently 
           unlocked the atomic prefetch gate, causing subsequent client hits 
           on the stale memory record to perpetually spam the upstream provider. 
           The prefetch lock now correctly remains sealed on all valid downstream 
           payload receipts natively.
  1.12.0 - [SECURITY/FIX] Resolved a severe deadlock vulnerability inside the 
           background revalidation pipeline. If an upstream exchange or cache-set 
           panicked mid-flight, the `revertGate` callback was bypassed, marooning 
           the domain and permanently locking its prefetch bounds. A robust `defer` 
           recovery utilizing a boolean `success` flag now guarantees the gate 
           unrolls reliably under all failure conditions.
  1.11.0 - [PERF] Eliminated goroutine heap allocations during severe cache-miss floods. 
           `TriggerBackgroundRevalidate` now rigorously tests the semaphore pipeline 
           prior to spawning the background revalidation thread.
  1.10.0 - [SECURITY/FIX] Addressed a deadlocking flaw where intentional negative caching 
           bypasses (e.g., ignoring upstream NXDOMAIN replies) failed to execute the 
           `revertGate()` callback. This permanently marooned the domain from future 
           background prefetching loops.
*/

package main

import (
	"context"
	"fmt"
	"log"
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
			msg.Ns = []dns.RR{&dns.SOA{
				Hdr:     dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: syntheticTTL},
				Ns:      "ns.sdproxy.",
				Mbox:    "hostmaster.sdproxy.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  syntheticTTL,
			}}
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
	
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
	}
	opt.SetUDPSize(4096)

	// Ensure the DNSSEC `DO` bit matches the cached original query to accurately 
	// retrieve RRSIG and NSEC records if required.
	if key.DoBit {
		opt.SetDo()
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

	msg, addr, err := group.Exchange(ctx, req, clientID, clientName)
	
	if logQueries {
		var status string
		if err != nil {
			status = fmt.Sprintf("FAILED: %v", err)
		} else if msg != nil {
			status = dns.RcodeToString[msg.Rcode]
			if status == "" {
				status = fmt.Sprintf("RCODE:%d", msg.Rcode)
			}
		}
		
		// Log the asynchronous background query, including the popularity (HITS) of the entry
		log.Printf("[DNS] [BG-REVAL] %s -> %s %s | ROUTE: %s | UPSTREAM: %s | HITS: %d | %s",
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

