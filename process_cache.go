/*
File:    process_cache.go
Version: 1.29.0
Last Updated: 25-Oct-2026 15:40 CET

Description:
  Background cache revalidation and synthetic message builders.
  Extracted from process.go to separate background worker logic and 
  message synthesis from the direct execution pipeline.

Changes:
  1.29.0 - [SECURITY/FIX] Updated `buildSynthCacheMsg` to accept `r *dns.Msg` and
           preserve `r.RecursionDesired` (alongside `Authoritative = true`) on all
           synthesized cache messages.
  1.28.0 - [SECURITY/FIX] Preserved `key.Qclass` in `backgroundRevalidate` instead
           of hardcoding `dns.ClassINET` via `SetQuestion`.
  1.27.0 - [SECURITY/FIX] Preserved `key.RecursionDesired` in `backgroundRevalidate`.
  1.26.0 - [SECURITY/FIX] Addressed an undeclared memory leak within the error 
           handling branches natively.
  1.25.0 - [FEAT/FIX] Injected `rotateAnswersInPlace` evaluation natively into 
           the `CacheGetExpired` infinite-stale fallback generator.
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
// corresponding to a local policy action (e.g., NULL-IP Blocks, NXDOMAIN),
// preserving the client's RecursionDesired flag.
func buildSynthCacheMsg(r *dns.Msg, q dns.Question, action int) *dns.Msg {
	rd := true
	if r != nil {
		rd = r.RecursionDesired
	}

	if action == PolicyActionBlock {
		var dummy dns.Msg
		dummy.RecursionDesired = rd
		dummy.Question = []dns.Question{q}
		return generateBlockMsg(&dummy, syntheticTTL)
	}

	msg := msgPool.Get().(*dns.Msg)
	*msg = dns.Msg{}

	msg.Response = true
	msg.Authoritative = true
	msg.RecursionDesired = rd
	msg.RecursionAvailable = true
	msg.Question = []dns.Question{q}

	if action >= 0 {
		msg.Rcode = action
		if action == dns.RcodeNameError || action == dns.RcodeSuccess {
			SetNegativeSOA(msg, q.Name, syntheticTTL)
		}
	}
	return msg
}

// ---------------------------------------------------------------------------
// Background Revalidation
// ---------------------------------------------------------------------------

func TriggerBackgroundRevalidate(key DNSCacheKey, routeName, clientName string, previousHits uint32, revertGate func()) {
	select {
	case revalSem <- struct{}{}:
		go func() {
			defer func() { <-revalSem }()
			backgroundRevalidate(key, routeName, clientName, previousHits, revertGate)
		}()
	default:
		if revertGate != nil {
			revertGate()
		}
	}
}

func backgroundRevalidate(key DNSCacheKey, routeName, clientName string, previousHits uint32, revertGate func()) {
	success := false
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in backgroundRevalidate: %v", r)
		}
		if !success && revertGate != nil {
			revertGate()
		}
	}()

	group := effectiveUpstreamGroup(routeName)
	if group == nil {
		return
	}

	req := msgPool.Get().(*dns.Msg)
	*req = dns.Msg{}
	req.SetQuestion(dns.Fqdn(key.Name), key.Qtype)
	if key.Qclass != 0 {
		req.Question[0].Qclass = key.Qclass
	}
	req.RecursionDesired = key.RecursionDesired
	req.CheckingDisabled = key.CdBit

	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
	}
	opt.SetUDPSize(4096)

	if key.DoBit {
		opt.SetDo()
	}

	var bgAddr netip.Addr
	if key.ECS != "" && key.ECS != "passed-ecs" {
		if prefix, err := netip.ParsePrefix(key.ECS); err == nil {
			bgAddr = prefix.Addr()

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
		success = true
	} else {
		success = false
	}
}
