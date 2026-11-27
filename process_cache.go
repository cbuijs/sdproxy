/*
File:    process_cache.go
Version: 1.37.0
Last Updated: 27-Nov-2026 13:30 CET

Description:
  Background cache revalidation and synthetic message builders.

Changes:
  1.37.0 - [FIX] Used `fullMsgRcode(msg)` in `backgroundRevalidate` for
           `isRcodeOnly` evaluation and diagnostic logging so Extended RCODEs
           (>=16) are never misclassified as `NOERROR`.
  1.36.0 - [FIX] Applied `applyRcodeOnlyWireTTL` inside `buildSynthCacheMsg`.
  1.35.0 - [FEAT] Broadened `isRcodeOnly` check in `backgroundRevalidate`.
  1.34.0 - [SECURITY/FIX] Rejected `consensus-log(...)` responses in
           `backgroundRevalidate`.
  1.33.0 - [SECURITY/FIX] Rejected synthetic `consensus(...)` responses in
           `backgroundRevalidate`.
  1.32.0 - [CRITICAL/FIX] Marked `backgroundRevalidate` context with
           `WithBypassUpstreamThrottle`.
  1.31.0 - [FIX] Replaced raw `dns.TypeToString` with `qtypeName`.
  1.30.0 - [SECURITY/FIX] Marked synthesized `EDNS0_SUBNET` with `SourceScope: 255`.
  1.29.0 - [SECURITY/FIX] Preserved `r.RecursionDesired` in `buildSynthCacheMsg`.
  1.28.0 - [SECURITY/FIX] Preserved `key.Qclass` in `backgroundRevalidate`.
*/

package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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
		msg.Rcode = action & 0x0F
		if action > 0x0F {
			opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			opt.SetUDPSize(1232)
			opt.SetExtendedRcode(uint16(action))
			msg.Extra = []dns.RR{opt}
		}
		if action == dns.RcodeNameError || action == dns.RcodeSuccess {
			SetNegativeSOA(msg, q.Name, syntheticTTL)
			applyRcodeOnlyWireTTL(msg)
		}
	}
	return msg
}

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
					SourceScope:   255,
					Address:       bgAddr.AsSlice(),
				}
				opt.Option = append(opt.Option, ecsOpt)
			}
		} else if addr, err := netip.ParseAddr(key.ECS); err == nil {
			bgAddr = addr.Unmap()
			if group.ECSAction == "pass" {
				var family uint16 = 1
				var bits uint8 = 32
				if bgAddr.Is6() {
					family = 2
					bits = 128
				}
				opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        family,
					SourceNetmask: bits,
					SourceScope:   255,
					Address:       bgAddr.AsSlice(),
				})
			}
		}
	}

	req.Extra = append(req.Extra, opt)

	bgTimeout := 10 * time.Second
	if upstreamTimeout > 0 && upstreamTimeout < bgTimeout {
		bgTimeout = upstreamTimeout
	}
	ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), bgTimeout)
	defer cancel()

	clientID := "background-worker"
	if clientName != "" {
		clientID = "background-worker (" + clientName + ")"
	}

	msg, addr, err := group.Exchange(ctx, req, clientID, clientName, bgAddr)

	isConsensusFail := strings.HasPrefix(addr, "consensus(") || strings.HasPrefix(addr, "consensus-log(")

	if logCaching {
		var status string
		if err != nil {
			status = fmt.Sprintf("FAILED: %v", err)
		} else if isConsensusFail {
			status = "CONSENSUS FAILED"
		} else if msg != nil {
			status = RcodeStr(fullMsgRcode(msg))
		}

		log.Printf("[CACHE] [BG-REVAL] %s -> %s %s | ROUTE: %s | UPSTREAM: %s | HITS: %d | %s",
			clientID, key.Name, qtypeName(key.Qtype), routeName, cleanUpstreamHost(addr), previousHits, status)
	}

	msgPool.Put(req)

	if err != nil || msg == nil || isConsensusFail {
		return
	}

	if cfg.Cache.AnswerSort == "ip-sort" {
		applyAnswerSort(msg, "ip-sort")
	}

	isRcodeOnly := len(msg.Answer) == 0 || fullMsgRcode(msg) != dns.RcodeSuccess
	if !isRcodeOnly || cacheUpstreamNeg {
		CacheSet(key, msg, routeName)
		success = true
	} else {
		success = false
	}
}
