/*
File:    rfc_compliance.go
Version: 1.16.0
Last Updated: 18-Nov-2026 13:00 CET

Description:
  RFC Compliance & CNAME Indirection validation engine for sdproxy.

  Enforces DNS protocol and RR-type structural invariants across:
    - NS  (RFC 2181 §10.3, RFC 1035 §3.3.11): NS target must not point to a CNAME/DNAME
          alias or an IP literal; also verifies the queried domain/apex's authoritative
          NS targets.
    - MX  (RFC 2181 §10.3, RFC 5321 §5.1, RFC 7505): MX target must not point to a
          CNAME/DNAME alias or an IP literal, and Null MX (0 .) must be exclusive.
    - SRV (RFC 2782): SRV target must not point to a CNAME/DNAME alias or IP literal.
    - SOA (RFC 1035 / RFC 2181): SOA MNAME must not point to a CNAME/DNAME alias or IP literal.
    - PTR (RFC 2181 §10.2): PTR target must not point to a CNAME/DNAME alias or IP literal.
    - CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1): CNAME exclusivity (cannot coexist with other
          RR types at the same owner name), single CNAME per owner, no loops/self-references,
          no IP literal targets, and optional cross-apex CNAME enforcement in strict mode.

Changes:
  1.16.0 - [SECURITY/FIX] Checked `exceeded` returned by `walkBailiwickChain` in
           `chainBufInit` (`inspectMsgRFCCompliance`), `probeTargetHasCNAME`, and
           `probeDomainNSIndirection` so responses exceeding the 16-hop / 64-name
           alias chain ceiling are explicitly flagged as `RFC 1034 CNAME/DNAME Chain Exceeded`
           violations rather than silently truncating the chain.
  1.15.0 - [REFACTOR/PERF] Switched `rfc_compliance.go` to the shared
           `probeVerdictCache` (`for_sale.go` 1.18.0) and `walkBailiwickChain`
           (`cache_rw.go` 1.35.0), eliminating duplicated shard maps, sweepers,
           and CNAME/DNAME chain loops.
  1.14.0 - [PERF/FIX] Guarded `CacheSetSynth` in `applyRFCComplianceVerdict` with
           `!cacheHit` (matching `applyIDNHomographVerdict`) so cached
           `rfcShards` verdicts do not redundantly repack and overwrite `shards`
           on every hit.
  1.13.0 - [PERF/FIX] Added `allowNetworkProbe` to `probeTargetHasCNAME` and
           `inspectMsgRFCCompliance` so cache-hit inspections (`cacheHit == true`)
           only consult `rfcShards` and the main DNS cache lookaside without
           firing synchronous outbound network probes on a cache hit.
  1.12.0 - [FIX] Recorded `IncrPolicyBlock()` and `RecordBlockEvent()` in
           `applyRFCComplianceVerdict` when `rfc_compliance.action: "LOG"` or
           `block_action: "LOG"` is active so Web UI analytics (`Top Blocked`,
           `Top Block Reasons`, and total block counters) accurately reflect
           audit-mode detections.
  1.11.0 - [SECURITY/FIX] Added multi-hop DNAME cycle detection and end-to-end
           chain target resolution (`resolveCNAMEChainTarget`) on `dns.DNAME`
           records in `inspectMsgRFCCompliance`.
  1.10.0 - [SECURITY/FIX] Expanded `resolveCNAMEChainTarget` to accept in-packet
           `DNAME` rules (`dnames [][2]string`) so multi-hop `CNAME -> DNAME -> CNAME`
           chains are resolved end-to-end.
  1.9.0  - [SECURITY/FIX] Added RFC 6672 `DNAME` exclusivity and single-DNAME-per-owner
           validation in `inspectMsgRFCCompliance`.
  1.8.0  - [SECURITY/FIX] Extended in-packet `DNAME` synthesis (`inPacketCNAMEs` in
           `inspectMsgRFCCompliance` and `nsCNAMEs` in `probeDomainNSIndirection`).
  1.7.0  - [SECURITY/FIX] Enforced `isInBailiwick(nsOwner, true)` when checking
           whether an Answer CNAME coexists with an Authority `SOA`/`NS`.
*/

package main

import (
	"context"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

const (
	rfcMinTTL          = 300 * time.Second
	rfcMaxTTL          = 3600 * time.Second
	rfcNegTTL          = 900 * time.Second
	rfcFailTTL         = 60 * time.Second
	rfcProbeBudget     = 1500 * time.Millisecond
	rfcMaxTargetProbes = 4
)

var (
	rfcAction     string
	rfcActionCode int
	rfcStrict     bool

	rfcCheckNS    bool
	rfcCheckMX    bool
	rfcCheckSRV   bool
	rfcCheckSOA   bool
	rfcCheckPTR   bool
	rfcCheckCNAME bool

	rfcCache   *probeVerdictCache
	rfcSFGroup singleflight.Group
)

// InitRFCCompliance initializes the RFC compliance validation subsystem.
func InitRFCCompliance() {
	act := strings.ToUpper(strings.TrimSpace(cfg.Server.RFCCompliance.Action))
	switch act {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		hasRFCCompliance = false
		rfcAction = "DISABLED"
		return
	case "LOG":
		rfcAction = "LOG"
		rfcActionCode = 0
	case "BLOCK":
		rfcAction = "BLOCK"
		rfcActionCode = PolicyActionBlock
	default:
		if logSystem {
			log.Printf("[RFC-COMPLIANCE] WARNING: unknown server.rfc_compliance.action %q — disabling feature", cfg.Server.RFCCompliance.Action)
		}
		hasRFCCompliance = false
		rfcAction = "DISABLED"
		return
	}

	rfcStrict = cfg.Server.RFCCompliance.Strict

	rfcCheckNS = false
	rfcCheckMX = false
	rfcCheckSRV = false
	rfcCheckSOA = false
	rfcCheckPTR = false
	rfcCheckCNAME = false

	var activeChecks []string
	if len(cfg.Server.RFCCompliance.Checks) == 0 {
		rfcCheckNS = true
		rfcCheckMX = true
		rfcCheckSRV = true
		rfcCheckSOA = true
		rfcCheckCNAME = true
		activeChecks = []string{"NS", "MX", "SRV", "SOA", "CNAME"}
	} else {
		seen := make(map[string]bool)
		for _, raw := range cfg.Server.RFCCompliance.Checks {
			for _, tok := range strings.Split(raw, ",") {
				c := strings.ToUpper(strings.TrimSpace(tok))
				if c == "" || seen[c] {
					continue
				}
				switch c {
				case "ALL", "*":
					rfcCheckNS, rfcCheckMX, rfcCheckSRV, rfcCheckSOA, rfcCheckPTR, rfcCheckCNAME = true, true, true, true, true, true
					seen["NS"], seen["MX"], seen["SRV"], seen["SOA"], seen["PTR"], seen["CNAME"] = true, true, true, true, true, true
					activeChecks = []string{"NS", "MX", "SRV", "SOA", "PTR", "CNAME"}
				case "NS":
					rfcCheckNS = true
					seen[c] = true
					activeChecks = append(activeChecks, c)
				case "MX":
					rfcCheckMX = true
					seen[c] = true
					activeChecks = append(activeChecks, c)
				case "SRV":
					rfcCheckSRV = true
					seen[c] = true
					activeChecks = append(activeChecks, c)
				case "SOA":
					rfcCheckSOA = true
					seen[c] = true
					activeChecks = append(activeChecks, c)
				case "PTR":
					rfcCheckPTR = true
					seen[c] = true
					activeChecks = append(activeChecks, c)
				case "CNAME":
					rfcCheckCNAME = true
					seen[c] = true
					activeChecks = append(activeChecks, c)
				}
			}
		}
	}

	if len(activeChecks) == 0 {
		hasRFCCompliance = false
		rfcAction = "DISABLED"
		return
	}

	rfcCache = newProbeVerdictCache()
	hasRFCCompliance = true

	if logSystem {
		log.Printf("[RFC-COMPLIANCE] Active (Action: %s, Strict Cross-Apex: %v, Checks: %s)",
			rfcAction, rfcStrict, strings.Join(activeChecks, ", "))
	}
}

func getRFCCache(key probeCacheKey, now int64) (probeCacheEntry, bool) {
	return rfcCache.Get(key, now)
}

func setRFCCache(key probeCacheKey, entry probeCacheEntry, now int64) {
	rfcCache.Set(key, entry, now)
}

func sameDomainApex(a, b string) bool {
	ca := lowerTrimDot(a)
	cb := lowerTrimDot(b)
	if ca == "" || cb == "" {
		return false
	}
	if ca == cb {
		return true
	}
	apexA, _ := extractETLDPlusOne(ca)
	apexB, _ := extractETLDPlusOne(cb)
	return apexA != "" && apexA == apexB
}

func isIndirectionActionable(refName, cnameTarget string) bool {
	if !rfcStrict {
		return true
	}
	return !sameDomainApex(refName, cnameTarget)
}

func isIPLiteralHost(h string) bool {
	clean := lowerTrimDot(h)
	if clean == "" {
		return false
	}
	if _, err := netip.ParseAddr(clean); err == nil {
		return true
	}
	return false
}

// resolveCNAMEChainTarget walks an in-packet CNAME/DNAME map up to 8 hops to find
// the first cross-apex target (when rfcStrict is enabled) or the final target,
// while detecting any multi-hop CNAME/DNAME cycle.
func resolveCNAMEChainTarget(cnames map[string]string, dnames [][2]string, startOwner, refOwner string) (target string, found bool, hasLoop bool) {
	step := func(name string) (string, bool) {
		if len(cnames) > 0 {
			if next, ok := cnames[name]; ok && next != "" {
				return next, true
			}
		}
		for _, dn := range dnames {
			if hasDotSuffix(name, dn[0]) {
				prefix := name[:len(name)-len(dn[0])]
				synth := lowerTrimDot(prefix + dn[1])
				if len(synth) <= 253 && synth != "" {
					return synth, true
				}
			}
		}
		return "", false
	}

	cur, ok := step(startOwner)
	if !ok {
		return "", false, false
	}
	var visited [10]string
	visited[0] = startOwner
	visitedCount := 1
	last := cur

	for hop := 0; hop < 8; hop++ {
		for i := 0; i < visitedCount; i++ {
			if visited[i] == cur {
				return cur, true, true
			}
		}
		if visitedCount < len(visited) {
			visited[visitedCount] = cur
			visitedCount++
		}
		if rfcStrict && (!sameDomainApex(refOwner, cur) || !sameDomainApex(startOwner, cur)) {
			last = cur
		}
		next, exists := step(cur)
		if !exists {
			break
		}
		if !rfcStrict {
			last = next
		}
		cur = next
	}
	return last, true, false
}

// probeTargetHasCNAME resolves `target` (A query) via main cache lookaside or
// upstream SingleFlight probe to determine whether `target` is a CNAME/DNAME alias.
func probeTargetHasCNAME(parentCtx context.Context, group *UpstreamGroup, routeIdx uint16, target, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies, allowNetworkProbe bool) (hasCNAME bool, cnameTarget string) {
	cleanTarget := lowerTrimDot(target)
	if cleanTarget == "" || len(cleanTarget) > 253 {
		return false, ""
	}

	now := time.Now().UnixNano()
	ck := probeCacheKey{routeIdx: routeIdx, kind: 2, domain: cleanTarget}
	if entry, ok := getRFCCache(ck, now); ok {
		return entry.positive, entry.secondary
	}

	if parentCtx.Err() != nil {
		return false, ""
	}

	fqdn := dns.Fqdn(cleanTarget)
	cNameKey, ecsKey := probeCacheKeyPartitions(group, clientName, clientAddr, ecsAddr, ecsPrefix)
	effectiveDo := doBit || (group != nil && group.RequireDNSSECAD)

	extractAlias := func(msg *dns.Msg) (bool, string, time.Duration) {
		if msg == nil {
			return false, "", rfcFailTTL
		}
		if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
			return false, "", rfcFailTTL
		}

		var chainBuf [64]string
		validNames, _, exceeded := walkBailiwickChain(msg.Answer, fqdn, 8, &chainBuf)
		if exceeded {
			return false, "", rfcFailTTL
		}

		minTTL := uint32(3600)
		var cnameMap map[string]string
		var dnameList [][2]string

		for _, rr := range msg.Answer {
			if !isValidBailiwickName(validNames, strings.ToLower(rr.Header().Name)) {
				continue
			}
			switch r := rr.(type) {
			case *dns.CNAME:
				if cnameMap == nil {
					cnameMap = make(map[string]string, 4)
				}
				cnameMap[lowerTrimDot(r.Hdr.Name)] = lowerTrimDot(r.Target)
				if r.Hdr.Ttl > 0 && r.Hdr.Ttl < minTTL {
					minTTL = r.Hdr.Ttl
				}
			case *dns.DNAME:
				ownerClean := lowerTrimDot(r.Hdr.Name)
				dTarg := lowerTrimDot(r.Target)
				dnameList = append(dnameList, [2]string{ownerClean, dTarg})
				if r.Hdr.Ttl > 0 && r.Hdr.Ttl < minTTL {
					minTTL = r.Hdr.Ttl
				}
			}
		}

		if resolved, ok, _ := resolveCNAMEChainTarget(cnameMap, dnameList, cleanTarget, cleanTarget); ok {
			ttl := time.Duration(minTTL) * time.Second
			if ttl < rfcMinTTL {
				ttl = rfcMinTTL
			} else if ttl > rfcMaxTTL {
				ttl = rfcMaxTTL
			}
			return true, resolved, ttl
		}
		return false, "", rfcNegTTL
	}

	if !allowNetworkProbe {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
			for _, tryDO := range []bool{effectiveDo, false} {
				mainKey := DNSCacheKey{
					Name:             cleanTarget,
					ClientName:       cNameKey,
					ECS:              ecsKey,
					Qtype:            qtype,
					Qclass:           dns.ClassINET,
					RouteIdx:         routeIdx,
					DoBit:            tryDO,
					CdBit:            cdBit,
					BypassGlobal:     bypassGlobal,
					BypassPolicies:   bypassPolicies,
					BypassLocal:      bypassLocal,
					RecursionDesired: true,
				}
				pooled := msgPool.Get().(*dns.Msg)
				*pooled = dns.Msg{}
				if _, _, cacheOK, _ := CacheGet(mainKey, fqdn, pooled); cacheOK && !pooled.Authoritative {
					isAlias, aliasTarg, ttl := extractAlias(pooled)
					msgPool.Put(pooled)
					entry := probeCacheEntry{
						positive:   isAlias,
						secondary:  aliasTarg,
						expireNano: time.Now().Add(ttl).UnixNano(),
					}
					setRFCCache(ck, entry, now)
					return entry.positive, entry.secondary
				}
				msgPool.Put(pooled)
				if !effectiveDo {
					break
				}
			}
		}
		return false, ""
	}

	sfKey := "t|" + itoa64(int64(routeIdx)) + "|" + cleanTarget
	resCh := rfcSFGroup.DoChan(sfKey, func() (any, error) {
		nowInner := time.Now().UnixNano()
		if entry, ok := getRFCCache(ck, nowInner); ok {
			return entry, nil
		}

		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
			for _, tryDO := range []bool{effectiveDo, false} {
				mainKey := DNSCacheKey{
					Name:             cleanTarget,
					ClientName:       cNameKey,
					ECS:              ecsKey,
					Qtype:            qtype,
					Qclass:           dns.ClassINET,
					RouteIdx:         routeIdx,
					DoBit:            tryDO,
					CdBit:            cdBit,
					BypassGlobal:     bypassGlobal,
					BypassPolicies:   bypassPolicies,
					BypassLocal:      bypassLocal,
					RecursionDesired: true,
				}
				pooled := msgPool.Get().(*dns.Msg)
				*pooled = dns.Msg{}
				if _, _, cacheOK, _ := CacheGet(mainKey, fqdn, pooled); cacheOK && !pooled.Authoritative {
					isAlias, aliasTarg, ttl := extractAlias(pooled)
					msgPool.Put(pooled)
					entry := probeCacheEntry{
						positive:   isAlias,
						secondary:  aliasTarg,
						expireNano: time.Now().Add(ttl).UnixNano(),
					}
					setRFCCache(ck, entry, nowInner)
					return entry, nil
				}
				msgPool.Put(pooled)
				if !effectiveDo {
					break
				}
			}
		}

		req := msgPool.Get().(*dns.Msg)
		*req = dns.Msg{}
		req.SetQuestion(fqdn, dns.TypeA)
		req.RecursionDesired = true
		if group.ECSAction == "pass" && ecsAddr.IsValid() {
			injectPassedECS(req, ecsAddr, ecsPrefix)
		}

		ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), rfcProbeBudget)
		resp, uAddr, err := group.Exchange(ctx, req, clientID, clientName, clientAddr)
		cancel()
		msgPool.Put(req)

		var entry probeCacheEntry
		if err != nil || resp == nil || strings.HasPrefix(uAddr, "consensus(") || strings.HasPrefix(uAddr, "consensus-log(") {
			entry = probeCacheEntry{
				positive:   false,
				expireNano: time.Now().Add(rfcFailTTL).UnixNano(),
			}
		} else {
			isAlias, aliasTarg, ttl := extractAlias(resp)
			entry = probeCacheEntry{
				positive:   isAlias,
				secondary:  aliasTarg,
				expireNano: time.Now().Add(ttl).UnixNano(),
			}
		}
		setRFCCache(ck, entry, time.Now().UnixNano())
		return entry, nil
	})

	select {
	case <-parentCtx.Done():
		return false, ""
	case r := <-resCh:
		if res, ok := r.Val.(probeCacheEntry); ok {
			return res.positive, res.secondary
		}
		return false, ""
	}
}

// inspectMsgRFCCompliance performs in-packet structural RFC validation and
// checks any NS, MX, SRV, SOA, and PTR targets in the message for CNAME indirection.
func (qc *queryCtx) inspectMsgRFCCompliance(msg *dns.Msg, allowNetworkProbe bool) (violated bool, reason string, ownerZone string) {
	if msg == nil || (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) {
		return false, "", ""
	}

	var qDomainClean string
	var chainStack [64]string
	validNames, exceeded := chainBufInit(&chainStack, msg, qc.qNameTrimmed, &qDomainClean)
	if exceeded {
		if rfcCheckCNAME {
			return true, "RFC 1034 CNAME/DNAME Chain Exceeded (" + qDomainClean + ")", ""
		}
		return false, "", ""
	}

	isInBailiwick := func(owner string, allowAncestor bool) bool {
		if len(validNames) == 0 {
			return true
		}
		ownerFqdn := strings.ToLower(dns.Fqdn(owner))
		if isValidBailiwickName(validNames, ownerFqdn) {
			return true
		}
		if !allowAncestor {
			return false
		}
		cleanOwner := strings.TrimSuffix(ownerFqdn, ".")
		if isPublicSuffix(cleanOwner) || isDGASafeDomain(cleanOwner) {
			return false
		}
		if _, isShared := sharedHostingDomains[cleanOwner]; isShared {
			return false
		}
		for _, vn := range validNames {
			vnClean := strings.TrimSuffix(vn, ".")
			if cleanOwner == vnClean || hasDotSuffix(vnClean, cleanOwner) {
				return true
			}
		}
		return false
	}

	var inPacketCNAMEs map[string]string
	var inPacketDNAMEs [][2]string
	var inPacketCanonical map[string]bool
	for _, rr := range msg.Answer {
		ownerLower := lowerTrimDot(rr.Header().Name)
		if !isInBailiwick(ownerLower, false) {
			continue
		}
		switch r := rr.(type) {
		case *dns.CNAME:
			if inPacketCNAMEs == nil {
				inPacketCNAMEs = make(map[string]string, 4)
			}
			inPacketCNAMEs[ownerLower] = lowerTrimDot(r.Target)
		case *dns.DNAME:
			dTarg := lowerTrimDot(r.Target)
			inPacketDNAMEs = append(inPacketDNAMEs, [2]string{ownerLower, dTarg})
			for _, vn := range validNames {
				vnClean := strings.TrimSuffix(vn, ".")
				if hasDotSuffix(vnClean, ownerLower) {
					prefix := vnClean[:len(vnClean)-len(ownerLower)]
					synthTarget := lowerTrimDot(prefix + dTarg)
					if len(synthTarget) <= 253 {
						if inPacketCNAMEs == nil {
							inPacketCNAMEs = make(map[string]string, 4)
						}
						if _, exists := inPacketCNAMEs[vnClean]; !exists {
							inPacketCNAMEs[vnClean] = synthTarget
						}
					}
				}
			}
		case *dns.A, *dns.AAAA:
			if inPacketCanonical == nil {
				inPacketCanonical = make(map[string]bool, 4)
			}
			inPacketCanonical[ownerLower] = true
		}
	}

	resolveInPacketTarget := func(targ, refOwner string) (string, bool) {
		if cTarg, ok, _ := resolveCNAMEChainTarget(inPacketCNAMEs, inPacketDNAMEs, targ, refOwner); ok {
			return cTarg, true
		}
		return "", false
	}

	// 1. CNAME/DNAME Structural & Strict Cross-Apex Checks (RFC 1034 §3.6.2 / RFC 2181 §10.1 / RFC 6672)
	if rfcCheckCNAME && len(msg.Answer) > 0 {
		type ownerMask struct {
			cnameCount int
			cnameTarg  string
			dnameCount int
			dnameTarg  string
			hasOther   bool
			otherType  uint16
		}
		type ownerEntry struct {
			name string
			info ownerMask
		}
		var ownersBuf [16]ownerEntry
		owners := ownersBuf[:0]

		findOwner := func(name string) *ownerMask {
			for i := range owners {
				if owners[i].name == name {
					return &owners[i].info
				}
			}
			owners = append(owners, ownerEntry{name: name})
			return &owners[len(owners)-1].info
		}

		for _, rr := range msg.Answer {
			hdr := rr.Header()
			rt := hdr.Rrtype
			if rt == dns.TypeRRSIG || rt == dns.TypeNSEC || rt == dns.TypeNSEC3 || rt == dns.TypeOPT {
				continue
			}
			ownerLower := lowerTrimDot(hdr.Name)
			if !isInBailiwick(ownerLower, false) {
				continue
			}
			om := findOwner(ownerLower)

			switch r := rr.(type) {
			case *dns.CNAME:
				targLower := lowerTrimDot(r.Target)
				if targLower == "" || isIPLiteralHost(targLower) {
					return true, "RFC 1035 CNAME Target IP Literal (" + ownerLower + " -> " + targLower + ")", ""
				}
				if ownerLower == targLower {
					return true, "RFC 2181 CNAME Self-Loop (" + ownerLower + ")", ""
				}
				if resolvedTarg, _, hasLoop := resolveCNAMEChainTarget(inPacketCNAMEs, inPacketDNAMEs, ownerLower, ownerLower); hasLoop {
					return true, "RFC 1034 CNAME Loop (" + ownerLower + " -> " + targLower + ")", ""
				} else if rfcStrict && resolvedTarg != "" && (!sameDomainApex(qc.qNameTrimmed, resolvedTarg) || !sameDomainApex(ownerLower, resolvedTarg)) {
					return true, "RFC Strict Cross-Apex CNAME (" + ownerLower + " -> " + resolvedTarg + ")", ""
				}
				if rfcStrict && (!sameDomainApex(qc.qNameTrimmed, targLower) || !sameDomainApex(ownerLower, targLower)) {
					return true, "RFC Strict Cross-Apex CNAME (" + ownerLower + " -> " + targLower + ")", ""
				}
				om.cnameCount++
				if om.cnameCount > 1 && om.cnameTarg != targLower {
					return true, "RFC 2181 Multiple CNAMEs (" + ownerLower + ")", ""
				}
				om.cnameTarg = targLower
				if om.dnameCount > 0 {
					return true, "RFC 6672 CNAME/DNAME Coexistence Violation (" + ownerLower + ")", ""
				}
				if om.hasOther {
					return true, "RFC 2181 CNAME Exclusivity Violation (" + ownerLower + " with " + qtypeName(om.otherType) + ")", ""
				}
			case *dns.DNAME:
				targLower := lowerTrimDot(r.Target)
				if targLower == "" || isIPLiteralHost(targLower) {
					return true, "RFC 6672 DNAME Target IP Literal (" + ownerLower + " -> " + targLower + ")", ""
				}
				if ownerLower == targLower || hasDotSuffix(targLower, ownerLower) {
					return true, "RFC 6672 DNAME Self-Loop (" + ownerLower + " -> " + targLower + ")", ""
				}
				for _, vn := range validNames {
					vnClean := strings.TrimSuffix(vn, ".")
					if hasDotSuffix(vnClean, ownerLower) {
						if resolvedTarg, _, hasLoop := resolveCNAMEChainTarget(inPacketCNAMEs, inPacketDNAMEs, vnClean, ownerLower); hasLoop {
							return true, "RFC 6672 DNAME Loop (" + ownerLower + " -> " + targLower + ")", ""
						} else if rfcStrict && resolvedTarg != "" && (!sameDomainApex(qc.qNameTrimmed, resolvedTarg) || !sameDomainApex(ownerLower, resolvedTarg)) {
							return true, "RFC Strict Cross-Apex DNAME (" + ownerLower + " -> " + resolvedTarg + ")", ""
						}
					}
				}
				if rfcStrict && (!sameDomainApex(qc.qNameTrimmed, targLower) || !sameDomainApex(ownerLower, targLower)) {
					return true, "RFC Strict Cross-Apex DNAME (" + ownerLower + " -> " + targLower + ")", ""
				}
				om.dnameCount++
				if om.dnameCount > 1 && om.dnameTarg != targLower {
					return true, "RFC 6672 Multiple DNAMEs (" + ownerLower + ")", ""
				}
				om.dnameTarg = targLower
				if om.cnameCount > 0 {
					return true, "RFC 6672 CNAME/DNAME Coexistence Violation (" + ownerLower + ")", ""
				}
			default:
				om.hasOther = true
				om.otherType = rt
				if om.cnameCount > 0 {
					return true, "RFC 2181 CNAME Exclusivity Violation (" + ownerLower + " with " + qtypeName(rt) + ")", ""
				}
			}
		}

		// Check if an Answer CNAME coexists with an in-bailiwick Authority SOA/NS at the exact same owner
		for i := range owners {
			if owners[i].info.cnameCount > 0 {
				cOwner := owners[i].name
				for _, nsRR := range msg.Ns {
					nsType := nsRR.Header().Rrtype
					if nsType == dns.TypeSOA || nsType == dns.TypeNS {
						nsOwner := lowerTrimDot(nsRR.Header().Name)
						if nsOwner == cOwner && isInBailiwick(nsOwner, true) {
							return true, "RFC 2181 CNAME at Zone Apex (" + cOwner + " with " + qtypeName(nsType) + ")", cOwner
						}
					}
				}
			}
		}
	}

	type targetSpec struct {
		rrLabel string
		owner   string
		target  string
	}
	var targetsBuf [rfcMaxTargetProbes]targetSpec
	targets := targetsBuf[:0]

	addTarget := func(rrLabel, owner, target string) {
		if len(targets) >= rfcMaxTargetProbes {
			return
		}
		for i := range targets {
			if targets[i].target == target && targets[i].rrLabel == rrLabel {
				return
			}
		}
		targets = append(targets, targetSpec{rrLabel: rrLabel, owner: owner, target: target})
	}

	type mxOwnerEntry struct {
		owner   string
		count   int
		hasNull bool
	}
	var mxOwnersBuf [8]mxOwnerEntry
	mxOwners := mxOwnersBuf[:0]
	recordMXOwner := func(owner string, isNull bool) (coexists bool) {
		for i := range mxOwners {
			if mxOwners[i].owner == owner {
				mxOwners[i].count++
				if isNull {
					mxOwners[i].hasNull = true
				}
				return mxOwners[i].hasNull && mxOwners[i].count > 1
			}
		}
		mxOwners = append(mxOwners, mxOwnerEntry{owner: owner, count: 1, hasNull: isNull})
		return false
	}

	inspectSection := func(rrs []dns.RR, isAuthority bool) (bool, string, string) {
		for _, rr := range rrs {
			owner := lowerTrimDot(rr.Header().Name)
			if !isInBailiwick(owner, isAuthority) {
				continue
			}

			switch r := rr.(type) {
			case *dns.NS:
				if !rfcCheckNS {
					continue
				}
				targ := lowerTrimDot(r.Ns)
				if targ == "" || isIPLiteralHost(targ) {
					return true, "RFC 2181 NS Target IP Literal (" + owner + " -> " + r.Ns + ")", owner
				}
				if cnameTarg, isCNAME := resolveInPacketTarget(targ, owner); isCNAME {
					if isIndirectionActionable(owner, cnameTarg) || isIndirectionActionable(targ, cnameTarg) {
						return true, "RFC 2181 NS CNAME Indirection (" + owner + " NS " + targ + " -> CNAME " + cnameTarg + ")", owner
					}
					continue
				}
				if !inPacketCanonical[targ] {
					addTarget("NS", owner, targ)
				}

			case *dns.MX:
				if !rfcCheckMX {
					continue
				}
				targ := lowerTrimDot(r.Mx)
				if r.Mx == "." || targ == "" {
					if r.Preference != 0 {
						return true, "RFC 7505 Null MX Non-Zero Preference (" + owner + ")", ""
					}
					if recordMXOwner(owner, true) {
						return true, "RFC 7505 Null MX Coexistence Violation (" + owner + ")", ""
					}
					continue
				}
				if recordMXOwner(owner, false) {
					return true, "RFC 7505 Null MX Coexistence Violation (" + owner + ")", ""
				}
				if isIPLiteralHost(targ) {
					return true, "RFC 2181 MX Target IP Literal (" + owner + " -> " + r.Mx + ")", ""
				}
				if cnameTarg, isCNAME := resolveInPacketTarget(targ, owner); isCNAME {
					if isIndirectionActionable(owner, cnameTarg) || isIndirectionActionable(targ, cnameTarg) {
						return true, "RFC 2181 MX CNAME Indirection (" + owner + " MX " + targ + " -> CNAME " + cnameTarg + ")", ""
					}
					continue
				}
				if !inPacketCanonical[targ] {
					addTarget("MX", owner, targ)
				}

			case *dns.SRV:
				if !rfcCheckSRV {
					continue
				}
				if r.Target == "." {
					continue
				}
				targ := lowerTrimDot(r.Target)
				if targ == "" || isIPLiteralHost(targ) {
					return true, "RFC 2782 SRV Target IP Literal (" + owner + " -> " + r.Target + ")", ""
				}
				if cnameTarg, isCNAME := resolveInPacketTarget(targ, owner); isCNAME {
					if isIndirectionActionable(owner, cnameTarg) || isIndirectionActionable(targ, cnameTarg) {
						return true, "RFC 2782 SRV CNAME Indirection (" + owner + " SRV " + targ + " -> CNAME " + cnameTarg + ")", ""
					}
					continue
				}
				if !inPacketCanonical[targ] {
					addTarget("SRV", owner, targ)
				}

			case *dns.SOA:
				if !rfcCheckSOA {
					continue
				}
				if r.Ns == "ns.sdproxy." {
					continue
				}
				targ := lowerTrimDot(r.Ns)
				if targ == "" || isIPLiteralHost(targ) {
					return true, "RFC 1035 SOA MNAME IP Literal (" + owner + " -> " + r.Ns + ")", ""
				}
				if cnameTarg, isCNAME := resolveInPacketTarget(targ, owner); isCNAME {
					if isIndirectionActionable(owner, cnameTarg) || isIndirectionActionable(targ, cnameTarg) {
						return true, "RFC 2181 SOA MNAME CNAME Indirection (" + owner + " SOA " + targ + " -> CNAME " + cnameTarg + ")", ""
					}
					continue
				}
				if !inPacketCanonical[targ] && (!isAuthority || qc.q.Qtype == dns.TypeSOA) {
					addTarget("SOA", owner, targ)
				}

			case *dns.PTR:
				if !rfcCheckPTR {
					continue
				}
				targ := lowerTrimDot(r.Ptr)
				if targ == "" || isIPLiteralHost(targ) {
					return true, "RFC 1035 PTR Target IP Literal (" + owner + " -> " + r.Ptr + ")", ""
				}
				if cnameTarg, isCNAME := resolveInPacketTarget(targ, targ); isCNAME {
					if isIndirectionActionable(targ, cnameTarg) {
						return true, "RFC 2181 PTR CNAME Indirection (" + owner + " PTR " + targ + " -> CNAME " + cnameTarg + ")", ""
					}
					continue
				}
				if !inPacketCanonical[targ] {
					addTarget("PTR", owner, targ)
				}
			}
		}
		return false, "", ""
	}

	if v, r, oz := inspectSection(msg.Answer, false); v {
		return true, r, oz
	}
	if v, r, oz := inspectSection(msg.Ns, true); v {
		return true, r, oz
	}

	if len(targets) == 0 || qc.group == nil {
		return false, "", ""
	}

	for _, t := range targets {
		if isDGASafeDomain(t.target) || isVerifiedAWSDNS(t.target) {
			continue
		}
		hasCNAME, cnameTarg := probeTargetHasCNAME(
			context.Background(),
			qc.group,
			qc.route.routeIdx,
			t.target,
			qc.clientID,
			qc.clientName,
			qc.clientAddr,
			qc.ecsAddr,
			qc.ecsPrefix,
			qc.doBit,
			qc.r.CheckingDisabled,
			qc.route.bypassLocal,
			qc.bypassGlobal,
			qc.bypassPolicies,
			allowNetworkProbe,
		)
		if hasCNAME {
			if isIndirectionActionable(t.owner, cnameTarg) || isIndirectionActionable(t.target, cnameTarg) {
				rfcRef := "RFC 2181"
				if t.rrLabel == "SRV" {
					rfcRef = "RFC 2782"
				}
				oz := ""
				if t.rrLabel == "NS" && (qDomainClean == "" || t.owner == qDomainClean || hasDotSuffix(qDomainClean, t.owner)) {
					oz = t.owner
				}
				return true, rfcRef + " " + t.rrLabel + " CNAME Indirection (" + t.owner + " " + t.rrLabel + " " + t.target + " -> CNAME " + cnameTarg + ")", oz
			}
		}
	}

	return false, "", ""
}

func chainBufInit(chainStack *[64]string, msg *dns.Msg, fallbackQName string, qDomainClean *string) ([]string, bool) {
	var initQName string
	if len(msg.Question) > 0 {
		qLower := strings.ToLower(msg.Question[0].Name)
		initQName = qLower
		*qDomainClean = strings.TrimSuffix(qLower, ".")
	} else if fallbackQName != "" {
		*qDomainClean = fallbackQName
		initQName = dns.Fqdn(fallbackQName)
	}

	validNames, _, exceeded := walkBailiwickChain(msg.Answer, initQName, 16, chainStack)
	return validNames, exceeded
}

func hasCachedRFCDomainViolation(routeIdx uint16, qname, apex string, now int64) (violated bool, reason string, qnameCachedNeg bool, apexCachedNeg bool) {
	search := qname
	for {
		if entry, ok := getRFCCache(probeCacheKey{routeIdx: routeIdx, kind: 1, domain: search}, now); ok {
			if entry.positive {
				return true, entry.matchedTag, false, false
			}
			if search == qname {
				qnameCachedNeg = true
			}
			if search == apex {
				apexCachedNeg = true
			}
		}
		if search == apex || apex == "" {
			break
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
		if len(search) < len(apex) || isPublicSuffix(search) {
			break
		}
	}
	return false, "", qnameCachedNeg, apexCachedNeg
}

func probeDomainNSIndirection(parentCtx context.Context, group *UpstreamGroup, routeIdx uint16, domain, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies bool) (bool, string) {
	now := time.Now().UnixNano()
	ck := probeCacheKey{routeIdx: routeIdx, kind: 1, domain: domain}
	if entry, ok := getRFCCache(ck, now); ok {
		return entry.positive, entry.matchedTag
	}
	if parentCtx.Err() != nil || len(domain) == 0 || len(domain) > 253 {
		return false, ""
	}

	sfKey := "d|" + itoa64(int64(routeIdx)) + "|" + domain
	resCh := rfcSFGroup.DoChan(sfKey, func() (any, error) {
		nowInner := time.Now().UnixNano()
		if entry, ok := getRFCCache(ck, nowInner); ok {
			return entry, nil
		}

		fqdn := dns.Fqdn(domain)
		cNameKey, ecsKey := probeCacheKeyPartitions(group, clientName, clientAddr, ecsAddr, ecsPrefix)
		effectiveDo := doBit || (group != nil && group.RequireDNSSECAD)

		var nsResp *dns.Msg
		for _, tryDO := range []bool{effectiveDo, false} {
			mainKey := DNSCacheKey{
				Name:             domain,
				ClientName:       cNameKey,
				ECS:              ecsKey,
				Qtype:            dns.TypeNS,
				Qclass:           dns.ClassINET,
				RouteIdx:         routeIdx,
				DoBit:            tryDO,
				CdBit:            cdBit,
				BypassGlobal:     bypassGlobal,
				BypassPolicies:   bypassPolicies,
				BypassLocal:      bypassLocal,
				RecursionDesired: true,
			}
			pooled := msgPool.Get().(*dns.Msg)
			*pooled = dns.Msg{}
			if _, _, cacheOK, _ := CacheGet(mainKey, fqdn, pooled); cacheOK && !pooled.Authoritative {
				nsResp = pooled.Copy()
				msgPool.Put(pooled)
				break
			}
			msgPool.Put(pooled)
			if !effectiveDo {
				break
			}
		}

		if nsResp == nil {
			req := msgPool.Get().(*dns.Msg)
			*req = dns.Msg{}
			req.SetQuestion(fqdn, dns.TypeNS)
			req.RecursionDesired = true
			if group.ECSAction == "pass" && ecsAddr.IsValid() {
				injectPassedECS(req, ecsAddr, ecsPrefix)
			}

			ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), rfcProbeBudget)
			resp, uAddr, err := group.Exchange(ctx, req, clientID, clientName, clientAddr)
			cancel()
			msgPool.Put(req)

			if err != nil || resp == nil || strings.HasPrefix(uAddr, "consensus(") || strings.HasPrefix(uAddr, "consensus-log(") {
				entry := probeCacheEntry{
					positive:   false,
					expireNano: time.Now().Add(rfcFailTTL).UnixNano(),
				}
				setRFCCache(ck, entry, time.Now().UnixNano())
				return entry, nil
			}
			nsResp = resp
		}

		var chainBuf [64]string
		validNames, _, exceeded := walkBailiwickChain(nsResp.Answer, fqdn, 8, &chainBuf)
		if exceeded {
			nowStore := time.Now().UnixNano()
			entry := probeCacheEntry{
				positive:   true,
				matchedTag: "RFC 1034 NS CNAME/DNAME Chain Exceeded (" + domain + ")",
				expireNano: time.Now().Add(rfcMinTTL).UnixNano(),
			}
			setRFCCache(ck, entry, nowStore)
			return entry, nil
		}

		type nsTargetItem struct {
			owner string
			host  string
		}
		var nsTargetsBuf [rfcMaxTargetProbes]nsTargetItem
		nsTargets := nsTargetsBuf[:0]
		minTTL := uint32(3600)

		var nsCNAMEs map[string]string
		var nsDNAMEs [][2]string
		for _, rr := range nsResp.Answer {
			ownerFqdn := strings.ToLower(dns.Fqdn(rr.Header().Name))
			if !isValidBailiwickName(validNames, ownerFqdn) {
				continue
			}
			switch r := rr.(type) {
			case *dns.CNAME:
				if nsCNAMEs == nil {
					nsCNAMEs = make(map[string]string, 4)
				}
				nsCNAMEs[lowerTrimDot(r.Hdr.Name)] = lowerTrimDot(r.Target)
			case *dns.DNAME:
				ownerClean := lowerTrimDot(r.Hdr.Name)
				if isPublicSuffix(ownerClean) || isDGASafeDomain(ownerClean) {
					continue
				}
				if _, isShared := sharedHostingDomains[ownerClean]; isShared {
					continue
				}
				if ownerClean != domain && !hasDotSuffix(domain, ownerClean) {
					continue
				}
				dTarg := lowerTrimDot(r.Target)
				nsDNAMEs = append(nsDNAMEs, [2]string{ownerClean, dTarg})
				for _, vn := range validNames {
					vnClean := strings.TrimSuffix(vn, ".")
					if hasDotSuffix(vnClean, ownerClean) {
						prefix := vnClean[:len(vnClean)-len(ownerClean)]
						synthTarget := lowerTrimDot(prefix + dTarg)
						if len(synthTarget) <= 253 {
							if nsCNAMEs == nil {
								nsCNAMEs = make(map[string]string, 4)
							}
							if _, exists := nsCNAMEs[vnClean]; !exists {
								nsCNAMEs[vnClean] = synthTarget
							}
						}
					}
				}
			}
		}

		resolveNSTarget := func(targ, refOwner string) (string, bool) {
			if cTarg, ok, _ := resolveCNAMEChainTarget(nsCNAMEs, nsDNAMEs, targ, refOwner); ok {
				return cTarg, true
			}
			return "", false
		}

		collectNS := func(rrs []dns.RR, allowAncestor bool) (bool, string, string) {
			for _, rr := range rrs {
				ownerFqdn := strings.ToLower(dns.Fqdn(rr.Header().Name))
				if !allowAncestor && !isValidBailiwickName(validNames, ownerFqdn) {
					continue
				}
				switch r := rr.(type) {
				case *dns.CNAME:
					if strings.EqualFold(r.Hdr.Name, fqdn) {
						t := lowerTrimDot(r.Target)
						if cTarg, ok := resolveNSTarget(domain, domain); ok {
							t = cTarg
						}
						if isIndirectionActionable(domain, t) {
							return true, "RFC 2181 NS Owner is CNAME (" + domain + " -> CNAME " + t + ")", domain
						}
					}
				case *dns.DNAME:
					ownerClean := lowerTrimDot(r.Hdr.Name)
					if isPublicSuffix(ownerClean) || isDGASafeDomain(ownerClean) {
						continue
					}
					if _, isShared := sharedHostingDomains[ownerClean]; isShared {
						continue
					}
					if hasDotSuffix(domain, ownerClean) {
						t := lowerTrimDot(r.Target)
						prefix := domain[:len(domain)-len(ownerClean)]
						synth := lowerTrimDot(prefix + t)
						if cTarg, ok := resolveNSTarget(synth, domain); ok {
							t = cTarg
						} else if synth != "" {
							t = synth
						}
						if isIndirectionActionable(domain, t) {
							return true, "RFC 6672 NS Owner is DNAME (" + domain + " -> DNAME " + t + ")", domain
						}
					}
				case *dns.NS:
					owner := lowerTrimDot(r.Hdr.Name)
					if owner != domain && !hasDotSuffix(domain, owner) {
						continue
					}
					if isPublicSuffix(owner) || isDGASafeDomain(owner) {
						continue
					}
					if _, isShared := sharedHostingDomains[owner]; isShared {
						continue
					}
					targ := lowerTrimDot(r.Ns)
					if targ == "" || isIPLiteralHost(targ) {
						return true, "RFC 2181 NS Target IP Literal (" + owner + " -> " + r.Ns + ")", owner
					}
					if cTarg, isCNAME := resolveNSTarget(targ, owner); isCNAME {
						if isIndirectionActionable(owner, cTarg) || isIndirectionActionable(targ, cTarg) {
							return true, "RFC 2181 NS CNAME Indirection (" + owner + " NS " + targ + " -> CNAME " + cTarg + ")", owner
						}
						continue
					}
					if r.Hdr.Ttl > 0 && r.Hdr.Ttl < minTTL {
						minTTL = r.Hdr.Ttl
					}
					if len(nsTargets) < rfcMaxTargetProbes {
						dup := false
						for _, ex := range nsTargets {
							if ex.host == targ {
								dup = true
								break
							}
						}
						if !dup {
							nsTargets = append(nsTargets, nsTargetItem{owner: owner, host: targ})
						}
					}
				}
			}
			return false, "", ""
		}

		if v, r, oz := collectNS(nsResp.Answer, false); v {
			nowStore := time.Now().UnixNano()
			entry := probeCacheEntry{
				positive:   true,
				matchedTag: r,
				expireNano: time.Now().Add(rfcMinTTL).UnixNano(),
			}
			setRFCCache(ck, entry, nowStore)
			if oz != "" && oz != domain && !shouldSkipForSaleCheck(oz, dns.TypeA) {
				setRFCCache(probeCacheKey{routeIdx: routeIdx, kind: 1, domain: oz}, entry, nowStore)
			}
			return entry, nil
		}
		if len(nsTargets) == 0 {
			if v, r, oz := collectNS(nsResp.Ns, true); v {
				nowStore := time.Now().UnixNano()
				entry := probeCacheEntry{
					positive:   true,
					matchedTag: r,
					expireNano: time.Now().Add(rfcMinTTL).UnixNano(),
				}
				setRFCCache(ck, entry, nowStore)
				if oz != "" && oz != domain && !shouldSkipForSaleCheck(oz, dns.TypeA) {
					setRFCCache(probeCacheKey{routeIdx: routeIdx, kind: 1, domain: oz}, entry, nowStore)
				}
				return entry, nil
			}
		}

		for _, item := range nsTargets {
			if isDGASafeDomain(item.host) || isVerifiedAWSDNS(item.host) {
				continue
			}
			hasCNAME, cnameTarg := probeTargetHasCNAME(
				parentCtx,
				group,
				routeIdx,
				item.host,
				clientID,
				clientName,
				clientAddr,
				ecsAddr,
				ecsPrefix,
				doBit,
				cdBit,
				bypassLocal,
				bypassGlobal,
				bypassPolicies,
				true,
			)
			if hasCNAME {
				if isIndirectionActionable(item.owner, cnameTarg) || isIndirectionActionable(item.host, cnameTarg) {
					ttl := time.Duration(minTTL) * time.Second
					if ttl < rfcMinTTL {
						ttl = rfcMinTTL
					} else if ttl > rfcMaxTTL {
						ttl = rfcMaxTTL
					}
					reason := "RFC 2181 NS CNAME Indirection (" + item.owner + " NS " + item.host + " -> CNAME " + cnameTarg + ")"
					nowStore := time.Now().UnixNano()
					entry := probeCacheEntry{
						positive:   true,
						matchedTag: reason,
						expireNano: time.Now().Add(ttl).UnixNano(),
					}
					setRFCCache(ck, entry, nowStore)
					if item.owner != "" && item.owner != domain && !shouldSkipForSaleCheck(item.owner, dns.TypeA) {
						setRFCCache(probeCacheKey{routeIdx: routeIdx, kind: 1, domain: item.owner}, entry, nowStore)
					}
					return entry, nil
				}
			}
		}

		entry := probeCacheEntry{
			positive:   false,
			expireNano: time.Now().Add(rfcNegTTL).UnixNano(),
		}
		setRFCCache(ck, entry, time.Now().UnixNano())
		return entry, nil
	})

	select {
	case <-parentCtx.Done():
		return false, ""
	case r := <-resCh:
		if res, ok := r.Val.(probeCacheEntry); ok {
			return res.positive, res.matchedTag
		}
		return false, ""
	}
}

func checkRFCDomainNS(group *UpstreamGroup, routeIdx uint16, qname, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies bool) (bool, string) {
	if !rfcCheckNS || group == nil || shouldSkipForSaleCheck(qname, dns.TypeA) {
		return false, ""
	}

	apex, _ := extractETLDPlusOne(qname)
	checkApex := apex != "" && apex != qname && !isPublicSuffix(apex) && !isDGASafeDomain(apex)
	if checkApex {
		if _, isShared := sharedHostingDomains[apex]; isShared {
			checkApex = false
		}
	}

	walkStop := qname
	if checkApex {
		walkStop = apex
	}

	now := time.Now().UnixNano()
	if hit, reason, qNeg, aNeg := hasCachedRFCDomainViolation(routeIdx, qname, walkStop, now); hit {
		return true, reason
	} else {
		if qNeg && (!checkApex || aNeg) {
			return false, ""
		}
		if !checkApex || aNeg {
			return probeDomainNSIndirection(context.Background(), group, routeIdx, qname, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		}
		if qNeg {
			return probeDomainNSIndirection(context.Background(), group, routeIdx, apex, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		}
	}

	type probeRes struct {
		violated bool
		reason   string
	}
	ch := make(chan probeRes, 2)
	probeCtx, cancelProbes := context.WithCancel(context.Background())
	defer cancelProbes()

	go func() {
		v, r := probeDomainNSIndirection(probeCtx, group, routeIdx, apex, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		ch <- probeRes{violated: v, reason: r}
	}()
	go func() {
		v, r := probeDomainNSIndirection(probeCtx, group, routeIdx, qname, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		ch <- probeRes{violated: v, reason: r}
	}()

	r1 := <-ch
	if r1.violated {
		cancelProbes()
		return true, r1.reason
	}
	r2 := <-ch
	if r2.violated {
		return true, r2.reason
	}
	return false, ""
}

// applyRFCComplianceVerdict executes the configured action (`LOG` or `BLOCK`).
func (qc *queryCtx) applyRFCComplianceVerdict(reason string, cacheHit bool) bool {
	IncrPolicyBlock()
	RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)

	if rfcAction == "LOG" || (rfcAction == "BLOCK" && globalBlockAction == BlockActionLog) {
		if logQueries {
			if logSimple {
				log.Printf("[DNS] [%s] %s -> %s %s | RFC COMPLIANCE (LOG ONLY): %s",
					qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), reason)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | RFC COMPLIANCE DETECTION (LOG ONLY) (%s) | LOG",
					qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), reason)
			}
		}
		return false
	}

	dropped := writePolicyAction(qc.w, qc.r, rfcActionCode)

	if !cacheHit && cacheSynthFlag && !dropped && !(rfcActionCode == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
		synthMsg := buildSynthCacheMsg(qc.r, qc.q, rfcActionCode)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg)
	}

	if logQueries {
		actionLogStr := getBlockActionLogStr(qc.q.Qtype)
		if logSimple {
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), actionLogStr, reason, cacheHit)
		} else {
			statusMark := "RFC COMPLIANCE BLOCK"
			if dropped {
				statusMark = "RFC COMPLIANCE DROP"
			}
			statusMark = qc.annotateAlias(statusMark)

			log.Printf("[DNS] [%s] %s -> %s %s | %s (%s) | %s",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
				statusMark, reason, actionLogStr)
		}
	}

	return true
}

func (qc *queryCtx) enforceRFCComplianceCachedOnly() bool {
	if !hasRFCCompliance || !rfcCheckNS || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}

	checkSingleCached := func(cand string) bool {
		targetQName, skip := normalizeForSaleTarget(cand, qc.q.Qtype)
		if skip {
			return false
		}
		if ddrHostnames != nil && ddrHostnames[targetQName] {
			return false
		}

		apex, _ := extractETLDPlusOne(targetQName)
		walkStop := targetQName
		if apex != "" && apex != targetQName && !isPublicSuffix(apex) && !isDGASafeDomain(apex) {
			if _, isShared := sharedHostingDomains[apex]; !isShared {
				walkStop = apex
			}
		}

		hit, reason, _, _ := hasCachedRFCDomainViolation(
			qc.route.routeIdx,
			targetQName,
			walkStop,
			time.Now().UnixNano(),
		)
		if !hit {
			return false
		}
		return qc.applyRFCComplianceVerdict(reason, true)
	}

	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if checkSingleCached(qc.originalQNameTrimmed) {
			return true
		}
	}
	return checkSingleCached(qc.qNameTrimmed)
}

func (qc *queryCtx) enforceRFCComplianceCheck() bool {
	if !hasRFCCompliance || !rfcCheckNS || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}

	checkSingle := func(cand string) bool {
		if qc.q.Qtype == dns.TypeNS && cand == qc.qNameTrimmed {
			apex, _ := extractETLDPlusOne(cand)
			if apex == "" || apex == cand || isPublicSuffix(apex) || isDGASafeDomain(apex) {
				return false
			}
			if _, isShared := sharedHostingDomains[apex]; isShared {
				return false
			}
			cand = apex
		}
		targetQName, skip := normalizeForSaleTarget(cand, qc.q.Qtype)
		if skip {
			return false
		}
		if ddrHostnames != nil && ddrHostnames[targetQName] {
			return false
		}

		violated, reason := checkRFCDomainNS(
			qc.group,
			qc.route.routeIdx,
			targetQName,
			qc.clientID,
			qc.clientName,
			qc.clientAddr,
			qc.ecsAddr,
			qc.ecsPrefix,
			qc.doBit,
			qc.r.CheckingDisabled,
			qc.route.bypassLocal,
			qc.bypassGlobal,
			qc.bypassPolicies,
		)
		if !violated {
			return false
		}
		return qc.applyRFCComplianceVerdict(reason, false)
	}

	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if checkSingle(qc.originalQNameTrimmed) {
			return true
		}
	}
	return checkSingle(qc.qNameTrimmed)
}

func (qc *queryCtx) enforceRFCComplianceResponseCheck(resp *dns.Msg, cacheHit bool) bool {
	if !hasRFCCompliance || resp == nil || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}
	if ddrHostnames != nil && ddrHostnames[qc.qNameTrimmed] {
		return false
	}

	violated, reason, ownerZone := qc.inspectMsgRFCCompliance(resp, !cacheHit)
	if !violated {
		return false
	}

	if ownerZone != "" && !shouldSkipForSaleCheck(ownerZone, dns.TypeA) {
		now := time.Now().UnixNano()
		entry := probeCacheEntry{
			positive:   true,
			matchedTag: reason,
			expireNano: time.Now().Add(rfcMinTTL).UnixNano(),
		}
		setRFCCache(probeCacheKey{routeIdx: qc.route.routeIdx, kind: 1, domain: ownerZone}, entry, now)
		if ownerZone != qc.qNameTrimmed && !shouldSkipForSaleCheck(qc.qNameTrimmed, dns.TypeA) {
			setRFCCache(probeCacheKey{routeIdx: qc.route.routeIdx, kind: 1, domain: qc.qNameTrimmed}, entry, now)
		}
		if qc.originalQNameTrimmed != qc.qNameTrimmed && qc.originalQNameTrimmed != ownerZone && !shouldSkipForSaleCheck(qc.originalQNameTrimmed, dns.TypeA) {
			setRFCCache(probeCacheKey{routeIdx: qc.route.routeIdx, kind: 1, domain: qc.originalQNameTrimmed}, entry, now)
		}
	}

	return qc.applyRFCComplianceVerdict(reason, cacheHit)
}
