/*
File:    cache_rw.go
Version: 1.51.0 (Split)
Last Updated: 24-Nov-2026 12:30 CET

Description:
  Hot-path Read/Write operations for the sdproxy cache engine.
  Handles packing/unpacking dns.Msg structures, TTL rewrites, background
  revalidation tracking, and strict RFC bailiwick security enforcement.

Changes:
  1.51.0 - [SECURITY/FIX] Fixed `CacheSet` authority bailiwick validation so
           parent TLD/eTLD and root `"."` `SOA` / `DS` / `NSEC` / `NSEC3` /
           `RRSIG` authority records on `NXDOMAIN` and negative responses are
           permitted while still rejecting out-of-bailiwick or root/public-suffix
           `TypeNS` delegation records.
         - [FIX] Stopped mutating `SOA.Minttl` RDATA during `CacheGet` and
           `CacheGetExpired` per RFC 2308 §5, and synced CNAME head owner casing
           in `syncQuestionCasing` when `!hasRRSIG`.
  1.50.0 - [SECURITY/FIX] Capped authority `Hdr.Ttl` and `SOA.Minttl` by
           `targetTTL` inside `rewriteAuthorityTTLInPlace` and returned
           `isSynth` directly from `CacheGet`.
  1.49.0 - [SECURITY/FIX] Excluded `dns.TypeRRSIG` records from `minAnsTTL`
           and wire TTL clamping in `applyRcodeOnlyWireTTL` and `CacheSet`.
  1.48.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` with `CacheSet` and
           `CacheSetSynth` on non-`NOERROR` responses with `Answer` records.
  1.47.0 - [FIX] Clamped `targetTTL` by `minAnsTTL` in `applyRcodeOnlyWireTTL`.
  1.46.0 - [SECURITY/FIX] Clamped `ttl` on `isRcodeOnlyAfterClean` responses in
           `CacheSet` by the minimum `Answer` record TTL.
  1.45.0 - [SECURITY/FIX] Extended `applyRcodeOnlyWireTTL` and `CacheSet` to
           clamp `Answer` wire TTLs on unsigned non-`NOERROR` responses.
  1.44.0 - [SECURITY/FIX] Prevented `rcodeTTLBounds` and `computeRcodeOnlyTTL`
           from applying `MinTTL` or `NegativeTTL` to non-negative RCODEs.
  1.43.0 - [SECURITY/FIX] Aligned `CacheSet` positive answer wire-TTL clamping.
  1.42.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` with `CacheSet`.
*/

package main

import (
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// extractAuthorityTTL derives the RFC 2308 negative/RCODE caching TTL from the
// Authority (`Ns`) section of msg.
func extractAuthorityTTL(ns []dns.RR) (ttl uint32, hasAuth bool) {
	for _, rr := range ns {
		if soa, ok := rr.(*dns.SOA); ok {
			t := soa.Hdr.Ttl
			if soa.Minttl > 0 && (t == 0 || soa.Minttl < t) {
				t = soa.Minttl
			}
			return t, t > 0
		}
	}
	minT := ^uint32(0)
	for _, rr := range ns {
		if rr == nil || rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		if t := rr.Header().Ttl; t > 0 && t < minT {
			minT = t
		}
	}
	if minT != ^uint32(0) {
		return minT, true
	}
	return 0, false
}

// computeRcodeOnlyTTL computes the effective TTL for an RCODE-only response.
func computeRcodeOnlyTTL(authTTL uint32, hasAuth bool, rcode int) uint32 {
	isNegRcode := rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess
	if !isNegRcode && cfg.Cache.RcodeTTL <= 0 && cfg.Cache.RcodeMinTTL <= 0 {
		return 0
	}

	ttl := authTTL

	if !hasAuth || ttl == 0 {
		switch {
		case cfg.Cache.RcodeTTL > 0:
			ttl = uint32(cfg.Cache.RcodeTTL)
		case cfg.Cache.NegativeTTL > 0 && isNegRcode:
			ttl = uint32(cfg.Cache.NegativeTTL)
		case cfg.Cache.RcodeMinTTL > 0:
			ttl = uint32(cfg.Cache.RcodeMinTTL)
		case isNegRcode:
			ttl = uint32(cfg.Cache.MinTTL)
		}
	} else if cfg.Cache.NegativeTTL > 0 && cfg.Cache.RcodeTTL == 0 && cfg.Cache.RcodeMinTTL == 0 && cfg.Cache.RcodeMaxTTL == 0 {
		if isNegRcode {
			ttl = uint32(cfg.Cache.NegativeTTL)
		}
	}

	if cfg.Cache.RcodeTTL > 0 && cfg.Cache.RcodeMinTTL == 0 && cfg.Cache.RcodeMaxTTL == 0 {
		ttl = uint32(cfg.Cache.RcodeTTL)
	}

	minFloor, maxCeil := rcodeTTLBounds(rcode)
	if ttl < minFloor {
		ttl = minFloor
	}
	if maxCeil > 0 && ttl > maxCeil {
		ttl = maxCeil
	}

	return ttl
}

func rcodeTTLBounds(rcode int) (minFloor, maxCeil uint32) {
	isNegRcode := rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess
	switch {
	case cfg.Cache.RcodeMinTTL > 0:
		minFloor = uint32(cfg.Cache.RcodeMinTTL)
	case cfg.Cache.NegativeTTL > 0 && isNegRcode:
		minFloor = uint32(cfg.Cache.NegativeTTL)
	case isNegRcode:
		minFloor = uint32(cfg.Cache.MinTTL)
	}

	if cfg.Cache.RcodeMaxTTL > 0 {
		maxCeil = uint32(cfg.Cache.RcodeMaxTTL)
	} else if cfg.Cache.MaxTTL > 0 {
		maxCeil = uint32(cfg.Cache.MaxTTL)
	}
	return minFloor, maxCeil
}

func isHardRcodeTTLOverride(rcode int) bool {
	if cfg.Cache.RcodeTTL > 0 && cfg.Cache.RcodeMinTTL == 0 && cfg.Cache.RcodeMaxTTL == 0 {
		return true
	}
	if cfg.Cache.NegativeTTL > 0 && cfg.Cache.RcodeTTL == 0 && cfg.Cache.RcodeMinTTL == 0 && cfg.Cache.RcodeMaxTTL == 0 {
		return rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess
	}
	return false
}

func rewriteAuthorityTTLInPlace(cp dns.RR, targetTTL uint32, rcode int) {
	if cp == nil || cp.Header().Rrtype == dns.TypeRRSIG {
		return
	}
	hardOverride := isHardRcodeTTLOverride(rcode)
	minFloor, maxCeil := rcodeTTLBounds(rcode)

	clampVal := func(v uint32) uint32 {
		if hardOverride || v == 0 {
			return targetTTL
		}
		if v < minFloor {
			v = minFloor
		}
		if maxCeil > 0 && v > maxCeil {
			v = maxCeil
		}
		if targetTTL > 0 && v > targetTTL {
			v = targetTTL
		}
		return v
	}

	cp.Header().Ttl = clampVal(cp.Header().Ttl)
	if soa, ok := cp.(*dns.SOA); ok {
		soa.Minttl = clampVal(soa.Minttl)
	}
}

func applyRcodeOnlyWireTTL(msg *dns.Msg) {
	if msg == nil || hasAnyRRSIG(msg) {
		return
	}
	minAnsTTL := ^uint32(0)
	if len(msg.Answer) > 0 {
		minFloor := uint32(cfg.Cache.MinTTL)
		maxCeil := uint32(cfg.Cache.MaxTTL)
		for i, rr := range msg.Answer {
			if rr == nil || rr.Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			t := rr.Header().Ttl
			nt := t
			if minFloor > 0 && nt < minFloor {
				nt = minFloor
			}
			if maxCeil > 0 && nt > maxCeil {
				nt = maxCeil
			}
			if nt != t {
				cp := dns.Copy(rr)
				cp.Header().Ttl = nt
				msg.Answer[i] = cp
			}
			if nt < minAnsTTL {
				minAnsTTL = nt
			}
		}
		if msg.Rcode == dns.RcodeSuccess {
			return
		}
	}
	if len(msg.Ns) == 0 {
		return
	}
	switch msg.Rcode {
	case dns.RcodeFormatError, dns.RcodeBadCookie, dns.RcodeBadSig, dns.RcodeBadKey, dns.RcodeBadTime, dns.RcodeBadMode, dns.RcodeBadName, dns.RcodeBadAlg, dns.RcodeBadTrunc:
		return
	}
	hasRcodeConfig := cfg.Cache.RcodeTTL > 0 || cfg.Cache.RcodeMinTTL > 0 || cfg.Cache.RcodeMaxTTL > 0
	hasTTLConfig := hasRcodeConfig || cfg.Cache.NegativeTTL > 0 || cfg.Cache.MinTTL > 0 || cfg.Cache.MaxTTL > 0
	if !hasTTLConfig && minAnsTTL == ^uint32(0) {
		return
	}
	if minAnsTTL == 0 {
		for i, rr := range msg.Ns {
			if rr == nil || rr.Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			cp := dns.Copy(rr)
			cp.Header().Ttl = 0
			if soa, ok := cp.(*dns.SOA); ok {
				soa.Minttl = 0
			}
			msg.Ns[i] = cp
		}
		return
	}
	authTTL, hasAuth := extractAuthorityTTL(msg.Ns)
	if !hasAuth && msg.Authoritative {
		authTTL = syntheticTTL
		hasAuth = true
	}
	targetTTL := computeRcodeOnlyTTL(authTTL, hasAuth, msg.Rcode)
	if minAnsTTL != ^uint32(0) && (targetTTL == 0 || minAnsTTL < targetTTL) {
		targetTTL = minAnsTTL
	}
	if targetTTL == 0 {
		return
	}
	for i, rr := range msg.Ns {
		cp := dns.Copy(rr)
		rewriteAuthorityTTLInPlace(cp, targetTTL, msg.Rcode)
		msg.Ns[i] = cp
	}
}

func isValidBailiwickName(names []string, name string) bool {
	for _, v := range names {
		if v == name {
			return true
		}
	}
	return false
}

func hasDotSuffix(s, suffix string) bool {
	if len(s) <= len(suffix) {
		return false
	}
	cut := len(s) - len(suffix)
	return s[cut-1] == '.' && s[cut:] == suffix
}

// walkBailiwickChain builds the set of in-bailiwick owner names (lowercased FQDN)
// by walking CNAME and RFC 6672 DNAME chains up to maxDepth iterations.
func walkBailiwickChain(rrs []dns.RR, initialQName string, maxDepth int, stackBuf *[64]string) (validNames []string, minAliasTTL uint32, exceeded bool) {
	validNames = stackBuf[:0]
	minAliasTTL = ^uint32(0)

	if initialQName != "" {
		validNames = append(validNames, strings.ToLower(initialQName))
	}

	if maxDepth <= 0 {
		maxDepth = 16
	}

	depth := 0
	for {
		added := false
		for _, rr := range rrs {
			ansName := strings.ToLower(rr.Header().Name)
			switch r := rr.(type) {
			case *dns.CNAME:
				if len(validNames) == 0 || isValidBailiwickName(validNames, ansName) {
					if len(validNames) == 0 {
						validNames = append(validNames, ansName)
					}
					if r.Hdr.Ttl < minAliasTTL {
						minAliasTTL = r.Hdr.Ttl
					}
					target := strings.ToLower(r.Target)
					if !isValidBailiwickName(validNames, target) {
						if len(validNames) >= 64 {
							return validNames, minAliasTTL, true
						}
						validNames = append(validNames, target)
						added = true
					}
				}
			case *dns.DNAME:
				for _, vn := range validNames {
					if hasDotSuffix(vn, ansName) {
						if r.Hdr.Ttl < minAliasTTL {
							minAliasTTL = r.Hdr.Ttl
						}
						if !isValidBailiwickName(validNames, ansName) {
							if len(validNames) >= 64 {
								return validNames, minAliasTTL, true
							}
							validNames = append(validNames, ansName)
							added = true
						}
						prefix := vn[:len(vn)-len(ansName)]
						synthTarget := prefix + strings.ToLower(r.Target)
						if len(synthTarget) <= 254 && !isValidBailiwickName(validNames, synthTarget) {
							if len(validNames) >= 64 {
								return validNames, minAliasTTL, true
							}
							validNames = append(validNames, synthTarget)
							added = true
						}
					}
				}
			}
		}
		if !added {
			break
		}
		depth++
		if depth > maxDepth {
			return validNames, minAliasTTL, true
		}
	}
	return validNames, minAliasTTL, false
}

func isAllowedAnswerRR(rr dns.RR, qtype uint16, doBit bool) bool {
	if rr == nil {
		return false
	}
	hdr := rr.Header()
	if hdr.Class != dns.ClassINET && qtype != dns.TypeANY {
		return false
	}
	rt := hdr.Rrtype
	if qtype == dns.TypeANY {
		if rt == dns.TypeOPT {
			return false
		}
		if rt == dns.TypeRRSIG && !doBit {
			return false
		}
		return true
	}
	if rt == qtype || rt == dns.TypeCNAME || rt == dns.TypeDNAME {
		return true
	}
	if sig, ok := rr.(*dns.RRSIG); ok && doBit {
		return sig.TypeCovered == qtype || sig.TypeCovered == dns.TypeCNAME || sig.TypeCovered == dns.TypeDNAME
	}
	return false
}

func isAllowedAuthorityRR(rr dns.RR, doBit bool) bool {
	if rr == nil {
		return false
	}
	hdr := rr.Header()
	if hdr.Class != dns.ClassINET {
		return false
	}
	switch hdr.Rrtype {
	case dns.TypeSOA, dns.TypeNS:
		return true
	case dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
		return doBit
	case dns.TypeRRSIG:
		if !doBit {
			return false
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			switch sig.TypeCovered {
			case dns.TypeSOA, dns.TypeNS, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
				return true
			}
		}
	}
	return false
}

func stripRRSIGRecords(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	hasSig := false
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasSig = true
			break
		}
	}
	if !hasSig {
		return rrs
	}
	clean := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeRRSIG {
			clean = append(clean, rr)
		}
	}
	return clean
}

func rotateAnswersInPlace(msg *dns.Msg, offset uint32) {
	if msg == nil || len(msg.Answer) < 2 {
		return
	}

	var aIdxBuf [16]int
	var aaaaIdxBuf [16]int
	aIdx := aIdxBuf[:0]
	aaaaIdx := aaaaIdxBuf[:0]

	for i, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			aIdx = append(aIdx, i)
		case dns.TypeAAAA:
			aaaaIdx = append(aaaaIdx, i)
		}
	}

	rotate := func(idx []int) {
		n := len(idx)
		if n < 2 {
			return
		}
		shift := int(offset % uint32(n))
		if shift == 0 {
			return
		}

		var origBuf [16]dns.RR
		var orig []dns.RR
		if n <= 16 {
			orig = origBuf[:n]
		} else {
			orig = make([]dns.RR, n)
		}

		for i, pos := range idx {
			orig[i] = msg.Answer[pos]
		}
		for i, pos := range idx {
			msg.Answer[pos] = orig[(i+shift)%n]
		}
	}

	rotate(aIdx)
	rotate(aaaaIdx)
}

func syncQuestionCasing(out *dns.Msg, qName string) {
	if qName == "" || len(out.Question) == 0 {
		return
	}
	if out.Question[0].Name == qName {
		return
	}
	qCopy := make([]dns.Question, len(out.Question))
	copy(qCopy, out.Question)
	qCopy[0].Name = qName
	out.Question = qCopy

	for _, rr := range out.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return
		}
	}
	for _, rr := range out.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return
		}
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return
		}
	}

	for _, rr := range out.Answer {
		if strings.EqualFold(rr.Header().Name, qName) {
			rr.Header().Name = qName
		}
	}
	for _, rr := range out.Ns {
		if strings.EqualFold(rr.Header().Name, qName) {
			rr.Header().Name = qName
		}
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT && strings.EqualFold(rr.Header().Name, qName) {
			rr.Header().Name = qName
		}
	}
}

func inspectRRSIGBounds(msg *dns.Msg, nowUnix uint32) (hasRRSIG bool, maxSigTTL uint32, sigExpired bool) {
	maxSigTTL = ^uint32(0)
	checkSection := func(rrs []dns.RR) {
		for _, rr := range rrs {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}
			hasRRSIG = true
			if !sig.ValidityPeriod(time.Unix(int64(nowUnix), 0)) {
				sigExpired = true
				maxSigTTL = 0
				return
			}
			if sig.Expiration <= nowUnix {
				sigExpired = true
				maxSigTTL = 0
				return
			}
			rem := sig.Expiration - nowUnix
			if rem < maxSigTTL {
				maxSigTTL = rem
			}
			if sig.Hdr.Ttl > 0 && sig.Hdr.Ttl < maxSigTTL {
				maxSigTTL = sig.Hdr.Ttl
			}
		}
	}
	checkSection(msg.Answer)
	if !sigExpired {
		checkSection(msg.Ns)
	}
	if !sigExpired {
		checkSection(msg.Extra)
	}
	return
}

// ---------------------------------------------------------------------------
// Public read/write API
// ---------------------------------------------------------------------------

func CacheGet(key DNSCacheKey, qName string, out *dns.Msg) (isStale bool, isPrefetch bool, ok bool, isSynth bool) {
	if !cfg.Cache.Enabled {
		return false, false, false, false
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	if !found {
		return false, false, false, false
	}

	nowTime := time.Now()
	now := nowTime.UnixNano()

	if now >= item.staleNano {
		return false, false, false, false
	}

	isStale = now >= item.expireNano
	if isStale && !staleEnabled {
		return false, false, false, false
	}

	var remaining uint32
	if !isStale {
		r := item.expireNano - now
		if r < int64(time.Second) {
			if !staleEnabled {
				return false, false, false, false
			}
			isStale = true
			remaining = 1
		} else {
			remaining = uint32(r / int64(time.Second))
		}
	} else {
		remaining = 1
	}

	packedData := item.packed.Load()
	if packedData == nil {
		return false, false, false, false
	}
	if err := out.Unpack(*packedData); err != nil {
		return false, false, false, false
	}

	hasRRSIG, maxSigTTL, sigExpired := inspectRRSIGBounds(out, uint32(nowTime.Unix()))
	if hasRRSIG {
		if sigExpired || maxSigTTL == 0 {
			return false, false, false, false
		}
		if maxSigTTL < remaining {
			remaining = maxSigTTL
		}
	}

	out.RecursionDesired = key.RecursionDesired
	syncQuestionCasing(out, qName)

	var elapsed uint32
	if item.cachedAtNano > 0 && now > item.cachedAtNano {
		elapsed = uint32((now - item.cachedAtNano) / int64(time.Second))
	}

	decayRR := func(origTTL uint32) uint32 {
		if isStale {
			return remaining
		}
		var decayed uint32
		if origTTL > elapsed {
			decayed = origTTL - elapsed
		} else {
			decayed = 1
		}
		if decayed > remaining {
			decayed = remaining
		}
		if decayed == 0 {
			decayed = 1
		}
		return decayed
	}

	for _, rr := range out.Answer {
		rr.Header().Ttl = decayRR(rr.Header().Ttl)
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = decayRR(rr.Header().Ttl)
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = decayRR(rr.Header().Ttl)
		}
	}

	if cacheRotateAnswers {
		rotateAnswersInPlace(out, item.rotation.Add(1))
	}

	currentHits := item.hits.Add(1)

	isSynthetic := item.routeName == ""
	triggerBG := false

	if !isSynthetic {
		if isStale {
			triggerBG = true
		} else if hasPrefetch && remaining > 0 && remaining <= uint32(cfg.Cache.PrefetchBefore) && currentHits >= uint32(cfg.Cache.PrefetchMinHits) {
			triggerBG = true
			isPrefetch = true
		}
	}

	if triggerBG && item.prefetched.CompareAndSwap(false, true) {
		revertGate := func() {
			item.prefetched.Store(false)
		}
		TriggerBackgroundRevalidate(key, item.routeName, key.ClientName, currentHits, revertGate)
	}

	return isStale, isPrefetch, true, isSynthetic
}

func CacheGetExpired(key DNSCacheKey, qName string, out *dns.Msg) bool {
	if !cfg.Cache.Enabled {
		return false
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	if !found || item.routeName == "" {
		return false
	}

	packedData := item.packed.Load()
	if packedData == nil {
		return false
	}
	if err := out.Unpack(*packedData); err != nil {
		return false
	}

	hasRRSIG, maxSigTTL, sigExpired := inspectRRSIGBounds(out, uint32(time.Now().Unix()))
	if hasRRSIG && (sigExpired || maxSigTTL == 0) {
		return false
	}

	out.RecursionDesired = key.RecursionDesired
	syncQuestionCasing(out, qName)

	staleTTL := uint32(30)
	if hasRRSIG && maxSigTTL < staleTTL {
		staleTTL = maxSigTTL
	}

	for _, rr := range out.Answer {
		if rr.Header().Ttl == 0 || staleTTL < rr.Header().Ttl {
			rr.Header().Ttl = staleTTL
		}
	}
	for _, rr := range out.Ns {
		if rr.Header().Ttl == 0 || staleTTL < rr.Header().Ttl {
			rr.Header().Ttl = staleTTL
		}
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			if rr.Header().Ttl == 0 || staleTTL < rr.Header().Ttl {
				rr.Header().Ttl = staleTTL
			}
		}
	}

	if cacheRotateAnswers {
		rotateAnswersInPlace(out, item.rotation.Add(1))
	}

	return true
}

func CacheSet(key DNSCacheKey, msg *dns.Msg, routeName string) {
	if !cfg.Cache.Enabled || msg == nil || msg.Truncated {
		return
	}

	isRcodeOnly := len(msg.Answer) == 0 || msg.Rcode != dns.RcodeSuccess
	if isRcodeOnly && !cacheUpstreamNeg {
		return
	}

	hasExplicitRcodeTTL := cfg.Cache.RcodeTTL > 0 || cfg.Cache.RcodeMinTTL > 0
	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	case dns.RcodeFormatError, dns.RcodeBadCookie, dns.RcodeBadSig, dns.RcodeBadKey, dns.RcodeBadTime, dns.RcodeBadMode, dns.RcodeBadName, dns.RcodeBadAlg, dns.RcodeBadTrunc:
		return
	default:
		if !hasExplicitRcodeTTL {
			return
		}
	}

	// Bailiwick & RRType Cache-Poisoning Prevention
	if len(msg.Question) != 1 {
		if logCaching || logSystem {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Invalid Question count (%d).", key.Name, len(msg.Question))
		}
		return
	}

	qName := strings.ToLower(msg.Question[0].Name)
	cleanQName := strings.TrimSuffix(qName, ".")

	if cleanQName != key.Name || msg.Question[0].Qtype != key.Qtype || msg.Question[0].Qclass != key.Qclass {
		if logCaching || logSystem {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response. Question section (%q/%d/%d) does not match requested cache key (%q/%d/%d).",
				cleanQName, msg.Question[0].Qtype, msg.Question[0].Qclass, key.Name, key.Qtype, key.Qclass)
		}
		return
	}

	var validStack [64]string
	validNames, _, exceeded := walkBailiwickChain(msg.Answer, qName, 16, &validStack)
	if exceeded {
		if logCaching || logSystem {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME/DNAME chain exceeds maximum safe limit.", qName)
		}
		return
	}

	cacheMsg := *msg
	cacheMsg.Id = 0
	cacheMsg.Extra = nil
	if !key.DoBit {
		if key.Qtype != dns.TypeRRSIG {
			cacheMsg.Answer = stripRRSIGRecords(cacheMsg.Answer)
		}
		cacheMsg.Ns = stripRRSIGRecords(cacheMsg.Ns)
		cacheMsg.AuthenticatedData = false
	}

	if len(cacheMsg.Answer) > 0 {
		for i, rr := range cacheMsg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			if !isValidBailiwickName(validNames, ansName) {
				if logCaching || logSystem {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Record %d (%q) breaks Bailiwick/CNAME chain.", qName, i, ansName)
				}
				return
			}
			if !isAllowedAnswerRR(rr, key.Qtype, key.DoBit) {
				if logCaching || logSystem {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Unexpected Answer RRtype %s for query type %s.",
						qName, qtypeName(rr.Header().Rrtype), qtypeName(key.Qtype))
				}
				return
			}
		}
	}

	if len(cacheMsg.Ns) > 0 {
		for i, rr := range cacheMsg.Ns {
			if !isAllowedAuthorityRR(rr, key.DoBit) {
				if logCaching || logSystem {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Disallowed Authority RRtype %s in Ns section.",
						qName, qtypeName(rr.Header().Rrtype))
				}
				return
			}

			ansName := strings.ToLower(rr.Header().Name)
			isValid := ansName == "."
			if !isValid {
				for _, vn := range validNames {
					if ansName == vn || hasDotSuffix(vn, ansName) {
						isValid = true
						break
					}
				}
			}

			cleanAnsName := strings.TrimSuffix(ansName, ".")
			if isValid && cleanAnsName != key.Name {
				isDelegationNS := rr.Header().Rrtype == dns.TypeNS
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNS {
					isDelegationNS = true
				}
				if isDelegationNS && (ansName == "." || isPublicSuffix(cleanAnsName)) {
					isValid = false
				}
			}

			if !isValid {
				if logCaching || logSystem {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Authority Record %d (%q) breaks Bailiwick.", qName, i, ansName)
				}
				return
			}
		}
	}

	isRcodeOnlyAfterClean := len(cacheMsg.Answer) == 0 || cacheMsg.Rcode != dns.RcodeSuccess
	if isRcodeOnlyAfterClean && !cacheUpstreamNeg {
		return
	}

	nowTime := time.Now()
	now := nowTime.UnixNano()
	hasRRSIG, maxSigTTL, sigExpired := inspectRRSIGBounds(&cacheMsg, uint32(nowTime.Unix()))
	if hasRRSIG && (sigExpired || maxSigTTL == 0) {
		return
	}

	var ttl uint32
	if !isRcodeOnlyAfterClean {
		ttl = ^uint32(0)
		for _, rr := range cacheMsg.Answer {
			if rr.Header().Rrtype == dns.TypeRRSIG && key.Qtype != dns.TypeRRSIG {
				continue
			}
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
		if ttl == ^uint32(0) {
			ttl = maxSigTTL
		}
		if ttl < uint32(cfg.Cache.MinTTL) {
			ttl = uint32(cfg.Cache.MinTTL)
		}
		if hasRRSIG && maxSigTTL < ttl {
			ttl = maxSigTTL
		}
		if cfg.Cache.MaxTTL > 0 && ttl > uint32(cfg.Cache.MaxTTL) {
			ttl = uint32(cfg.Cache.MaxTTL)
		}
	} else {
		authTTL, hasAuth := extractAuthorityTTL(cacheMsg.Ns)
		if hasRRSIG && authTTL == 0 {
			authTTL = maxSigTTL
			hasAuth = true
		}
		ttl = computeRcodeOnlyTTL(authTTL, hasAuth, cacheMsg.Rcode)
		if hasRRSIG && maxSigTTL < ttl {
			ttl = maxSigTTL
		}
	}

	if ttl == 0 || ttl == ^uint32(0) {
		return
	}

	if len(cacheMsg.Answer) > 0 {
		minFloor := ttl
		if isRcodeOnlyAfterClean {
			minFloor = uint32(cfg.Cache.MinTTL)
		}
		maxCeil := uint32(cfg.Cache.MaxTTL)
		if hasRRSIG && (maxCeil == 0 || maxSigTTL < maxCeil) {
			maxCeil = maxSigTTL
		}
		minAnsTTL := ^uint32(0)
		ansCopy := make([]dns.RR, len(cacheMsg.Answer))
		for i, rr := range cacheMsg.Answer {
			cp := dns.Copy(rr)
			t := cp.Header().Ttl
			isSig := cp.Header().Rrtype == dns.TypeRRSIG
			if !hasRRSIG && !isSig {
				if minFloor > 0 && t < minFloor {
					t = minFloor
				}
				if maxCeil > 0 && t > maxCeil {
					t = maxCeil
				}
				cp.Header().Ttl = t
			}
			if (!isSig || key.Qtype == dns.TypeRRSIG) && t < minAnsTTL {
				minAnsTTL = t
			}
			ansCopy[i] = cp
		}
		cacheMsg.Answer = ansCopy
		if isRcodeOnlyAfterClean && minAnsTTL != ^uint32(0) && minAnsTTL < ttl {
			ttl = minAnsTTL
		}
		if ttl == 0 {
			return
		}
	}
	if isRcodeOnlyAfterClean && !hasRRSIG && len(cacheMsg.Ns) > 0 {
		nsCopy := make([]dns.RR, len(cacheMsg.Ns))
		for i, rr := range cacheMsg.Ns {
			cp := dns.Copy(rr)
			rewriteAuthorityTTLInPlace(cp, ttl, cacheMsg.Rcode)
			nsCopy[i] = cp
		}
		cacheMsg.Ns = nsCopy
	}

	expireNano := now + int64(ttl)*int64(time.Second)
	staleNano := expireNano
	if staleEnabled {
		staleWindow := int64(cfg.Cache.StaleTTL) * int64(time.Second)
		if hasRRSIG {
			sigMaxNano := now + int64(maxSigTTL)*int64(time.Second)
			if expireNano+staleWindow > sigMaxNano {
				staleNano = sigMaxNano
			} else {
				staleNano = expireNano + staleWindow
			}
		} else {
			staleNano = expireNano + staleWindow
		}
	}

	bufp := largeBufPool.Get().(*[]byte)
	packed, err := cacheMsg.PackBuffer((*bufp)[:0])
	if err != nil {
		largeBufPool.Put(bufp)
		if logCaching || logSystem {
			log.Printf("[CACHE] WARNING: CacheSet pack failed for %q: %v", key.Name, err)
		}
		return
	}
	stored := make([]byte, len(packed))
	copy(stored, packed)
	largeBufPool.Put(bufp)

	ci := &cacheItem{
		expireNano:   expireNano,
		staleNano:    staleNano,
		cachedAtNano: now,
		routeName:    routeName,
	}
	ci.packed.Store(&stored)
	storeItem(key, ci)
}

func CacheSetSynth(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil || msg.Truncated {
		return
	}

	cacheMsg := *msg
	cacheMsg.Id = 0
	cacheMsg.Extra = nil

	ttl := syntheticTTL
	isRcodeOnly := len(cacheMsg.Answer) == 0 || cacheMsg.Rcode != dns.RcodeSuccess
	minRRTTL := ^uint32(0)

	if len(cacheMsg.Answer) > 0 {
		minFloor := uint32(cfg.Cache.MinTTL)
		maxCeil := uint32(cfg.Cache.MaxTTL)
		ansCopy := make([]dns.RR, len(cacheMsg.Answer))
		for i, rr := range cacheMsg.Answer {
			cp := dns.Copy(rr)
			t := cp.Header().Ttl
			if t == 0 {
				t = syntheticTTL
			}
			if minFloor > 0 && t < minFloor {
				t = minFloor
			}
			if maxCeil > 0 && t > maxCeil {
				t = maxCeil
			}
			cp.Header().Ttl = t
			if t < minRRTTL {
				minRRTTL = t
			}
			ansCopy[i] = cp
		}
		cacheMsg.Answer = ansCopy
		if !isRcodeOnly && minRRTTL != ^uint32(0) && minRRTTL > 0 {
			ttl = minRRTTL
		}
	}

	hasRcodeConfig := cfg.Cache.RcodeTTL > 0 || cfg.Cache.RcodeMinTTL > 0 || cfg.Cache.RcodeMaxTTL > 0
	if isRcodeOnly {
		authTTL, hasAuth := extractAuthorityTTL(cacheMsg.Ns)
		if !hasAuth {
			authTTL = syntheticTTL
			hasAuth = true
		}
		if hasRcodeConfig || cfg.Cache.NegativeTTL > 0 || cfg.Cache.MinTTL > 0 || cfg.Cache.MaxTTL > 0 {
			if rTTL := computeRcodeOnlyTTL(authTTL, hasAuth, cacheMsg.Rcode); rTTL > 0 {
				ttl = rTTL
			}
		} else if authTTL > 0 {
			ttl = authTTL
		}
		if minRRTTL != ^uint32(0) && minRRTTL > 0 && minRRTTL < ttl {
			ttl = minRRTTL
		}
		if len(cacheMsg.Ns) > 0 {
			nsCopy := make([]dns.RR, len(cacheMsg.Ns))
			for i, rr := range cacheMsg.Ns {
				cp := dns.Copy(rr)
				rewriteAuthorityTTLInPlace(cp, ttl, cacheMsg.Rcode)
				nsCopy[i] = cp
			}
			cacheMsg.Ns = nsCopy
		}
	}

	if ttl == 0 {
		ttl = 1
	}

	now := time.Now().UnixNano()
	expireNano := now + int64(ttl)*int64(time.Second)

	bufp := largeBufPool.Get().(*[]byte)
	packed, err := cacheMsg.PackBuffer((*bufp)[:0])
	if err != nil {
		largeBufPool.Put(bufp)
		if logCaching || logSystem {
			log.Printf("[CACHE] WARNING: CacheSetSynth pack failed for %q: %v", key.Name, err)
		}
		return
	}
	stored := make([]byte, len(packed))
	copy(stored, packed)
	largeBufPool.Put(bufp)

	ci := &cacheItem{
		expireNano:   expireNano,
		staleNano:    expireNano,
		cachedAtNano: now,
		routeName:    "",
	}
	ci.packed.Store(&stored)
	storeItem(key, ci)
}
