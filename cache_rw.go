/*
File:    cache_rw.go
Version: 1.34.0 (Split)
Last Updated: 12-Nov-2026 16:55 CET

Description:
  Hot-path Read/Write operations for the sdproxy cache engine.
  Handles packing/unpacking dns.Msg structures, TTL rewrites, background
  revalidation tracking, and strict RFC bailiwick security enforcement.

  Extracted from cache.go to prioritize hot-path execution clarity.

Changes:
  1.34.0 - [SECURITY/FIX] Tightened Authority (`Ns`) bailiwick validation in
           `CacheSet` so authority records must be equal to or an ancestor zone
           of a valid query/CNAME chain name (`ansName == vn || hasDotSuffix(vn, ansName)`),
           disallowing child subdomain zones in `Ns`.
  1.33.0 - [SECURITY/FIX] Removed `applyFloor` inflation in `CacheGet`'s `decayRR`
           so answers cached on DNSSEC-signed responses (where `ttl` was capped by
           `maxSigTTL < cfg.Cache.MinTTL`) are never artificially inflated to
           `minFloor` before subtracting `elapsed`, and instead wrote `effectiveMin`
           directly onto answer RRs during `CacheSet` when `rr.Header().Ttl < ttl`.
         - [CLEANUP] Removed dead `CacheUpdateOrder` function.
  1.32.0 - [SECURITY/FIX] Decayed individual record TTLs by elapsed cache time
           (`elapsed = uint32((now - item.cachedAtNano) / int64(time.Second))`)
           in `CacheGet` instead of comparing raw stored wire TTLs against
           `remaining`.
  1.31.0 - [SECURITY/FIX] Preserved original positive `Answer` and `Extra` record
           TTLs on cache hits when `remaining >= rr.Header().Ttl` in `CacheGet`
           and `CacheGetExpired`.
  1.30.0 - [SECURITY/FIX] Enforced `effectiveMin` (`cfg.Cache.MinTTL` /
           `cfg.Cache.NegativeTTL`) on DNSSEC-signed responses (`hasRRSIG == true`)
           in `CacheSet` while capping at `maxSigTTL` so signature expiration is
           never exceeded, and tightened `isAllowedAuthorityRR` to reject `DS`
           records on non-DNSSEC (`doBit == false`) responses.
  1.29.0 - [SECURITY/FIX] Preserved original Authority (`Ns`) SOA records on
           cached negative (`NXDOMAIN` / `NODATA`) responses by only overwriting
           `rr.Header().Ttl` when `remaining < rr.Header().Ttl` in `CacheGet`
           and `CacheGetExpired`, and bounded positive answer TTLs by `minTTL`
           during `CacheSet` without inflating negative SOA TTLs past `NegativeTTL`.
  1.28.0 - [SECURITY/FIX] Fixed negative response TTL derivation in `CacheSet`
           when a negative response (`NXDOMAIN` / `NODATA`) carries DNSSEC
           `RRSIG` records (`hasRRSIG == true`) without an `SOA` record or with
           a zero-TTL `SOA`.
  1.27.0 - [SECURITY/FIX] Enforced live `inspectRRSIGBounds` validation in
           `CacheGet` unconditionally whenever a cached message contains `RRSIG`
           records, and guarded against nil `packedData` pointers in `CacheGet`
           and `CacheGetExpired`.
  1.26.0 - [SECURITY/FIX] Verified `inspectRRSIGBounds` in `CacheGet` when
           `key.DoBit` is set.
  1.25.0 - [SECURITY/FIX] Enforced live `inspectRRSIGBounds` validation in
           `CacheGetExpired` and stripped `RRSIG` records in `CacheSet` when
           `key.DoBit` is false and `key.Qtype == dns.TypeRRSIG` is not requested.
*/

package main

import (
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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
	prevQName := out.Question[0].Name
	if prevQName == qName {
		return
	}
	qCopy := make([]dns.Question, len(out.Question))
	copy(qCopy, out.Question)
	qCopy[0].Name = qName
	out.Question = qCopy

	hasRRSIG := false
	hasCNAME := false
	for _, rr := range out.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG:
			hasRRSIG = true
		case dns.TypeCNAME, dns.TypeDNAME:
			hasCNAME = true
		}
	}
	for _, rr := range out.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasRRSIG = true
			break
		}
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasRRSIG = true
			break
		}
	}
	if hasRRSIG {
		return
	}

	if !hasCNAME {
		for _, rr := range out.Answer {
			if strings.EqualFold(rr.Header().Name, qName) {
				rr.Header().Name = qName
			}
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

func CacheGet(key DNSCacheKey, qName string, out *dns.Msg) (isStale bool, isPrefetch bool, ok bool, hits uint32) {
	if !cfg.Cache.Enabled {
		return false, false, false, 0
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	if !found {
		return false, false, false, 0
	}

	nowTime := time.Now()
	now := nowTime.UnixNano()

	if now >= item.staleNano {
		return false, false, false, 0
	}

	isStale = now >= item.expireNano
	if isStale && !staleEnabled {
		return false, false, false, 0
	}

	var remaining uint32
	if !isStale {
		r := item.expireNano - now
		if r < int64(time.Second) {
			if !staleEnabled {
				return false, false, false, 0
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
		return false, false, false, 0
	}
	if err := out.Unpack(*packedData); err != nil {
		return false, false, false, 0
	}

	hasRRSIG, maxSigTTL, sigExpired := inspectRRSIGBounds(out, uint32(nowTime.Unix()))
	if hasRRSIG {
		if sigExpired || maxSigTTL == 0 {
			return false, false, false, 0
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

	return isStale, isPrefetch, true, currentHits
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
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	if msg.Truncated {
		return
	}

	isNeg := msg.Rcode == dns.RcodeNameError ||
		(msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
	if isNeg && !cacheUpstreamNeg {
		return
	}

	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return
	}

	// ---------------------------------------------------------------------------
	// [SECURITY] Bailiwick & RRType Cache-Poisoning Prevention
	// ---------------------------------------------------------------------------
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
	validNames := validStack[:0]
	validNames = append(validNames, qName)

	chainDepth := 0
	for {
		added := false
		for _, rr := range msg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			switch r := rr.(type) {
			case *dns.CNAME:
				if isValidBailiwickName(validNames, ansName) {
					target := strings.ToLower(r.Target)
					if !isValidBailiwickName(validNames, target) {
						if len(validNames) >= 64 {
							if logCaching || logSystem {
								log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME target count exceeds maximum safe limit.", qName)
							}
							return
						}
						validNames = append(validNames, target)
						added = true
					}
				}
			case *dns.DNAME:
				for _, vn := range validNames {
					if hasDotSuffix(vn, ansName) {
						if !isValidBailiwickName(validNames, ansName) {
							if len(validNames) >= 64 {
								return
							}
							validNames = append(validNames, ansName)
							added = true
						}
						prefix := vn[:len(vn)-len(ansName)]
						synthTarget := prefix + strings.ToLower(r.Target)
						if len(synthTarget) <= 254 && !isValidBailiwickName(validNames, synthTarget) {
							if len(validNames) >= 64 {
								return
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
		chainDepth++
		if chainDepth > 16 {
			if logCaching || logSystem {
				log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME chain exceeds maximum safe parsing depth.", qName)
			}
			return
		}
	}

	cacheMsg := *msg
	cacheMsg.Id = 0
	// Strip all Additional/Extra records (glue, OPT, cookies, ECS) before caching.
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
			isValid := false

			for _, vn := range validNames {
				if ansName == vn || hasDotSuffix(vn, ansName) {
					isValid = true
					break
				}
			}

			cleanAnsName := strings.TrimSuffix(ansName, ".")
			if isValid && cleanAnsName != key.Name && isPublicSuffix(cleanAnsName) {
				isValid = false
			}

			if !isValid {
				if logCaching || logSystem {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Authority Record %d (%q) breaks Bailiwick.", qName, i, ansName)
				}
				return
			}
		}
	}

	isNegAfterClean := cacheMsg.Rcode == dns.RcodeNameError ||
		(cacheMsg.Rcode == dns.RcodeSuccess && len(cacheMsg.Answer) == 0)
	if isNegAfterClean && !cacheUpstreamNeg {
		return
	}

	nowTime := time.Now()
	now := nowTime.UnixNano()
	hasRRSIG, maxSigTTL, sigExpired := inspectRRSIGBounds(&cacheMsg, uint32(nowTime.Unix()))
	if hasRRSIG && (sigExpired || maxSigTTL == 0) {
		return
	}

	var ttl uint32
	if !isNegAfterClean {
		ttl = ^uint32(0)
		for _, rr := range cacheMsg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		for _, rr := range cacheMsg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl = soa.Hdr.Ttl
				if soa.Minttl > 0 && (ttl == 0 || soa.Minttl < ttl) {
					ttl = soa.Minttl
				}
				break
			}
		}
		if !hasRRSIG {
			if cfg.Cache.NegativeTTL > 0 {
				ttl = uint32(cfg.Cache.NegativeTTL)
			} else if ttl == 0 {
				ttl = uint32(cfg.Cache.MinTTL)
			}
		} else {
			if ttl == 0 {
				ttl = maxSigTTL
			}
			if cfg.Cache.NegativeTTL > 0 && uint32(cfg.Cache.NegativeTTL) < ttl {
				ttl = uint32(cfg.Cache.NegativeTTL)
			}
		}
	}

	effectiveMin := uint32(cfg.Cache.MinTTL)
	if isNegAfterClean && cfg.Cache.NegativeTTL > 0 {
		effectiveMin = uint32(cfg.Cache.NegativeTTL)
	}
	if ttl < effectiveMin {
		ttl = effectiveMin
	}
	if hasRRSIG && maxSigTTL < ttl {
		ttl = maxSigTTL
	}

	if cfg.Cache.MaxTTL > 0 && ttl > uint32(cfg.Cache.MaxTTL) {
		ttl = uint32(cfg.Cache.MaxTTL)
	}
	if ttl == 0 || ttl == ^uint32(0) {
		return
	}

	if !isNegAfterClean && len(cacheMsg.Answer) > 0 {
		ansCopy := make([]dns.RR, len(cacheMsg.Answer))
		for i, rr := range cacheMsg.Answer {
			cp := dns.Copy(rr)
			if cp.Header().Ttl < ttl {
				cp.Header().Ttl = ttl
			}
			ansCopy[i] = cp
		}
		cacheMsg.Answer = ansCopy
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
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	if msg.Truncated {
		return
	}

	cacheMsg := *msg
	cacheMsg.Id = 0
	cacheMsg.Extra = nil

	now := time.Now().UnixNano()
	expireNano := now + int64(syntheticTTL)*int64(time.Second)

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
