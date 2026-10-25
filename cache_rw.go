/*
File:    cache_rw.go
Version: 1.17.0 (Split)
Last Updated: 25-Oct-2026 15:40 CET

Description:
  Hot-path Read/Write operations for the sdproxy cache engine.
  Handles packing/unpacking dns.Msg structures, TTL rewrites, background
  revalidation tracking, and strict RFC bailiwick security enforcement.

  Extracted from cache.go to prioritize hot-path execution clarity.

Changes:
  1.17.0 - [SECURITY/FIX] Restricted `CacheGetExpired` to eligible upstream responses
           (`item.routeName != ""`), preventing expired synthetic policy blocks or
           stale local-identity records from being served indefinitely under
           `serve_stale_infinite`.
         - [SECURITY/FIX] Enforced strict DNSSEC cache lifetime bounds in `CacheSet`:
           signed responses (`hasRRSIG`) are never extended past their original
           upstream TTL by `cache.min_ttl` or `cache.negative_ttl`, and their cache
           lifetime is capped by the earliest `RRSIG.Expiration` timestamp.
         - [SECURITY/FIX] Explicitly restored `out.RecursionDesired = key.RecursionDesired`
           in `CacheGet` and `CacheGetExpired`.
  1.16.0 - [SECURITY/FIX] Hardened `syncQuestionCasing` to only rewrite `out.Answer`
           owner names when no `CNAME` records are present in `out.Answer`, and to
           rewrite `out.Ns` SOA owner names when no `RRSIG` is present in `out.Ns`.
  1.15.0 - [SECURITY/FIX] Extended `syncQuestionCasing` to also synchronize direct
           owner names in `out.Extra` (e.g., DDR/HTTPS glue records) when no `RRSIG`
           records are present, and ensured `out.Question` slice is isolated before
           mutation.
  1.14.0 - [SECURITY/FIX] Extended `syncQuestionCasing` to synchronize `out.Ns`
           owner names when they match `qName` case-insensitively and no `RRSIG`
           records are present.
  1.13.0 - [SECURITY/FIX] Rewrote matching terminal record owner names in `CacheGet`
           and `CacheGetExpired` when the cached answer has no CNAME records.
  1.12.0 - [SECURITY/FIX] Bounded `validNames` growth in `CacheSet` to 64 entries.
  1.11.0 - [SECURITY/FIX] Rewrote `out.Question[0].Name` on cache hits in `CacheGet`
           and `CacheGetExpired` to match the incoming query's exact case (`q.Name`).
  1.10.0 - [SECURITY/FIX] Enforced `TC=1` truncation guard inside `CacheSetSynth`.
  1.9.0  - [SECURITY/FIX] Hardened `CacheSet` Authority Section (Ns) validations natively.
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

func stripOPTRecords(extra []dns.RR) []dns.RR {
	if len(extra) == 0 {
		return nil
	}
	hasOpt := false
	for _, rr := range extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			hasOpt = true
			break
		}
	}
	if !hasOpt {
		return extra
	}

	clean := make([]dns.RR, 0, len(extra)-1)
	for _, rr := range extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			clean = append(clean, rr)
		}
	}
	if len(clean) == 0 {
		return nil
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
		case dns.TypeCNAME:
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

// inspectRRSIGBounds scans msg for RRSIG records, returning whether any RRSIG
// is present and the minimum remaining cryptographic signature validity in seconds.
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
			rem := uint32(int32(sig.Expiration - nowUnix))
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

// CacheGet unpacks a cached response into the caller-provided *dns.Msg
// and returns status flags alongside the active cache hit count.
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

	now := time.Now().UnixNano()

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
	if err := out.Unpack(*packedData); err != nil {
		return false, false, false, 0
	}

	out.RecursionDesired = key.RecursionDesired
	syncQuestionCasing(out, qName)

	for _, rr := range out.Answer {
		rr.Header().Ttl = remaining
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = remaining
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = remaining
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

// CacheGetExpired retrieves an expired upstream cached record as an emergency
// fallback when upstream exchanges fail and serve_stale_infinite is enabled.
// Synthetic responses (item.routeName == "") are strictly excluded.
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
	if err := out.Unpack(*packedData); err != nil {
		return false
	}

	out.RecursionDesired = key.RecursionDesired
	syncQuestionCasing(out, qName)

	for _, rr := range out.Answer {
		rr.Header().Ttl = 30
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = 30
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = 30
		}
	}

	if cacheRotateAnswers {
		rotateAnswersInPlace(out, item.rotation.Add(1))
	}

	return true
}

// CacheSet packs msg into wire format and stores it under key.
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
	// [SECURITY] Bailiwick / cache-poisoning prevention
	// ---------------------------------------------------------------------------
	if len(msg.Question) == 0 {
		if logCaching {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Missing Question section.", key.Name)
		}
		return
	}

	qName := strings.ToLower(msg.Question[0].Name)
	cleanQName := strings.TrimSuffix(qName, ".")

	if cleanQName != key.Name {
		if logCaching {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response. Question section (%q) does not match requested cache key (%q).", cleanQName, key.Name)
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
			if isValidBailiwickName(validNames, ansName) {
				if cname, ok := rr.(*dns.CNAME); ok {
					target := strings.ToLower(cname.Target)
					if !isValidBailiwickName(validNames, target) {
						if len(validNames) >= 64 {
							if logCaching {
								log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME target count exceeds maximum safe limit.", qName)
							}
							return
						}
						validNames = append(validNames, target)
						added = true
					}
				}
			}
		}
		if !added {
			break
		}
		chainDepth++
		if chainDepth > 16 {
			if logCaching {
				log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME chain exceeds maximum safe parsing depth.", qName)
			}
			return
		}
	}

	if len(msg.Answer) > 0 {
		for i, rr := range msg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			if !isValidBailiwickName(validNames, ansName) {
				if logCaching {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Record %d (%q) breaks Bailiwick/CNAME chain.", qName, i, ansName)
				}
				return
			}
		}
	}

	if len(msg.Ns) > 0 {
		for i, rr := range msg.Ns {
			ansName := strings.ToLower(rr.Header().Name)
			isValid := false

			for _, vn := range validNames {
				if ansName == vn || hasDotSuffix(vn, ansName) || hasDotSuffix(ansName, vn) {
					isValid = true
					break
				}
			}

			cleanAnsName := strings.TrimSuffix(ansName, ".")
			if isValid && cleanAnsName != key.Name && isPublicSuffix(cleanAnsName) {
				isValid = false
			}

			if !isValid {
				if logCaching {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Authority Record %d (%q) breaks Bailiwick.", qName, i, ansName)
				}
				return
			}
		}
	}

	cacheMsg := *msg
	cacheMsg.Extra = stripOPTRecords(cacheMsg.Extra)

	nowTime := time.Now()
	now := nowTime.UnixNano()
	hasRRSIG, maxSigTTL, sigExpired := inspectRRSIGBounds(&cacheMsg, uint32(nowTime.Unix()))
	if hasRRSIG && (sigExpired || maxSigTTL == 0) {
		return
	}

	var ttl uint32
	if !isNeg {
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
				if soa.Minttl < ttl {
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
		} else if cfg.Cache.NegativeTTL > 0 && uint32(cfg.Cache.NegativeTTL) < ttl {
			ttl = uint32(cfg.Cache.NegativeTTL)
		}
	}

	// [SECURITY/FIX 1.17.0] Never artificially raise DNSSEC-signed record TTLs
	// above the upstream's original TTL or RRSIG cryptographic validity window.
	if !hasRRSIG {
		effectiveMin := uint32(cfg.Cache.MinTTL)
		if isNeg && cfg.Cache.NegativeTTL > 0 {
			effectiveMin = uint32(cfg.Cache.NegativeTTL)
		}
		if ttl < effectiveMin {
			ttl = effectiveMin
		}
	} else if maxSigTTL < ttl {
		ttl = maxSigTTL
	}

	if cfg.Cache.MaxTTL > 0 && ttl > uint32(cfg.Cache.MaxTTL) {
		ttl = uint32(cfg.Cache.MaxTTL)
	}
	if ttl == 0 || ttl == ^uint32(0) {
		return
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
		if logCaching {
			log.Printf("[CACHE] CacheSet: pack failed for %q: %v", key.Name, err)
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

// CacheSetSynth stores a synthesised sdproxy response (any RCODE) at a fixed
// syntheticTTL.
func CacheSetSynth(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	if msg.Truncated {
		return
	}

	now := time.Now().UnixNano()
	expireNano := now + int64(syntheticTTL)*int64(time.Second)

	bufp := largeBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufp)[:0])
	if err != nil {
		largeBufPool.Put(bufp)
		if logCaching {
			log.Printf("[CACHE] CacheSetSynth: pack failed for %q: %v", key.Name, err)
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

// CacheUpdateOrder atomically swaps the packed bytes of an existing cache item.
func CacheUpdateOrder(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()

	if !found {
		return
	}

	cacheMsg := *msg
	cacheMsg.Extra = stripOPTRecords(cacheMsg.Extra)

	bufp := largeBufPool.Get().(*[]byte)
	packed, err := cacheMsg.PackBuffer((*bufp)[:0])
	if err == nil {
		stored := make([]byte, len(packed))
		copy(stored, packed)
		item.packed.Store(&stored)
	}
	largeBufPool.Put(bufp)
}
