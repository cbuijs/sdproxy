/*
File:    cache_rw.go
Version: 1.1.0 (Split)
Updated: 10-Jun-2026 10:39 CEST

Description:
  Hot-path Read/Write operations for the sdproxy cache engine.
  Handles packing/unpacking `dns.Msg` structures, TTL rewrites, Background 
  Revalidation tracking, and strict RFC Bailiwick Security Enforcement.

  Extracted from cache.go to prioritize hot-path execution clarity.

Changes:
  1.1.0 - [PERF] Decoupled bailiwick validation closures from the caching engine 
          into a global `isValidBailiwickName` helper to definitively eradicate 
          fractional heap allocations during intense cache-write floods natively.
*/

package main

import (
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// isValidBailiwickName executes a zero-allocation bounds check to ensure
// nested CNAME/NS records respect the established resolution chain natively.
func isValidBailiwickName(names []string, name string) bool {
	for _, v := range names {
		if v == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Public read/write API
// ---------------------------------------------------------------------------

// CacheGet unpacks a cached response into the caller-provided *dns.Msg
// (sourced from msgPool in process.go) and returns status flags alongside
// the active cache hit count.
//
// The caller must zero the message before passing it in: `*out = dns.Msg{}`.
// After WriteMsg the caller returns out to msgPool.
//
//	isStale=false, isPrefetch=false — normal fresh hit.
//	isStale=false, isPrefetch=true  — fresh; background prefetch just fired.
//	isStale=true,  isPrefetch=false — past TTL but inside stale window.
//
// Returns ok=false on a miss or when the stale window has passed.
// out is in an undefined state when ok=false — do not use it.
func CacheGet(key DNSCacheKey, out *dns.Msg) (isStale bool, isPrefetch bool, ok bool, hits uint32) {
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

	// Past the full stale window — treat as miss (sweeper may not have fired yet).
	if now >= item.staleNano {
		return false, false, false, 0
	}

	isStale = now >= item.expireNano
	if isStale && !staleEnabled {
		return false, false, false, 0
	}

	// Remaining TTL in whole seconds. 
	// [RFC COMPLIANCE] We apply a floor of 1 second to stale responses 
	// to prevent strict stub resolvers from entering infinite retry loops 
	// when receiving TTL=0, satisfying RFC 8767 §4.
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

	currentHits := item.hits.Add(1)

	// [SECURITY/FIX] Unified Background Revalidation Gate
	// Safely bounds BOTH prefetch and stale-serve background revalidations behind 
	// a strict atomic CompareAndSwap gate. 
	// We definitively bypass synthetic records (`isSynthetic`) to prevent LAN privacy 
	// leakage and cache corruption via public upstream queries.
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
		// [FIX] Provide a state-reversion callback so saturated background semaphores 
		// do not permanently lock the prefetch gate for this entry.
		revertGate := func() {
			item.prefetched.Store(false)
		}

		// Launch background worker natively passing the popularity index (hits)
		TriggerBackgroundRevalidate(key, item.routeName, key.ClientName, currentHits, revertGate)
	}

	packedData := item.packed.Load()
	if err := out.Unpack(*packedData); err != nil {
		return false, false, false, 0
	}

	// Rewrite TTLs to reflect actual remaining lifetime natively in the payload.
	// OPT (EDNS0) carries flags, not a TTL — always skip it to prevent protocol breakage.
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
	return isStale, isPrefetch, true, currentHits
}

// CacheGetExpired retrieves any cached record natively regardless of its 
// TTL/stale expiration bounds. Used exclusively as an emergency fallback 
// when upstream exchanges fail and serve_stale_infinite is enabled.
func CacheGetExpired(key DNSCacheKey, out *dns.Msg) bool {
	if !cfg.Cache.Enabled {
		return false
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	if !found {
		return false
	}

	packedData := item.packed.Load()
	if err := out.Unpack(*packedData); err != nil {
		return false
	}

	// Force a short 30-second TTL natively so clients don't permanently 
	// cache the dead record, allowing them to retry gracefully later.
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
	return true
}

// CacheSet packs msg into wire format and stores it under key.
//
// TTL derivation:
//   Positive (NOERROR with answers): minimum TTL across all answer RRs.
//   Negative (NXDOMAIN or NODATA):   SOA minimum from authority section;
//                                    falls back to NegativeTTL, then MinTTL.
func CacheSet(key DNSCacheKey, msg *dns.Msg, routeName string) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	// [SECURITY/PERF] Truncation Guard
	// Never cache truncated (TC=1) responses natively returned by the upstream. 
	// If cached, subsequent TCP retries initiated by the client would continuously 
	// receive the identical incomplete cached payload, trapping the client in an 
	// infinite resolution loop and starving file descriptors.
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
	// [SECURITY] Bailiwick / Cache Poisoning Prevention
	// ---------------------------------------------------------------------------
	// Enforce that the provided answers natively belong to the QNAME that 
	// was initially requested, preventing malicious upstreams from slipping 
	// out-of-zone spoofed records into the memory shards (Cache Poisoning).
	
	if len(msg.Question) == 0 {
		if logCaching {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Missing Question section.", key.Name)
		}
		return
	}

	qName := strings.ToLower(msg.Question[0].Name)
	cleanQName := strings.TrimSuffix(qName, ".")
	
	// Rigorously enforce that the upstream echoed the exact target requested.
	if cleanQName != key.Name {
		if logCaching {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response. Question section (%q) does not match requested cache key (%q).", cleanQName, key.Name)
		}
		return
	}

	// [PERF/FIX] Replaced heap-allocated map with stack-allocated slice for 
	// zero-allocation validation during hot-path caching. Drastically mitigates GC thrashing.
	// [PERF] Expanded stack array size to 64 to guarantee that even complex CNAME chains 
	// or multi-target record depths never trigger fallback heap allocations natively.
	var validStack [64]string
	validNames := validStack[:0]
	validNames = append(validNames, qName)
	
	// [FIX] CNAME chains can technically be returned out of sequential order by 
	// intermediate resolvers. We execute an associative pre-discovery loop 
	// to map all valid targets within the chain before enforcing strict verification,
	// neutralizing false-positive cache drops natively.
	// [SECURITY] Enforce strict loop boundaries to prevent CPU exhaustion DoS attacks 
	// against infinitely circular or massive payload chains natively.
	chainDepth := 0
	for {
		added := false
		for _, rr := range msg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			if isValidBailiwickName(validNames, ansName) {
				if cname, ok := rr.(*dns.CNAME); ok {
					target := strings.ToLower(cname.Target)
					if !isValidBailiwickName(validNames, target) {
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

	// Validate Answer Section against the fully discovered chain map
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

	// Validate Authority (Ns) Section against the discovered chain.
	// Thwarts malicious upstreams from injecting out-of-zone NS/SOA records.
	if len(msg.Ns) > 0 {
		for i, rr := range msg.Ns {
			ansName := strings.ToLower(rr.Header().Name)
			isValid := false
			
			for _, vn := range validNames {
				// Ns records are usually parent delegations (e.g., google.com for www.google.com)
				// or sub-delegations (e.g., sub.example.com for example.com).
				if ansName == vn || strings.HasSuffix(vn, "."+ansName) || strings.HasSuffix(ansName, "."+vn) {
					isValid = true
					break
				}
			}
			
			if !isValid {
				if logCaching {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Authority Record %d (%q) breaks Bailiwick.", qName, i, ansName)
				}
				return
			}
		}
	}
	
	// ---------------------------------------------------------------------------
	// [SECURITY] RFC 6891 §6.1.1 - Strip OPT Records safely
	// ---------------------------------------------------------------------------
	// OPT records (EDNS0) are strictly hop-by-hop and MUST NOT be cached.
	// Stripping them natively prevents downstream clients from receiving stale or 
	// inaccurate payload sizes/DNSSEC flags from the original upstream negotiation.
	
	// [FIX] Perform a shallow copy of the message struct to prevent mutating the 
	// `Extra` array of the live response payload passing through the execution pipeline.
	// Altering the live pointer strips the Extended RCODE from the client's payload natively.
	cacheMsg := *msg

	// [PERF/FIX] Evaluate payload structure organically before aggressively allocating slices.
	// Bypasses severe GC thrashing natively since 99.9% of queries contain precisely one auxiliary 
	// record (the OPT parameter) that requires deletion, eliminating the need to construct a 0-length slice.
	if len(cacheMsg.Extra) > 0 {
		hasNonOpt := false
		for _, rr := range cacheMsg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				hasNonOpt = true
				break
			}
		}
		if hasNonOpt {
			cleanExtra := make([]dns.RR, 0, len(cacheMsg.Extra)-1)
			for _, rr := range cacheMsg.Extra {
				if rr.Header().Rrtype != dns.TypeOPT {
					cleanExtra = append(cleanExtra, rr)
				}
			}
			cacheMsg.Extra = cleanExtra
		} else {
			cacheMsg.Extra = nil
		}
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
		if ttl == 0 {
			if cfg.Cache.NegativeTTL > 0 {
				ttl = uint32(cfg.Cache.NegativeTTL)
			} else {
				ttl = uint32(cfg.Cache.MinTTL)
			}
		}
	}

	effectiveMin := uint32(cfg.Cache.MinTTL)
	if isNeg && cfg.Cache.NegativeTTL > 0 {
		effectiveMin = uint32(cfg.Cache.NegativeTTL)
	}
	if ttl < effectiveMin {
		ttl = effectiveMin
	}
	if cfg.Cache.MaxTTL > 0 && ttl > uint32(cfg.Cache.MaxTTL) {
		ttl = uint32(cfg.Cache.MaxTTL)
	}

	now        := time.Now().UnixNano()
	expireNano := now + int64(ttl)*int64(time.Second)
	staleNano  := expireNano
	if staleEnabled {
		staleNano = expireNano + int64(cfg.Cache.StaleTTL)*int64(time.Second)
	}

	// [PERF/FIX] Replaced `smallBufPool` (4KB) with `largeBufPool` (64KB) to securely
	// accommodate enormous DNSSEC-signed responses. This completely eradicates 
	// `dns.ErrBuf` packing truncations that previously prevented cache storage
	// of robust payloads, maintaining absolute RFC compliance natively.
	bufp   := largeBufPool.Get().(*[]byte)
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
// syntheticTTL. Unlike CacheSet it bypasses the RFC 2308 RCODE filter, so
// REFUSED, NOTIMP, and NOERROR-with-no-answers can all be cached here natively.
//
// staleNano == expireNano — synthetic entries have no upstream to revalidate
// against, so backgroundRevalidate must never fire for them.
func CacheSetSynth(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	now        := time.Now().UnixNano()
	expireNano := now + int64(syntheticTTL)*int64(time.Second)

	// [PERF/FIX] Replaced `smallBufPool` with `largeBufPool` to guarantee 
	// packing success even on heavily synthesized structural payloads.
	bufp   := largeBufPool.Get().(*[]byte)
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
		staleNano:    expireNano, // no stale window — nothing to revalidate
		cachedAtNano: now,
		routeName:    "",         // synthetic; backgroundRevalidate must not fire
	}
	ci.packed.Store(&stored)
	storeItem(key, ci)
}

// CacheUpdateOrder atomically swaps the packed bytes of an existing cache item.
// Used to persist updated Answer record orders (e.g., round-robin shifting)
// without disturbing the original expiration timelines or active atomic trackers.
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

	// [SECURITY/FIX] Strip OPT records safely before caching
	// Enforces RFC 6891 strictly. Prevents downstream payload-size corruption 
	// when `answer_sort` natively reshuffles and persists cache records.
	// [PERF/FIX] Zero-allocation boundary check suppresses redundant memory slicing
	// for structural payloads exclusively matching standard constraints natively.
	cacheMsg := *msg
	if len(cacheMsg.Extra) > 0 {
		hasNonOpt := false
		for _, rr := range cacheMsg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				hasNonOpt = true
				break
			}
		}
		if hasNonOpt {
			cleanExtra := make([]dns.RR, 0, len(cacheMsg.Extra)-1)
			for _, rr := range cacheMsg.Extra {
				if rr.Header().Rrtype != dns.TypeOPT {
					cleanExtra = append(cleanExtra, rr)
				}
			}
			cacheMsg.Extra = cleanExtra
		} else {
			cacheMsg.Extra = nil
		}
	}

	// [PERF/FIX] Migrated to `largeBufPool` to ensure updated records mapping 
	// 4KB+ payloads (like root servers or immense CNAME chains) don't silently fail 
	// during re-packing serialization.
	bufp := largeBufPool.Get().(*[]byte)
	packed, err := cacheMsg.PackBuffer((*bufp)[:0])
	if err == nil {
		stored := make([]byte, len(packed))
		copy(stored, packed)
		item.packed.Store(&stored)
	}
	largeBufPool.Put(bufp)
}

