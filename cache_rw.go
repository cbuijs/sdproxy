/*
File:    cache_rw.go
Version: 1.2.0 (Split)
Updated: 22-Jul-2026 21:40 CEST

Description:
  Hot-path Read/Write operations for the sdproxy cache engine.
  Handles packing/unpacking dns.Msg structures, TTL rewrites, background
  revalidation tracking, and strict RFC bailiwick security enforcement.

  Extracted from cache.go to prioritize hot-path execution clarity.

Changes:
  1.2.0 - [TIER 2] Extracted stripOPTRecords(); the RFC 6891 OPT-stripping block
          with its zero-allocation pre-scan was copy-pasted in CacheSet,
          CacheSetSynth and CacheUpdateOrder. Behaviour unchanged.
  1.1.0 - [PERF] Decoupled bailiwick validation from a per-call closure into the
          global isValidBailiwickName helper to eliminate heap allocations
          during cache-write floods.
*/

package main

import (
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// isValidBailiwickName executes a zero-allocation bounds check to ensure
// nested CNAME/NS records respect the established resolution chain.
func isValidBailiwickName(names []string, name string) bool {
	for _, v := range names {
		if v == name {
			return true
		}
	}
	return false
}

// stripOPTRecords returns extra with all OPT (EDNS0) records removed.
//
// [SECURITY] RFC 6891 §6.1.1 — OPT is strictly hop-by-hop and MUST NOT be
// cached. Storing it would hand downstream clients stale payload sizes and
// DNSSEC flags from the original upstream negotiation.
//
// [PERF] Pre-scans before allocating. ~99.9% of responses carry exactly one
// auxiliary record (the OPT itself), so the common case returns nil without
// constructing a zero-length slice.
func stripOPTRecords(extra []dns.RR) []dns.RR {
	if len(extra) == 0 {
		return extra
	}
	hasNonOpt := false
	for _, rr := range extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			hasNonOpt = true
			break
		}
	}
	if !hasNonOpt {
		return nil
	}
	clean := make([]dns.RR, 0, len(extra)-1)
	for _, rr := range extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			clean = append(clean, rr)
		}
	}
	return clean
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
	// [RFC COMPLIANCE] Floor stale responses at 1s so strict stub resolvers
	// don't enter infinite retry loops on TTL=0 (RFC 8767 §4).
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

	// [SECURITY] Unified background revalidation gate.
	// Bounds BOTH prefetch and stale-serve revalidation behind one atomic CAS.
	// Synthetic records are skipped entirely: revalidating them would leak LAN
	// names to public upstreams and corrupt the cache.
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
		// State-reversion callback so a saturated background semaphore does not
		// permanently lock the prefetch gate for this entry.
		revertGate := func() {
			item.prefetched.Store(false)
		}
		TriggerBackgroundRevalidate(key, item.routeName, key.ClientName, currentHits, revertGate)
	}

	packedData := item.packed.Load()
	if err := out.Unpack(*packedData); err != nil {
		return false, false, false, 0
	}

	// Rewrite TTLs to reflect actual remaining lifetime.
	// OPT (EDNS0) carries flags, not a TTL — always skip it.
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

// CacheGetExpired retrieves any cached record regardless of its TTL/stale
// bounds. Emergency fallback only: used when upstream exchanges fail and
// serve_stale_infinite is enabled.
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

	// Force a short 30s TTL so clients don't permanently cache the dead record
	// and can retry once the upstream recovers.
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

	// [SECURITY/PERF] Truncation guard.
	// Caching a TC=1 response would make every subsequent TCP retry receive the
	// same incomplete payload, trapping the client in a resolution loop and
	// starving file descriptors.
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
	// Enforce that the answers belong to the QNAME that was requested, so a
	// malicious upstream cannot slip out-of-zone records into the shards.

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

	// [PERF] Stack-allocated slice, not a map — zero allocations on the write path.
	// Size 64 covers even deep CNAME chains without falling back to the heap.
	var validStack [64]string
	validNames := validStack[:0]
	validNames = append(validNames, qName)

	// CNAME chains can arrive out of order from intermediate resolvers, so
	// discover all valid targets first, then verify. Avoids false-positive drops.
	// [SECURITY] Depth is bounded to stop CPU-exhaustion DoS via circular chains.
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

	// Validate Answer section against the discovered chain.
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

	// Validate Authority (Ns) section — thwarts injection of out-of-zone NS/SOA.
	if len(msg.Ns) > 0 {
		for i, rr := range msg.Ns {
			ansName := strings.ToLower(rr.Header().Name)
			isValid := false

			for _, vn := range validNames {
				// Ns records are usually parent delegations (google.com for
				// www.google.com) or sub-delegations (sub.example.com for example.com).
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

	// Shallow-copy the message before stripping OPT. Mutating the live Extra
	// slice would strip the Extended RCODE from the client's own response.
	cacheMsg := *msg
	cacheMsg.Extra = stripOPTRecords(cacheMsg.Extra)

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

	now := time.Now().UnixNano()
	expireNano := now + int64(ttl)*int64(time.Second)
	staleNano := expireNano
	if staleEnabled {
		staleNano = expireNano + int64(cfg.Cache.StaleTTL)*int64(time.Second)
	}

	// [PERF] largeBufPool (64KB), not smallBufPool (4KB): large DNSSEC-signed
	// responses previously hit dns.ErrBuf and were silently never cached.
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
// syntheticTTL. Unlike CacheSet it bypasses the RFC 2308 RCODE filter, so
// REFUSED, NOTIMP, and NOERROR-with-no-answers can all be cached here.
//
// staleNano == expireNano — synthetic entries have no upstream to revalidate
// against, so backgroundRevalidate must never fire for them.
func CacheSetSynth(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
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
		staleNano:    expireNano, // no stale window — nothing to revalidate
		cachedAtNano: now,
		routeName:    "", // synthetic; backgroundRevalidate must not fire
	}
	ci.packed.Store(&stored)
	storeItem(key, ci)
}

// CacheUpdateOrder atomically swaps the packed bytes of an existing cache item.
// Used to persist updated Answer record orders (e.g. round-robin shifting)
// without disturbing the original expiration timelines or atomic trackers.
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

	// Strip OPT before re-storing, otherwise answer_sort reshuffling would
	// persist the hop-by-hop record and corrupt downstream payload sizes.
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

