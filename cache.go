/*
File:    cache.go
Version: 2.30.0
Updated: 07-May-2026 12:48 CEST

Description:
  High-performance, sharded, non-blocking DNS cache for sdproxy.
  Caches positive (NOERROR), negative (NXDOMAIN), and empty (NOERROR
  with no answer records) responses per RFC 2308.
  Optimised for embedded environments with struct-based zero-allocation 
  keys, pseudo-random eviction, and wire-format storage.

Changes:
  2.30.0 - [SECURITY] Bounded CNAME chain Bailiwick resolution in `CacheSet` to 
           strictly 16 iterations natively. Neutralizes CPU exhaustion DoS attacks 
           instigated by malicious upstreams feeding infinitely circular or 
           artificially massive CNAME structures into the memory parser.
  2.29.0 - [FEAT] Added `cachedAtNano` tracking to `cacheItem` and implemented 
           `DumpCache()` natively. Facilitates direct Memory-Array extraction 
           for the new Web UI Cache Inspector modal without inducing lock contention.
  2.28.0 - [SECURITY/FIX] Resolved a severe Cache Poisoning vulnerability where 
           malicious upstreams could return payloads omitting the `Question` section 
           or spoofing an alternate `QNAME`. This previously bypassed Bailiwick 
           chain validations, allowing arbitrary records to be injected into the 
           memory shards. `CacheSet` now strictly enforces RFC 1035 Question-parity 
           natively before memory allocation occurs.
  2.27.0 - [SECURITY/FIX] Replaced `smallBufPool` (4KB) with `largeBufPool` (64KB) 
           during wire-format packing inside `CacheSet` and `CacheUpdateOrder`. 
           This natively eradicates `dns.ErrBuf` truncation errors, guaranteeing 
           that massive DNSSEC-signed or deeply padded payloads are reliably 
           stored in the cache memory shards.
  2.26.0 - [PERF] Eliminated severe heap-allocations during CNAME Bailiwick validation.
           Replaced the `map[string]bool` with a stack-allocated slice, radically
           improving caching throughput and eliminating GC thrashing.
  2.25.0 - [FEAT] Integrated Infinite Serve-Stale capability natively. Bypasses 
           garbage collection for expired cache shards when `serve_stale_infinite` 
           is enabled to provide a permanent resolution fallback.
  2.24.0 - [PERF] Replaced direct background goroutine spawning with the strictly bounded 
           `TriggerBackgroundRevalidate` engine. This completely neutralizes heap 
           allocations when the revalidation pool is natively saturated.
  2.23.0 - [PERF/FIX] Resolved a severe Thundering Herd performance regression. 
           Stale-serve background revalidation is now correctly governed by the 
           atomic `prefetched` CAS gate natively. This prevents thousands of redundant 
           background goroutines from spawning and immediately exhausting the 
           `upstreamLimit` slots during stale cache hits.
         - [SECURITY/FIX] Enforced RFC 6891 strictly inside `CacheUpdateOrder`. 
           `OPT` records are now cleanly stripped before payload repacking, eliminating 
           memory corruption and payload-size poisoning when `answer_sort` is enabled.
*/

package main

import (
	"fmt"
	"hash/maphash"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DNSCacheKey is the map key for all cache lookups.
//
// Name must always be normalised (lowercase, no trailing dot) as produced by
// lowerTrimDot in policy.go — ensures "GOOGLE.COM." and "google.com" share
// the same entry. RouteIdx is a compact uint16 so the key stays small and
// struct-comparable without a string route name on every lookup.
// DoBit and CdBit ensure cryptographically signed/unsigned, and validated/unvalidated
// requests are isolated securely, preventing cross-contamination.
type DNSCacheKey struct {
	Name     string
	Qtype    uint16
	Qclass   uint16
	RouteIdx uint16
	DoBit    bool
	CdBit    bool
}

// cacheItem is a single cached DNS response in wire format.
type cacheItem struct {
	packed       atomic.Pointer[[]byte] // immutable packed DNS wire bytes, rotatable atomically
	expireNano   int64                  // expiry deadline as unix nanoseconds
	staleNano    int64                  // end of stale-serving window; == expireNano for synth entries
	cachedAtNano int64                  // timestamp of exact creation time for introspection
	routeName    string                 // upstream group name used by backgroundRevalidate
	hits         atomic.Uint32          // hit counter for prefetch popularity gate
	prefetched   atomic.Bool            // CAS flag: exactly one prefetch fires per entry lifetime
}

// cacheShard is an independently locked segment of the cache.
// 32 shards reduce write-lock contention by ~32× compared to a single mutex.
type cacheShard struct {
	sync.RWMutex
	items map[DNSCacheKey]*cacheItem
}

const shardCount = 32

var shards [shardCount]*cacheShard

// cacheMaxPerShard is the per-shard entry ceiling, pre-computed from the
// configured total size at InitCache time.
var cacheMaxPerShard int

// cacheHashSeed provides cryptographic randomization for the shard hashing algorithm.
// It is initialized exactly once at startup to ensure consistent bucket resolution.
var cacheHashSeed maphash.Seed

// ---------------------------------------------------------------------------
// Startup feature flags — set once in InitCache, read on every hot-path call.
// ---------------------------------------------------------------------------

// hasPrefetch is true when both prefetch knobs are > 0.
// Guards hits.Add(1) — skipping the atomic barrier on every cache hit when
// prefetch is disabled is meaningful on MIPS/ARM routers.
var hasPrefetch bool

// staleEnabled is true when cfg.Cache.StaleTTL > 0.
// Guards the stale-window logic so the common disabled case pays nothing
// beyond a single bool load.
var staleEnabled bool

// cacheUpstreamNeg controls whether upstream NXDOMAIN / NODATA responses are
// stored. true = cache them (RFC 2308 compliant, default).
// false = always forward negative queries upstream — useful when upstream
// blocklists change frequently and you don't want negatives to linger.
var cacheUpstreamNeg bool

// serveStaleInfinite controls whether expired cache entries are retained 
// indefinitely and served as an absolute last resort during upstream outages.
var serveStaleInfinite bool

// cacheSynthFlag controls whether synthesised policy responses (domain_policy,
// rtype_policy, AAAA filter, strict_ptr, obsolete qtypes) are stored via
// CacheSetSynth. When true, repeat policy-blocked queries hit the cache at
// step 3 in process.go and skip domain walks + policy lookups entirely.
var cacheSynthFlag bool

// cacheLocalIdentity controls whether local A/AAAA/PTR responses from
// hosts/leases files are stored via CacheSetSynth. Only safe when
// syntheticTTL ≤ identity.poll_interval — otherwise stale local addresses
// may be served in the gap between a file change and the next poll.
var cacheLocalIdentity bool

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

// InitCache initialises all shards and starts the background sweeper.
// Called once from main() after cfg is populated.
func InitCache(maxSize int, _ int) {
	if !cfg.Cache.Enabled {
		return
	}

	// Initialize the randomized seed for HashDoS protection natively at boot
	cacheHashSeed = maphash.MakeSeed()

	for i := range shards {
		shards[i] = &cacheShard{items: make(map[DNSCacheKey]*cacheItem)}
	}
	cacheMaxPerShard = maxSize / shardCount
	if cacheMaxPerShard < 1 {
		cacheMaxPerShard = 1
	}

	// Set hot-path feature flags once so CacheGet/CacheSet branches are pure
	// bool loads — no config struct field accesses on the critical path.
	hasPrefetch        = cfg.Cache.PrefetchBefore > 0 && cfg.Cache.PrefetchMinHits > 0
	staleEnabled       = cfg.Cache.StaleTTL > 0
	cacheUpstreamNeg   = cfg.Cache.CacheUpstreamNegative
	cacheSynthFlag     = cfg.Cache.CacheSynthetic
	cacheLocalIdentity = cfg.Cache.CacheLocalIdentity
	serveStaleInfinite = cfg.Cache.ServeStaleInfinite

	sweepInterval := 60 * time.Second
	if cfg.Cache.SweepIntervalS > 0 {
		sweepInterval = time.Duration(cfg.Cache.SweepIntervalS) * time.Second
	}
	log.Printf("[CACHE] Initialised: size=%d shards=%d sweep=%s stale=%ds "+
		"prefetch=%ds/%dhits synth=%v localid=%v upneg=%v sort=%s inf_stale=%v",
		maxSize, shardCount, sweepInterval,
		cfg.Cache.StaleTTL, cfg.Cache.PrefetchBefore, cfg.Cache.PrefetchMinHits,
		cacheSynthFlag, cacheLocalIdentity, cacheUpstreamNeg, cfg.Cache.AnswerSort, serveStaleInfinite)

	go runSweeper(sweepInterval)
}

// runSweeper periodically reclaims cache entries whose stale window has passed.
//
// Correctness note: the sweeper only frees memory. CacheGet independently
// rejects expired entries on every read, so a late sweep never serves stale data.
//
// Two-phase strategy (prevents holding a write lock during the full scan):
//   Phase 1 — RLock: scan shard, collect expired keys into toDelete.
//   Phase 2 — Lock:  delete each key, re-checking staleNano to skip any entry
//                    that was just refreshed by a concurrent CacheSet.
//
// toDelete is allocated once before the loop with a capacity hint and reused
// across all 32 shards per tick (reset with [:0]) — no per-shard allocation.
func runSweeper(interval time.Duration) {
	if serveStaleInfinite {
		// Disable garbage collection of expired records so they remain 
		// available indefinitely for upstream outage fallbacks.
		return 
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	toDelete := make([]DNSCacheKey, 0, max(cacheMaxPerShard/4, 16))

	for range ticker.C {
		now := time.Now().UnixNano()
		for i := range shards {
			shard    := shards[i]
			toDelete  = toDelete[:0]

			shard.RLock()
			for k, v := range shard.items {
				if now >= v.staleNano {
					toDelete = append(toDelete, k)
				}
			}
			shard.RUnlock()

			if len(toDelete) == 0 {
				continue
			}
			shard.Lock()
			for _, k := range toDelete {
				// Re-check: a concurrent CacheSet may have refreshed this key.
				if v, ok := shard.items[k]; ok && now >= v.staleNano {
					delete(shard.items, k)
				}
			}
			shard.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Shard selector
// ---------------------------------------------------------------------------

// getShard maps a cache key to a shard using Go's hardened maphash.
//
// [SECURITY/PERF] HashDoS Mitigation & Avalanche Distribution
// We utilize maphash with a randomized, per-process seed to neutralize HashDoS attacks
// against the unpredictable domain `Name` payload.
// The remaining deterministic metadata fields (Qtype, Qclass, RouteIdx, DoBit, CdBit) are then
// packed and folded into the primary hash natively. 
// To guarantee these upper bits securely influence the lowest 5 bits (which directly dictate 
// the 0-31 Shard Array Indexing mapping), an explicit bitwise avalanche step is executed. 
// This natively eliminates unintended Mutex collision hotspots under massive query floods.
func getShard(key DNSCacheKey) *cacheShard {
	// Hash the domain name utilizing the cryptographically seeded maphash
	h := maphash.String(cacheHashSeed, key.Name)
	
	// Pack the remaining structured, trusted deterministic fields.
	mix := uint64(key.Qtype)<<32 | uint64(key.Qclass)<<16 | uint64(key.RouteIdx)
	if key.DoBit {
		mix |= 1 << 48
	}
	if key.CdBit {
		mix |= 1 << 49
	}
	
	// Fold the scalar fields into the primary hash
	h ^= mix
	
	// Avalanche the upper bits downwards to guarantee absolute uniformity across the lowest 5 bits
	h ^= h >> 32
	h ^= h >> 16
	h ^= h >> 8
	h ^= h >> 4
	
	return shards[h&(shardCount-1)]
}

// ---------------------------------------------------------------------------
// Internal store helper
// ---------------------------------------------------------------------------

// storeItem acquires the shard write-lock, evicts one pseudo-random entry when
// the shard is at capacity, then stores item under key.
//
// Shared by CacheSet and CacheSetSynth — eviction and store logic live in
// exactly one place, so the two callers cannot drift out of sync.
//
// Pseudo-random eviction: Go's map iteration order is deliberately randomised,
// so the first key returned is statistically uniform across all entries.
func storeItem(key DNSCacheKey, item *cacheItem) {
	shard := getShard(key)
	shard.Lock()
	if len(shard.items) >= cacheMaxPerShard {
		for k := range shard.items {
			delete(shard.items, k)
			break
		}
	}
	shard.items[key] = item
	shard.Unlock()
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

	// Hit counting — only pay the atomic barrier when prefetch is configured or is stale.
	var currentHits uint32
	if hasPrefetch || isStale {
		// [FIX] Ensure we accurately count hits for stale evaluation gates too
		currentHits = item.hits.Add(1)
	} else {
		currentHits = item.hits.Load()
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

	// [SECURITY/PERF] Unified Background Revalidation Gate
	// Safely bounds BOTH prefetch and stale-serve background revalidations behind 
	// a strict atomic CompareAndSwap gate. This prevents the Thundering Herd 
	// vulnerability where hundreds of concurrent stale queries spawned unbounded 
	// background goroutines, instantly exhausting the `revalSem` semaphore and 
	// `upstreamLimit` throttler capacity natively.
	triggerBG := false
	if isStale {
		triggerBG = true
	} else if hasPrefetch && remaining > 0 && remaining <= uint32(cfg.Cache.PrefetchBefore) && currentHits >= uint32(cfg.Cache.PrefetchMinHits) {
		triggerBG = true
		isPrefetch = true
	}

	if triggerBG && item.prefetched.CompareAndSwap(false, true) {
		// [FIX] Provide a state-reversion callback so saturated background semaphores 
		// do not permanently lock the prefetch gate for this entry.
		revertGate := func() {
			item.prefetched.Store(false)
		}

		// Launch background worker natively passing the popularity index (hits)
		TriggerBackgroundRevalidate(key, item.routeName, "", currentHits, revertGate)
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
		log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Missing Question section.", key.Name)
		return
	}

	qName := strings.ToLower(msg.Question[0].Name)
	cleanQName := strings.TrimSuffix(qName, ".")
	
	// Rigorously enforce that the upstream echoed the exact target requested.
	if cleanQName != key.Name {
		log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response. Question section (%q) does not match requested cache key (%q).", cleanQName, key.Name)
		return
	}

	// [PERF/FIX] Replaced heap-allocated map with stack-allocated slice for 
	// zero-allocation validation during hot-path caching. Drastically mitigates GC thrashing.
	var validStack [16]string
	validNames := validStack[:0]
	validNames = append(validNames, qName)
	
	hasValidName := func(name string) bool {
		for _, v := range validNames {
			if v == name { return true }
		}
		return false
	}
	
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
			if hasValidName(ansName) {
				if cname, ok := rr.(*dns.CNAME); ok {
					target := strings.ToLower(cname.Target)
					if !hasValidName(target) {
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
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME chain exceeds maximum safe parsing depth.", qName)
			return
		}
	}

	// Validate Answer Section against the fully discovered chain map
	if len(msg.Answer) > 0 {
		for i, rr := range msg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			if !hasValidName(ansName) {
				log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Record %d (%q) breaks Bailiwick/CNAME chain.", qName, i, ansName)
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
				log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Authority Record %d (%q) breaks Bailiwick.", qName, i, ansName)
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

	if len(cacheMsg.Extra) > 0 {
		cleanExtra := make([]dns.RR, 0, len(cacheMsg.Extra))
		for _, rr := range cacheMsg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				cleanExtra = append(cleanExtra, rr)
			}
		}
		cacheMsg.Extra = cleanExtra
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
		log.Printf("[CACHE] CacheSet: pack failed for %q: %v", key.Name, err)
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
		log.Printf("[CACHE] CacheSetSynth: pack failed for %q: %v", key.Name, err)
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
	cacheMsg := *msg
	if len(cacheMsg.Extra) > 0 {
		cleanExtra := make([]dns.RR, 0, len(cacheMsg.Extra))
		for _, rr := range cacheMsg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				cleanExtra = append(cleanExtra, rr)
			}
		}
		cacheMsg.Extra = cleanExtra
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

// CacheEntryCount returns the total number of entries currently held across
// all 32 shards. Acquires each shard's read lock briefly — only called by the
// /api/stats poller (≤ once per 5 s), never in the DNS hot path.
func CacheEntryCount() int {
	if !cfg.Cache.Enabled {
		return 0
	}
	n := 0
	for _, s := range shards {
		s.RLock()
		n += len(s.items)
		s.RUnlock()
	}
	return n
}

// ---------------------------------------------------------------------------
// Cache Introspection (Web UI)
// ---------------------------------------------------------------------------

// CacheEntryDump encapsulates a single cache record dynamically extracted 
// for representation within the Web UI dashboard.
type CacheEntryDump struct {
	QName    string `json:"qname"`
	QType    string `json:"qtype"`
	Route    string `json:"upstream_group"`
	Response string `json:"response"`
	Hits     uint32 `json:"hits"`
	CachedAt string `json:"timestamp"`
	TimeLeft string `json:"time_left"`
}

// DumpCache iterates across all internal memory shards, securely locking and 
// replicating viable arrays to safely build an introspective snapshot of the 
// active DNS cache without inducing hot-path contention constraints natively.
func DumpCache() []CacheEntryDump {
	if !cfg.Cache.Enabled {
		return nil
	}

	var dumps []CacheEntryDump
	now := time.Now().UnixNano()

	type snapshot struct {
		Key      DNSCacheKey
		Item     *cacheItem
		Packed   []byte
		Hits     uint32
	}
	var snaps []snapshot

	// 1. Gather all active memory records natively using Read-Locks to minimize hot-path collision.
	for i := range shards {
		shard := shards[i]
		shard.RLock()
		for k, v := range shard.items {
			// Pre-emptively skip records completely outside the stale window bounds natively
			if now >= v.staleNano {
				continue
			}
			if p := v.packed.Load(); p != nil {
				packedCopy := make([]byte, len(*p))
				copy(packedCopy, *p)
				snaps = append(snaps, snapshot{
					Key:    k,
					Item:   v,
					Packed: packedCopy,
					Hits:   v.hits.Load(),
				})
			}
		}
		shard.RUnlock()
	}

	// 2. Unpack safely isolated from the core Mutexes natively
	msg := new(dns.Msg)
	for _, s := range snaps {
		*msg = dns.Msg{}
		if err := msg.Unpack(s.Packed); err != nil {
			continue
		}

		var answers []string
		for _, rr := range msg.Answer {
			// Strip tabs to maintain strict visual formatting boundaries
			str := strings.ReplaceAll(rr.String(), "\t", " ")
			answers = append(answers, str)
		}
		
		responseStr := strings.Join(answers, "\n")
		if responseStr == "" {
			if msg.Rcode != dns.RcodeSuccess {
				if rc, ok := dns.RcodeToString[msg.Rcode]; ok {
					responseStr = rc
				} else {
					responseStr = fmt.Sprintf("RCODE:%d", msg.Rcode)
				}
			} else {
				responseStr = "NODATA"
			}
		}

		timeLeftSec := (s.Item.expireNano - now) / int64(time.Second)
		timeLeft := fmt.Sprintf("%ds", timeLeftSec)
		if timeLeftSec < 0 {
			timeLeft = fmt.Sprintf("Expired (%ds)", timeLeftSec)
		}

		cachedAt := time.Unix(0, s.Item.cachedAtNano).Format("2006-01-02 15:04:05")

		route := s.Item.routeName
		if route == "" {
			route = "synthetic"
		}

		dumps = append(dumps, CacheEntryDump{
			QName:    s.Key.Name,
			QType:    dns.TypeToString[s.Key.Qtype],
			Route:    route,
			Response: responseStr,
			Hits:     s.Hits,
			CachedAt: cachedAt,
			TimeLeft: timeLeft,
		})
	}

	return dumps
}

// atomic import guard
var _ atomic.Uint32

