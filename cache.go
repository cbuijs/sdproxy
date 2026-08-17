/*
File:    cache.go
Version: 2.51.0 (Split)
Last Updated: 05-Aug-2026 21:30 CEST

Description:
  High-performance, sharded, non-blocking DNS cache core for sdproxy.
  Manages memory allocation, cryptographic sharding (HashDoS protection),
  and asynchronous garbage collection (Sweeper).
  
  Hot-path Read/Write operations have been moved to cache_rw.go.
  Disk persistence has been moved to cache_persistence.go.
  UI introspection has been moved to cache_ui.go.

Changes:
  2.51.0 - [PERF/FIX] Eliminated the cache-hot-path repack caused by
           `answer_sort: round-robin`.
           applyAnswerSort rotates the stored order by exactly one position, so
           for round-robin it reported "changed" on EVERY cache hit, and
           process.go dutifully persisted that new order through
           CacheUpdateOrder — a shallow msg copy, an OPT strip, a 64KB pool
           round-trip, a PackBuffer, a fresh heap allocation, a shard RLock and
           an atomic pointer store, all on the single hottest path in the
           daemon, for every hit.
           Note this was specific to round-robin. ip-sort is deterministic, so
           after one write-back the stored bytes are already sorted and
           applyAnswerSort returns false thereafter — it self-limits. random is
           already excluded. Round-robin alone could never converge, because
           rotating is the whole point.
           Replaced with a per-entry rotation counter (`cacheItem.rotation`)
           applied at unpack time in CacheGet. Each hit advances the counter and
           rotates the freshly unpacked answers by that offset, so successive
           clients still receive successive orderings — genuinely round-robin,
           and now genuinely per-entry rather than per-stored-blob. The packed
           bytes are never rewritten at all, so the entire write-back disappears
           rather than merely being debounced.
           `cacheRotateAnswers` is resolved once in InitCache so the hot path
           costs one bool load, matching the existing hasPrefetch/staleEnabled
           pattern.
  2.50.0 - [PERF/FIX] Replaced storeItem's blind first-key eviction with a
           small-sample oldest-victim policy.
           The previous code deleted whichever key Go's randomised map iteration
           yielded first. Uniform, O(1) — and completely blind to whether the
           victim was a long-dead entry or the freshest, most-requested record in
           the shard. That is merely wasteful under normal operation, where the
           sweeper reclaims expired entries on a timer anyway. Under
           `serve_stale_infinite: true` it is actively harmful: runSweeper
           disables itself entirely in that mode (by design — expired records
           must survive for outage fallback), so random eviction becomes the
           ONLY reclamation path, and it will happily discard hot live entries
           while entries that expired weeks ago sit untouched.
           storeItem now samples up to 8 keys and evicts the one with the
           earliest staleNano. Still O(1) with a fixed constant, still holds the
           write lock for a bounded time, but now strongly biased toward the
           genuinely dead. Classic power-of-N-choices: 8 samples is enough to
           make retaining an expired entry over a live one unlikely, without the
           cost of a full shard scan.
  2.49.0 - [SECURITY/FIX] Removed `go pruneRecentBlocks(shutdownCh)` from
           InitCache. That goroutine reclaims memory for the Search Domain Leak
           Prevention tracker in process_leak.go — a subsystem with no
           relationship to caching whatsoever. Because InitCache returns
           immediately when `cache.enabled: false`, hosting the launch here
           meant disabling the cache also silently disabled the tracker's ONLY
           reclaimer, letting rbShards grow without bound for the lifetime of
           the process. Ownership moved to InitRecentBlocks() in
           process_leak.go 1.4.0, invoked from main.go 1.242.0.
  2.48.0 - [SECURITY] Incorporated `BypassGlobal` natively into `DNSCacheKey` and 
           the cryptographic sharding mechanism to definitively neutralize cross-cache 
           contamination between policy-bound and bypassed client architectures.
  2.47.0 - [SECURITY/FIX] Eradicated a persistent zombie goroutine natively. 
           The background sweeper now explicitly listens to `shutdownCh` to 
           yield resources smoothly during structural reloads and shutdowns.
  2.46.0 - [PERF] Scoped `toDelete` array allocations directly into the `shards` 
           iteration loop within `runSweeper`. Definitively guarantees that 
           `DNSCacheKey` string pointers from previous shards are instantly 
           detached, preventing artificial memory retention prior to tick completion.
  2.45.0 - [CODE SMELL/FIX] Corrected documentation drift regarding `hasPrefetch` 
           capabilities natively. The flag regulates background revalidation loops 
           organically, but allows Web UI cache hit counters to populate accurately 
           even when prefetching logic is suspended.
  2.44.0 - [REFACTOR] Split monolithic cache.go into specific responsibility 
           domains (cache.go, cache_rw.go, cache_persistence.go, cache_ui.go).
           Improves maintainability and isolates disk I/O from the network path.
*/

package main

import (
	"hash/maphash"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// DNSCacheKey is the map key for all cache lookups.
//
// Name must always be normalised (lowercase, no trailing dot) as produced by
// lowerTrimDot in policy.go — ensures "GOOGLE.COM." and "google.com" share
// the same entry. RouteIdx is a compact uint16 so the key stays small and
// struct-comparable without a string route name on every lookup.
// DoBit and CdBit ensure cryptographically signed/unsigned, and validated/unvalidated
// requests are isolated securely, preventing cross-contamination.
// BypassGlobal explicitly partitions the cache payload natively when the routing 
// group bypasses globally defined Spoofed Records (rrs) and Domain Policies natively.
// ClientName explicitly partitions the cache payload natively when the routing 
// group relies on tailored upstream endpoints (e.g., NextDNS/ControlD).
// ECS explicitly partitions the cache payload natively when the routing group 
// injects localized EDNS0 Client Subnet architectures, neutralizing cross-contamination.
type DNSCacheKey struct {
	Name         string
	ClientName   string 
	ECS          string 
	Qtype        uint16
	Qclass       uint16
	RouteIdx     uint16
	DoBit        bool
	CdBit        bool
	BypassGlobal bool
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

	// rotation drives answer_sort: round-robin without ever rewriting the
	// packed bytes. Advanced once per cache hit; CacheGet rotates the unpacked
	// answer set by this offset. Deliberately allowed to wrap — the consumer
	// takes it modulo the group length, so uint32 overflow is a no-op.
	rotation atomic.Uint32
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
// Determines whether cache hits evaluate background revalidation logic natively.
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

// cacheRotateAnswers is true when answer_sort is "round-robin".
//
// Round-robin is the one sort mode that can never reach a fixed point: every
// application rotates the order again. Persisting the result on each hit (as
// versions before 2.51.0 did) therefore meant repacking and re-storing the entry
// on every single cache hit forever. The rotation is now applied at read time
// from cacheItem.rotation instead, and this flag lets CacheGet and process.go
// branch on a single bool load rather than a string comparison per query.
var cacheRotateAnswers bool

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
	cacheRotateAnswers = cfg.Cache.AnswerSort == "round-robin"

	sweepInterval := 60 * time.Second
	if cfg.Cache.SweepIntervalS > 0 {
		sweepInterval = time.Duration(cfg.Cache.SweepIntervalS) * time.Second
	}
	
	if logCaching {
		log.Printf("[CACHE] Initialised: size=%d shards=%d sweep=%s stale=%ds "+
			"prefetch=%ds/%dhits synth=%v localid=%v upneg=%v sort=%s inf_stale=%v persist=%v",
			maxSize, shardCount, sweepInterval,
			cfg.Cache.StaleTTL, cfg.Cache.PrefetchBefore, cfg.Cache.PrefetchMinHits,
			cacheSynthFlag, cacheLocalIdentity, cacheUpstreamNeg, cfg.Cache.AnswerSort, serveStaleInfinite, cfg.Cache.Persist)
	}

	go runSweeper(sweepInterval)

	// [2.49.0] pruneRecentBlocks is deliberately NOT started here. It services
	// the Search Domain Leak Prevention tracker (process_leak.go), which is
	// independent of caching — and this function returns early when the cache
	// is disabled, which used to strand that tracker with no reclaimer at all.
	// See InitRecentBlocks(), called from main().

	if cfg.Cache.Persist {
		LoadCache()
		
		if cfg.Cache.PersistSaveInterval != "" && cfg.Cache.PersistSaveInterval != "0" && cfg.Cache.PersistSaveInterval != "0s" {
			if interval, err := time.ParseDuration(cfg.Cache.PersistSaveInterval); err == nil && interval > 0 {
				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							SaveCache()
						case <-shutdownCh:
							return
						}
					}
				}()
			} else {
				if logCaching {
					log.Printf("[CACHE] WARNING: Invalid persist_save_interval %q: %v", cfg.Cache.PersistSaveInterval, err)
				}
			}
		}
	}
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
func runSweeper(interval time.Duration) {
	if serveStaleInfinite {
		// Disable garbage collection of expired records so they remain 
		// available indefinitely for upstream outage fallbacks.
		return 
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			
			for i := range shards {
				shard := shards[i]
				
				// [PERF/FIX] Allocate slice inside the shard loop to ensure pointers from the 
				// previous iteration are completely detached immediately, allowing the GC to reclaim 
				// the underlying strings organically and preventing catastrophic Memory Leaks.
				toDelete := make([]DNSCacheKey, 0, max(cacheMaxPerShard/4, 16))

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
		case <-shutdownCh:
			return
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
// The remaining deterministic metadata fields (Qtype, Qclass, RouteIdx, DoBit, CdBit, BypassGlobal) are then
// packed and folded into the primary hash natively. 
// To guarantee these upper bits securely influence the lowest 5 bits (which directly dictate 
// the 0-31 Shard Array Indexing mapping), an explicit bitwise avalanche step is executed. 
// This natively eliminates unintended Mutex collision hotspots under massive query floods.
func getShard(key DNSCacheKey) *cacheShard {
	// Hash the domain name utilizing the cryptographically seeded maphash
	h := maphash.String(cacheHashSeed, key.Name)
	
	// Incorporate dynamic ClientName boundaries to guarantee total cache isolation 
	// when upstream protocols specify individualized targeting natively.
	// Multiplied by a distinct MurmurHash64 constant to prevent XOR cancellation collisions natively.
	if key.ClientName != "" {
		h ^= maphash.String(cacheHashSeed, key.ClientName) * 0x5bd1e9955bd1e995
	}
	
	// Incorporate ECS boundaries dynamically to prevent subset-target contamination 
	// natively across independent origin IP mappings.
	// Multiplied by a distinct fractional constant to prevent commutative XOR collisions natively.
	if key.ECS != "" {
		h ^= maphash.String(cacheHashSeed, key.ECS) * 0x9e3779b97f4a7c15
	}
	
	// Pack the remaining structured, trusted deterministic fields.
	mix := uint64(key.Qtype)<<32 | uint64(key.Qclass)<<16 | uint64(key.RouteIdx)
	if key.DoBit {
		mix |= 1 << 48
	}
	if key.CdBit {
		mix |= 1 << 49
	}
	if key.BypassGlobal {
		mix |= 1 << 50
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

// evictionSampleSize is how many entries storeItem inspects when choosing a
// victim under capacity pressure.
//
// Power-of-N-choices: sampling a handful and taking the worst of them
// approximates "evict the oldest" far more closely than a single random draw,
// at a fixed, tiny cost. 8 is the usual sweet spot — beyond it the marginal
// improvement flattens while the time spent holding the shard write-lock keeps
// growing, and this runs on the cache-write path.
const evictionSampleSize = 8

// storeItem acquires the shard write-lock, evicts the oldest of a small random
// sample when the shard is at capacity, then stores item under key.
//
// Shared by CacheSet and CacheSetSynth — eviction and store logic live in
// exactly one place, so the two callers cannot drift out of sync.
//
// [PERF/FIX 2.50.0] The sampling replaces a blind "delete the first key map
// iteration hands us" policy. Go randomises that order, so the old victim was
// statistically uniform — which is precisely the problem: it was equally likely
// to discard a hot, live entry as a record that expired long ago.
//
// Normally the sweeper reclaims expired entries on its own timer and the
// distinction barely matters. Under `serve_stale_infinite: true` it matters a
// great deal: runSweeper returns immediately in that mode (deliberately, so
// expired records remain available as outage fallbacks), leaving this the ONLY
// reclamation path in the entire cache. Blind eviction there means a shard can
// steadily shed its most-requested live records while dead ones persist
// indefinitely.
//
// Selection uses staleNano — the end of the serve-stale window, i.e. the moment
// an entry becomes genuinely worthless. The earliest value is the best victim.
// Map iteration is already randomised, so simply taking the first
// evictionSampleSize keys yields a uniform random sample with no extra work.
func storeItem(key DNSCacheKey, item *cacheItem) {
	shard := getShard(key)
	shard.Lock()

	if _, exists := shard.items[key]; !exists && len(shard.items) >= cacheMaxPerShard {
		var (
			victim      DNSCacheKey
			victimStale int64
			sampled     int
		)

		for k, v := range shard.items {
			if sampled == 0 || v.staleNano < victimStale {
				victim = k
				victimStale = v.staleNano
			}
			sampled++
			if sampled >= evictionSampleSize {
				break
			}
		}

		// sampled is guaranteed >= 1 here: the map is at capacity and
		// cacheMaxPerShard has a floor of 1, so the range body always executes.
		if sampled > 0 {
			delete(shard.items, victim)
		}
	}

	shard.items[key] = item
	shard.Unlock()
}



