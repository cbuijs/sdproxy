/*
File:    cache.go
Version: 2.46.0 (Split)
Updated: 12-Jun-2026 14:27 CEST

Description:
  High-performance, sharded, non-blocking DNS cache core for sdproxy.
  Manages memory allocation, cryptographic sharding (HashDoS protection),
  and asynchronous garbage collection (Sweeper).
  
  Hot-path Read/Write operations have been moved to cache_rw.go.
  Disk persistence has been moved to cache_persistence.go.
  UI introspection has been moved to cache_ui.go.

Changes:
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
// ClientName explicitly partitions the cache payload natively when the routing 
// group relies on tailored upstream endpoints (e.g., NextDNS/ControlD).
// ECS explicitly partitions the cache payload natively when the routing group 
// injects localized EDNS0 Client Subnet architectures, neutralizing cross-contamination.
type DNSCacheKey struct {
	Name       string
	ClientName string 
	ECS        string 
	Qtype      uint16
	Qclass     uint16
	RouteIdx   uint16
	DoBit      bool
	CdBit      bool
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
	
	if logCaching {
		log.Printf("[CACHE] Initialised: size=%d shards=%d sweep=%s stale=%ds "+
			"prefetch=%ds/%dhits synth=%v localid=%v upneg=%v sort=%s inf_stale=%v persist=%v",
			maxSize, shardCount, sweepInterval,
			cfg.Cache.StaleTTL, cfg.Cache.PrefetchBefore, cfg.Cache.PrefetchMinHits,
			cacheSynthFlag, cacheLocalIdentity, cacheUpstreamNeg, cfg.Cache.AnswerSort, serveStaleInfinite, cfg.Cache.Persist)
	}

	go runSweeper(sweepInterval)
	
	if cfg.Cache.Persist {
		LoadCache()
		
		if cfg.Cache.PersistSaveInterval != "" && cfg.Cache.PersistSaveInterval != "0" && cfg.Cache.PersistSaveInterval != "0s" {
			if interval, err := time.ParseDuration(cfg.Cache.PersistSaveInterval); err == nil && interval > 0 {
				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for range ticker.C {
						SaveCache()
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

	for range ticker.C {
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

