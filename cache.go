/*
File:    cache.go
Version: 2.54.0 (Split)
Last Updated: 04-Sep-2026 12:32 CEST

Description:
  High-performance, sharded, non-blocking DNS cache core for sdproxy.
  Manages memory allocation, cryptographic sharding (HashDoS protection),
  and asynchronous garbage collection (Sweeper).

  Hot-path Read/Write operations have been moved to cache_rw.go.
  Disk persistence has been moved to cache_persistence.go.
  UI introspection has been moved to cache_ui.go.

Changes:
  2.54.0 - [SECURITY/FIX] Added RecursionDesired to cache partitioning and shard hashing.
           Recursive and non-recursive client queries must never share cached responses.
  2.53.0 - [PERF] Eliminated significant Garbage Collection (GC) thrashing
           within the `runSweeper` background routine. Hoisted the `toDelete`
           array allocation completely out of the iteration loop, leveraging
           `[:0]` capacity-reuse natively to eradicate 32 redundant slice
           allocations per sweeping cycle organically across the lifetime
           of the process.
  2.52.0 - [CLEANUP] Simplified `storeItem` mutex orchestration organically
           via `defer` declarations. Eliminated redundant condition bounds
           during oldest-victim sample evictions natively.
  2.51.0 - [PERF/FIX] Eliminated the cache-hot-path repack caused by
           `answer_sort: round-robin`.
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
	Name             string
	ClientName       string
	ECS              string
	Qtype            uint16
	Qclass           uint16
	RouteIdx         uint16
	DoBit            bool
	CdBit            bool
	BypassGlobal     bool
	RecursionDesired bool
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
	hasPrefetch = cfg.Cache.PrefetchBefore > 0 && cfg.Cache.PrefetchMinHits > 0
	staleEnabled = cfg.Cache.StaleTTL > 0
	cacheUpstreamNeg = cfg.Cache.CacheUpstreamNegative
	cacheSynthFlag = cfg.Cache.CacheSynthetic
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
func runSweeper(interval time.Duration) {
	if serveStaleInfinite {
		// Disable garbage collection of expired records so they remain
		// available indefinitely for upstream outage fallbacks.
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// [PERF/FIX] Allocate the eviction array ONCE outside the sweeping loop.
	// By leveraging capacity-reuse (toDelete[:0]) natively, we completely eradicate
	// 32 redundant slice heap-allocations per sweep cycle, drastically reducing
	// Garbage Collection (GC) thrashing and locking contention organically over
	// the lifetime of the process.
	toDelete := make([]DNSCacheKey, 0, max(cacheMaxPerShard/4, 16))

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()

			for i := range shards {
				shard := shards[i]

				// Re-slice to zero length to reuse the underlying capacity organically
				toDelete = toDelete[:0]

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
func getShard(key DNSCacheKey) *cacheShard {
	// Hash the domain name utilizing the cryptographically seeded maphash
	h := maphash.String(cacheHashSeed, key.Name)

	// Incorporate dynamic ClientName boundaries to guarantee total cache isolation
	// when upstream protocols specify individualized targeting natively.
	if key.ClientName != "" {
		h ^= maphash.String(cacheHashSeed, key.ClientName) * 0x5bd1e9955bd1e995
	}

	// Incorporate ECS boundaries dynamically to prevent subset-target contamination
	// natively across independent origin IP mappings.
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
	if key.RecursionDesired {
		mix |= 1 << 51
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
const evictionSampleSize = 8

// storeItem acquires the shard write-lock, evicts the oldest of a small random
// sample when the shard is at capacity, then stores item under key.
//
// [CLEANUP 2.52.0] Refactored to utilize localized `defer` operations, eliminating
// redundant condition constraints natively during active eviction matrices.
func storeItem(key DNSCacheKey, item *cacheItem) {
	shard := getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if _, exists := shard.items[key]; !exists && len(shard.items) >= cacheMaxPerShard {
		var victim DNSCacheKey
		var victimStale int64
		var sampled int

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

		delete(shard.items, victim)
	}

	shard.items[key] = item
}
