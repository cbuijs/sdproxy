/*
File:    cache.go
Version: 2.56.0 (Split)
Last Updated: 25-Oct-2026 15:40 CET

Description:
  High-performance, sharded, non-blocking DNS cache core for sdproxy.
  Manages memory allocation, cryptographic sharding (HashDoS protection),
  and asynchronous garbage collection (Sweeper).

  Hot-path Read/Write operations have been moved to cache_rw.go.
  Disk persistence has been moved to cache_persistence.go.
  UI introspection has been moved to cache_ui.go.

Changes:
  2.56.0 - [SECURITY/FIX] Kept `runSweeper` active when `serveStaleInfinite` is
           enabled so expired synthetic responses (`v.routeName == ""`, such as
           policy blocks and local-identity records) are still garbage-collected
           while upstream responses (`v.routeName != ""`) are retained for
           emergency stale fallback.
  2.55.0 - [SECURITY/FIX] Added `BypassPolicies` and `BypassLocal` to `DNSCacheKey`
           and `getShard` hashing.
  2.54.0 - [SECURITY/FIX] Added RecursionDesired to cache partitioning and shard hashing.
  2.53.0 - [PERF] Eliminated significant Garbage Collection (GC) thrashing
           within the `runSweeper` background routine.
  2.52.0 - [CLEANUP] Simplified `storeItem` mutex orchestration organically
           via `defer` declarations.
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
// lowerTrimDot in policy.go.
// DoBit and CdBit isolate DNSSEC-signed/unsigned and validated/unvalidated requests.
// BypassGlobal, BypassPolicies, and BypassLocal strictly partition the cache across
// policy and local-identity boundaries so synthetic blocks or local hosts records
// never contaminate routes or clients with differing policy/local-resolution rules.
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
	BypassPolicies   bool
	BypassLocal      bool
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

	rotation atomic.Uint32
}

// cacheShard is an independently locked segment of the cache.
type cacheShard struct {
	sync.RWMutex
	items map[DNSCacheKey]*cacheItem
}

const shardCount = 32

var shards [shardCount]*cacheShard

var cacheMaxPerShard int

var cacheHashSeed maphash.Seed

// ---------------------------------------------------------------------------
// Startup feature flags — set once in InitCache, read on every hot-path call.
// ---------------------------------------------------------------------------

var hasPrefetch bool
var staleEnabled bool
var cacheUpstreamNeg bool
var cacheRotateAnswers bool
var serveStaleInfinite bool
var cacheSynthFlag bool
var cacheLocalIdentity bool

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

func InitCache(maxSize int, _ int) {
	if !cfg.Cache.Enabled {
		return
	}

	cacheHashSeed = maphash.MakeSeed()

	for i := range shards {
		shards[i] = &cacheShard{items: make(map[DNSCacheKey]*cacheItem)}
	}
	cacheMaxPerShard = maxSize / shardCount
	if cacheMaxPerShard < 1 {
		cacheMaxPerShard = 1
	}

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
// When serveStaleInfinite is enabled, upstream entries (routeName != "") are
// retained for emergency fallback, while expired synthetic entries (routeName == "")
// are always evicted so stale policy blocks and local-identity records never
// linger indefinitely.
func runSweeper(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	toDelete := make([]DNSCacheKey, 0, max(cacheMaxPerShard/4, 16))

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()

			for i := range shards {
				shard := shards[i]
				toDelete = toDelete[:0]

				shard.RLock()
				for k, v := range shard.items {
					if now >= v.staleNano && (!serveStaleInfinite || v.routeName == "") {
						toDelete = append(toDelete, k)
					}
				}
				shard.RUnlock()

				if len(toDelete) == 0 {
					continue
				}
				shard.Lock()
				for _, k := range toDelete {
					if v, ok := shard.items[k]; ok && now >= v.staleNano && (!serveStaleInfinite || v.routeName == "") {
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

func getShard(key DNSCacheKey) *cacheShard {
	h := maphash.String(cacheHashSeed, key.Name)

	if key.ClientName != "" {
		h ^= maphash.String(cacheHashSeed, key.ClientName) * 0x5bd1e9955bd1e995
	}

	if key.ECS != "" {
		h ^= maphash.String(cacheHashSeed, key.ECS) * 0x9e3779b97f4a7c15
	}

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
	if key.BypassPolicies {
		mix |= 1 << 52
	}
	if key.BypassLocal {
		mix |= 1 << 53
	}

	h ^= mix

	h ^= h >> 32
	h ^= h >> 16
	h ^= h >> 8
	h ^= h >> 4

	return shards[h&(shardCount-1)]
}

// ---------------------------------------------------------------------------
// Internal store helper
// ---------------------------------------------------------------------------

const evictionSampleSize = 8

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
