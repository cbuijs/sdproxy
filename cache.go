/*
File:    cache.go
Version: 2.60.0 (Split)
Last Updated: 27-Nov-2026 13:30 CET

Description:
  High-performance, sharded, non-blocking DNS cache core for sdproxy.
  Manages memory allocation, cryptographic sharding (HashDoS protection),
  and asynchronous garbage collection (Sweeper).

  Hot-path Read/Write operations live in cache_rw.go.
  Disk persistence lives in cache_persistence.go.
  UI introspection lives in cache_ui.go.

Changes:
  2.60.0 - [PERF/SECURITY] Upgraded `storeItem` to a 2-tier sampled eviction
           policy: (1) immediately evict dead entries (`isEntryDead`), (2) prefer
           stale/expired entries over live entries, and (3) score live entries
           with a hit-weighted horizon (`staleNano + min(hits, 64)*5s`) so
           NXDOMAIN/scan floods cannot evict frequently hit records.
         - [FIX] Added `routeLocalTag` (`"\x00local"`) and `isSyntheticRoute` so
           local-identity cache entries are cleanly distinguished from policy
           synthetic entries across `LoadCache`, `DumpCache`, and telemetry while
           still expiring normally under `serveStaleInfinite`.
  2.59.0 - [FIX] Used ceiling division `(maxSize + shardCount - 1) / shardCount`
           when deriving `cacheMaxPerShard`.
  2.58.0 - [CLEANUP] Removed unused second parameter `_ int` from `InitCache`.
  2.57.0 - [FIX] Emitted startup `InitCache` summary and `persist_save_interval`
           warnings when `logSystem` or `logCaching` is active.
  2.56.0 - [SECURITY/FIX] Kept `runSweeper` active when `serveStaleInfinite` is
           enabled so expired synthetic responses are still garbage-collected.
  2.55.0 - [SECURITY/FIX] Added `BypassPolicies` and `BypassLocal` to `DNSCacheKey`.
  2.54.0 - [SECURITY/FIX] Added `RecursionDesired` to cache partitioning.
  2.53.0 - [PERF] Eliminated GC thrashing within `runSweeper`.
  2.52.0 - [CLEANUP] Simplified `storeItem` mutex orchestration via `defer`.
  2.51.0 - [PERF/FIX] Eliminated hot-path repack on `answer_sort: round-robin`.
*/

package main

import (
	"hash/maphash"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// routeLocalTag marks cached local-identity responses (`hosts_files` / `*_leases`)
// distinctly from policy-synthesized responses (`""`) while keeping both out of
// upstream route namespaces (`\x00` cannot appear in YAML upstream group names).
const routeLocalTag = "\x00local"

func isSyntheticRoute(routeName string) bool {
	return routeName == "" || routeName == routeLocalTag
}

func isEntryDead(v *cacheItem, now int64) bool {
	return now >= v.staleNano && (!serveStaleInfinite || isSyntheticRoute(v.routeName))
}

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

type cacheItem struct {
	packed       atomic.Pointer[[]byte]
	expireNano   int64
	staleNano    int64
	cachedAtNano int64
	routeName    string
	hits         atomic.Uint32
	prefetched   atomic.Bool

	rotation atomic.Uint32
}

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

func InitCache(maxSize int) {
	if !cfg.Cache.Enabled {
		return
	}

	cacheHashSeed = maphash.MakeSeed()

	for i := range shards {
		shards[i] = &cacheShard{items: make(map[DNSCacheKey]*cacheItem)}
	}
	cacheMaxPerShard = (maxSize + shardCount - 1) / shardCount
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

	if logCaching || logSystem {
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
			} else if logCaching || logSystem {
				log.Printf("[CACHE] WARNING: Invalid persist_save_interval %q: %v", cfg.Cache.PersistSaveInterval, err)
			}
		}
	}
}

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
					if isEntryDead(v, now) {
						toDelete = append(toDelete, k)
					}
				}
				shard.RUnlock()

				if len(toDelete) == 0 {
					continue
				}
				shard.Lock()
				for _, k := range toDelete {
					if v, ok := shard.items[k]; ok && isEntryDead(v, now) {
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

const (
	evictionSampleSize = 8
	hitBonusStepNano   = int64(5 * time.Second)
	hitBonusMaxCount   = 64
)

func storeItem(key DNSCacheKey, item *cacheItem) {
	shard := getShard(key)
	now := item.cachedAtNano
	if now <= 0 {
		now = time.Now().UnixNano()
	}

	shard.Lock()
	defer shard.Unlock()

	if _, exists := shard.items[key]; !exists && len(shard.items) >= cacheMaxPerShard {
		var (
			victim        DNSCacheKey
			victimScore   int64
			victimExpired bool
			sampled       int
		)

		for k, v := range shard.items {
			if isEntryDead(v, now) {
				victim = k
				sampled = 1
				break
			}

			expired := now >= v.expireNano
			score := v.staleNano
			if !expired {
				hits := min(int64(v.hits.Load()), hitBonusMaxCount)
				score += hits * hitBonusStepNano
			}

			better := sampled == 0 ||
				(expired && !victimExpired) ||
				(expired == victimExpired && score < victimScore)
			if better {
				victim = k
				victimScore = score
				victimExpired = expired
			}

			sampled++
			if sampled >= evictionSampleSize {
				break
			}
		}

		if sampled > 0 {
			delete(shard.items, victim)
		}
	}

	shard.items[key] = item
}
