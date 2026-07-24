/*
File:    cache_persistence.go
Version: 2.0.0 (Split)
Updated: 22-Jul-2026 22:10 CEST

Description:
  Disk persistence for the sdproxy cache engine. Serializes and restores the
  live memory cache across router reboots.

  Extracted from cache.go to decouple disk I/O from the DNS hot path.

Changes:
  2.0.0 - [TIER 2] Load/save moved onto the shared buffered-gob and atomic-write
          helpers; the manual flush/sync/close/rename ladder is gone.
  1.6.0 - [SECURITY/RELIABILITY] Directory fsync so renames survive power loss.
  1.5.0 - [LOGGING/FIX] Clearer decode diagnostics for a stale or corrupt
          dns_cache.bin across binary upgrades.
*/

package main

import (
	"log"
	"os"
	"runtime"
	"sync"
	"time"
)

// cacheDiskRecord is the serialized form of one cache entry.
type cacheDiskRecord struct {
	Key      DNSCacheKey
	Packed   []byte
	Expire   int64
	Stale    int64
	CachedAt int64
	Route    string
	Hits     uint32
}

// saveCacheMu serializes flush events so a background tick and a synchronous
// shutdown flush cannot race each other onto the same file.
var saveCacheMu sync.Mutex

// LoadCache restores the DNS cache from disk.
func LoadCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	records, err := loadGob[[]cacheDiskRecord](cfg.Cache.PersistFile)
	if err != nil {
		if logCaching && !os.IsNotExist(err) {
			log.Printf("[CACHE] WARNING: cannot restore persistent cache: %v — file may be corrupt or from an older version", err)
		}
		return
	}

	now := time.Now().UnixNano()
	loaded := 0

	for _, r := range records {
		// Drop anything already outside its stale window.
		if !serveStaleInfinite && now >= r.Stale {
			continue
		}

		ci := &cacheItem{
			expireNano:   r.Expire,
			staleNano:    r.Stale,
			cachedAtNano: r.CachedAt,
			routeName:    r.Route,
		}
		ci.hits.Store(r.Hits)
		ci.prefetched.Store(false)

		packed := make([]byte, len(r.Packed))
		copy(packed, r.Packed)
		ci.packed.Store(&packed)

		storeItem(r.Key, ci)
		loaded++
	}

	if logCaching {
		log.Printf("[CACHE] Restored %d active entries from persistent storage (%s)", loaded, cfg.Cache.PersistFile)
	}
}

// SaveCache gathers all viable cache records and serializes them to disk without
// blocking the DNS path for the duration of the write.
func SaveCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	saveCacheMu.Lock()
	defer saveCacheMu.Unlock()

	now := time.Now().UnixNano()

	// [PERF] Pre-size the slice so no reallocation happens while holding a shard
	// read lock.
	totalEst := 0
	for i := range shards {
		shards[i].RLock()
		totalEst += len(shards[i].items)
		shards[i].RUnlock()
	}

	var records []cacheDiskRecord
	if totalEst > 0 {
		records = make([]cacheDiskRecord, 0, totalEst)
	}

	for i := range shards {
		shard := shards[i]
		shard.RLock()
		for k, v := range shard.items {
			if !serveStaleInfinite && now >= v.staleNano {
				continue
			}
			if p := v.packed.Load(); p != nil {
				packedCopy := make([]byte, len(*p))
				copy(packedCopy, *p)
				records = append(records, cacheDiskRecord{
					Key:      k,
					Packed:   packedCopy,
					Expire:   v.expireNano,
					Stale:    v.staleNano,
					CachedAt: v.cachedAtNano,
					Route:    v.routeName,
					Hits:     v.hits.Load(),
				})
			}
		}
		shard.RUnlock()

		// [PERF] Yield between shards. Walking 32 saturated shards back-to-back
		// otherwise monopolizes the core and starves the live UDP/TCP dialers.
		runtime.Gosched()
	}

	if len(records) == 0 {
		return
	}

	if err := saveGob(cfg.Cache.PersistFile, records); err != nil {
		if logCaching {
			log.Printf("[CACHE] WARNING: failed to persist cache: %v", err)
		}
		return
	}

	if logCaching {
		log.Printf("[CACHE] Successfully persisted %d entries to disk", len(records))
	}
}

