/*
File:    cache_persistence.go
Version: 2.5.0 (Split)
Last Updated: 25-Oct-2026 15:40 CET

Description:
  Disk persistence for the sdproxy cache engine. Serializes and restores the
  live memory cache across router reboots.

  Extracted from cache.go to decouple disk I/O from the DNS hot path.

Changes:
  2.5.0 - [SECURITY/FIX] Added per-route upstream configuration fingerprinting
          (`RouteHash` via `computeRouteConfigHash`, `cacheDiskVersion = 3`) so
          persisted records are rejected if their route numerical index, route
          identity, or upstream group configuration changed across restarts.
        - [SECURITY/FIX] Removed or atomically cleared the on-disk snapshot in
          `SaveCache` when the live cache is empty (`len(records) == 0`),
          preventing stale on-disk records from resurrecting on restart.
        - [SECURITY/FIX] Excluded expired synthetic entries (`routeName == ""`)
          from infinite-stale persistence in `SaveCache` and `LoadCache`.
  2.4.0 - [SECURITY/FIX] Bumped `cacheDiskVersion` to 2 after expanding `DNSCacheKey`
          with `BypassPolicies` and `BypassLocal` partitioning, and verified route
          index consistency (`getRouteIdx(r.Route) == r.Key.RouteIdx`) on restore.
  2.3.1 - [FIX] Fixed `Route: v.routeName` assignment in `SaveCache`.
  2.3.0 - [FIX] Switched `LoadCache` to use `loadGobInto` (`helpers_io.go` 1.3.0)
          so generic bracket syntax is no longer required.
  2.2.0 - [PERF] Eradicated a massive, redundant memory allocation natively within SaveCache. 
  2.1.0 - [SECURITY/FIX] Versioned persisted records. Existing cache files are
          discarded on load after cache-key semantics changed to include RD.
  2.0.0 - [TIER 2] Load/save moved onto the shared buffered-gob and atomic-write
          helpers.
*/

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"runtime"
	"sync"
	"time"
)

// cacheDiskRecord is the serialized form of one cache entry.
const cacheDiskVersion uint8 = 3

type cacheDiskRecord struct {
	Version   uint8
	Key       DNSCacheKey
	Packed    []byte
	Expire    int64
	Stale     int64
	CachedAt  int64
	Route     string
	RouteHash string
	Hits      uint32
}

var saveCacheMu sync.Mutex

// computeRouteConfigHash generates a deterministic fingerprint for a route's
// effective upstream group configuration (or synthetic/policy state when routeName == "")
// so persisted records cannot cross routing boundaries or survive upstream config changes.
func computeRouteConfigHash(routeName string, routeIdx uint16) string {
	if routeName == "" {
		var idxTarget string
		for name, idx := range routeIdxByName {
			if idx == routeIdx {
				idxTarget = name
				break
			}
		}
		h := sha256.Sum256([]byte("synth:" + idxTarget))
		return hex.EncodeToString(h[:8])
	}

	type routeDescriptor struct {
		RouteName string
		Group     UpstreamGroupConfig
		HasGroup  bool
		Default   UpstreamGroupConfig
	}
	ugc, hasGrp := cfg.Upstreams[routeName]
	defUgc := cfg.Upstreams["default"]
	b, _ := json.Marshal(routeDescriptor{
		RouteName: routeName,
		Group:     ugc,
		HasGroup:  hasGrp,
		Default:   defUgc,
	})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// buildRouteHashTable precomputes configuration hashes for all active routes.
func buildRouteHashTable() map[string]string {
	out := make(map[string]string, len(routeIdxByName)+2)
	for name, idx := range routeIdxByName {
		out[name] = computeRouteConfigHash(name, idx)
	}
	return out
}

// LoadCache restores the DNS cache from disk.
func LoadCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	var records []cacheDiskRecord
	if err := loadGobInto(cfg.Cache.PersistFile, &records); err != nil {
		if logCaching && !os.IsNotExist(err) {
			log.Printf("[CACHE] WARNING: cannot restore persistent cache: %v — file may be corrupt or from an older version", err)
		}
		return
	}

	now := time.Now().UnixNano()
	routeHashes := buildRouteHashTable()
	loaded := 0

	for _, r := range records {
		if r.Version != cacheDiskVersion {
			continue
		}
		// Never restore expired synthetic entries even when serveStaleInfinite is enabled.
		if now >= r.Stale && (!serveStaleInfinite || r.Route == "") {
			continue
		}

		if r.Route != "" {
			idx, ok := routeIdxByName[r.Route]
			if !ok || idx != r.Key.RouteIdx {
				continue
			}
			if r.RouteHash == "" || r.RouteHash != routeHashes[r.Route] {
				continue
			}
		} else {
			expectedHash := computeRouteConfigHash("", r.Key.RouteIdx)
			if r.RouteHash == "" || r.RouteHash != expectedHash {
				continue
			}
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
	routeHashes := buildRouteHashTable()

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
			if now >= v.staleNano && (!serveStaleInfinite || v.routeName == "") {
				continue
			}
			if p := v.packed.Load(); p != nil {
				rHash := routeHashes[v.routeName]
				if rHash == "" {
					rHash = computeRouteConfigHash(v.routeName, k.RouteIdx)
				}
				records = append(records, cacheDiskRecord{
					Version:   cacheDiskVersion,
					Key:       k,
					Packed:    *p,
					Expire:    v.expireNano,
					Stale:     v.staleNano,
					CachedAt:  v.cachedAtNano,
					Route:     v.routeName,
					RouteHash: rHash,
					Hits:      v.hits.Load(),
				})
			}
		}
		shard.RUnlock()

		runtime.Gosched()
	}

	// [SECURITY/FIX 2.5.0] When the in-memory cache is empty, remove any existing
	// on-disk snapshot so stale entries cannot resurrect on the next startup.
	if len(records) == 0 {
		if err := os.Remove(cfg.Cache.PersistFile); err != nil && !os.IsNotExist(err) {
			_ = saveGob(cfg.Cache.PersistFile, []cacheDiskRecord{})
		} else if err == nil {
			syncDirForFile(cfg.Cache.PersistFile)
		}
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
