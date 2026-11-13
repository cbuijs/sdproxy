/*
File:    cache_persistence.go
Version: 2.8.0 (Split)
Last Updated: 10-Nov-2026 14:15 CET

Description:
  Disk persistence for the sdproxy cache engine. Serializes and restores the
  live memory cache across router reboots.

  Extracted from cache.go to decouple disk I/O from the DNS hot path.

Changes:
  2.8.0 - [FIX] Included `cfg.Server.DoH3FallbackThreshold` in `computeRouteConfigHash`
          so persisted cache route fingerprints remain consistent with all global
          upstream transport settings.
  2.7.0 - [SECURITY/FIX] Included global `cfg.Server.DNS0x20`, `cfg.Server.DNSCookies`,
          and `cfg.Server.RequireDNSSECAD` flags in `computeRouteConfigHash` so
          persisted cache records are invalidated if global upstream transport or
          DNSSEC validation requirements change across restarts.
  2.6.0 - [FIX] Ensured cache persistence warnings (`LoadCache` / `SaveCache`) and
          startup cache restoration logs are emitted when `logSystem` or `logCaching`
          is active, so Simple Logging Mode (`logSimple: true`) retains startup
          messages and disk I/O warnings.
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
		RouteName        string
		Group            UpstreamGroupConfig
		HasGroup         bool
		Default          UpstreamGroupConfig
		GlobalDNS0x20    bool
		GlobalCookies    bool
		GlobalRequireAD  bool
		GlobalDoH3Thresh int
		GlobalSelection  string
		GlobalECS        ECSConfig
	}
	ugc, hasGrp := cfg.Upstreams[routeName]
	defUgc := cfg.Upstreams["default"]
	b, _ := json.Marshal(routeDescriptor{
		RouteName:        routeName,
		Group:            ugc,
		HasGroup:         hasGrp,
		Default:          defUgc,
		GlobalDNS0x20:    cfg.Server.DNS0x20,
		GlobalCookies:    cfg.Server.DNSCookies,
		GlobalRequireAD:  cfg.Server.RequireDNSSECAD,
		GlobalDoH3Thresh: cfg.Server.DoH3FallbackThreshold,
		GlobalSelection:  cfg.Server.UpstreamSelection,
		GlobalECS:        cfg.Server.ECS,
	})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

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
		if (logCaching || logSystem) && !os.IsNotExist(err) {
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

	if logCaching || logSystem {
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

	if len(records) == 0 {
		if err := os.Remove(cfg.Cache.PersistFile); err != nil && !os.IsNotExist(err) {
			_ = saveGob(cfg.Cache.PersistFile, []cacheDiskRecord{})
		} else if err == nil {
			syncDirForFile(cfg.Cache.PersistFile)
		}
		return
	}

	if err := saveGob(cfg.Cache.PersistFile, records); err != nil {
		if logCaching || logSystem {
			log.Printf("[CACHE] WARNING: failed to persist cache: %v", err)
		}
		return
	}

	if logCaching && !logSimple {
		log.Printf("[CACHE] Successfully persisted %d entries to disk", len(records))
	}
}
