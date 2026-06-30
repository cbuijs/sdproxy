/*
File:    cache_persistence.go
Version: 1.4.0 (Split)
Updated: 18-Jun-2026 15:15 CEST

Description:
  Disk persistence routines for the sdproxy cache engine.
  Serializes and deserializes the live memory cache securely across router
  reboots to preserve structural state natively.

  Extracted from cache.go to decouple disk I/O from the DNS hot-path.

Changes:
  1.4.0 - [PERF] Injected `runtime.Gosched()` safely between memory shard extractions 
          natively. Effectively prevents the background Disk I/O flush iteration 
          from starving the active UDP worker threads during peak volumetric floods 
          on embedded routers deploying 50k+ entry constraints organically.
  1.3.0 - [SECURITY/FIX] Added a central `saveCacheMu` Mutex to rigidly orchestrate 
          disk flushing events. Definitively neutralizes fatal race conditions 
          between background polling ticks and synchronous OS `Shutdown` events.
  1.2.0 - [SECURITY/FIX] Enforced strict disk write verification organically. 
          Ignored flush, sync, and close errors on embedded routers caused corrupted 
          0-byte files to overwrite valid persistent data upon kernel cache flushes. 
          The routine now actively aborts atomic renames upon write failures natively.
*/

package main

import (
	"bufio"
	"encoding/gob"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// cacheDiskRecord defines the structural footprint utilized natively to 
// serialize active cache representations to disk securely.
type cacheDiskRecord struct {
	Key      DNSCacheKey
	Packed   []byte
	Expire   int64
	Stale    int64
	CachedAt int64
	Route    string
	Hits     uint32
}

var saveCacheMu sync.Mutex

// ---------------------------------------------------------------------------
// Disk Persistence (Load / Save)
// ---------------------------------------------------------------------------

// LoadCache natively restores the DNS cache state from disk securely organically.
func LoadCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	f, err := os.Open(cfg.Cache.PersistFile)
	if err != nil {
		if !os.IsNotExist(err) && logCaching {
			log.Printf("[CACHE] WARNING: Cannot read persistent cache file: %v", err)
		}
		return
	}
	defer f.Close()

	// [PERF] Apply a 64KB buffered reader to radically slash IO read syscalls natively
	br := bufio.NewReaderSize(f, 64*1024)
	var records []cacheDiskRecord
	dec := gob.NewDecoder(br)
	if err := dec.Decode(&records); err != nil {
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to decode persistent cache payloads natively: %v", err)
		}
		return
	}

	now := time.Now().UnixNano()
	loaded := 0

	for _, r := range records {
		// Immediately drop records completely outside our tolerance boundary organically
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
		log.Printf("[CACHE] Restored %d active entries from persistent storage (%s) natively", loaded, cfg.Cache.PersistFile)
	}
}

// SaveCache gathers all viable cache records organically without inducing 
// global execution blocks, and serializes the binary structure to disk automatically.
func SaveCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	saveCacheMu.Lock()
	defer saveCacheMu.Unlock()

	now := time.Now().UnixNano()

	// [PERF/OPTIMIZATION] Pre-calculate slice capacity to completely eradicate 
	// dynamic heap array re-allocations while holding RLock on the active shards natively.
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

	// Gather all valid records natively while minimizing hot-path Mutex locks
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
		
		// [PERF/FIX] Gracefully relinquish the processor core to the system scheduler natively.
		// Ensures that iterating sequentially across 32 saturated caching shards does not 
		// monopolize threads and inadvertently starve the live UDP/TCP network dialers 
		// during heavy I/O polling operations.
		runtime.Gosched()
	}

	if len(records) == 0 {
		return
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Cache.PersistFile), 0755); err != nil {
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to create cache directory natively: %v", err)
		}
		return
	}

	// Persist cleanly via an atomic rename boundary to prevent binary corruption securely
	tmpPath := cfg.Cache.PersistFile + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to create temporary cache file natively: %v", err)
		}
		return
	}

	// [PERF] Apply a 64KB buffered writer to drastically slash IO write syscalls 
	// when encoding thousands of small binary structs natively.
	bw := bufio.NewWriterSize(f, 64*1024)
	enc := gob.NewEncoder(bw)
	
	if err := enc.Encode(records); err != nil {
		f.Close()
		os.Remove(tmpPath)
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to encode cache payload securely natively: %v", err)
		}
		return
	}
	
	// [SECURITY/FIX] Enforce strict disk write verification natively.
	// Ignored flush/sync errors on embedded routers cause corrupted 0-byte 
	// files to overwrite valid persistent data upon kernel cache flushes.
	if err := bw.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to flush cache payload to disk natively: %v", err)
		}
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to sync cache payload to disk natively: %v", err)
		}
		return
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to close temporary cache file natively: %v", err)
		}
		return
	}

	if err := os.Rename(tmpPath, cfg.Cache.PersistFile); err != nil {
		if logCaching {
			log.Printf("[CACHE] WARNING: Failed to atomically save persistent cache natively: %v", err)
		}
	} else {
		if logCaching {
			log.Printf("[CACHE] Successfully persisted %d entries to disk natively", len(records))
		}
	}
}

