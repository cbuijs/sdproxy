/*
File: cache.go
Version: 1.11.0
Last Updated: 2026-03-01 14:00 CET
Description: High-performance, sharded, non-blocking DNS cache.
             Optimised for embedded: struct-based zero-allocation cache keys,
             pseudo-random eviction, reduced shard count.

Changes:
  1.11.0 - [PERF] Replaced fmt.Sprintf string cache key with a plain comparable
           struct (DNSCacheKey). fmt.Sprintf involves reflection and heap allocation
           on every cache lookup. Go map lookups on comparable structs use direct
           field comparison — zero allocation, no reflection, faster hashing.
           [PERF] Increased background sweep interval from 10s to 60s. Expired
           entries are already filtered at CacheGet time, so the sweeper only
           affects memory reclamation, not correctness. 60s halves idle wakeups.
  1.10.0 - Initial sharded cache with string keys and pseudo-random eviction.
*/

package main

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSCacheKey replaces the fmt.Sprintf string key — zero allocation, no reflection.
// All fields are comparable so Go uses direct field comparison for map lookups.
// Route is baked in to prevent cross-contamination between upstream partitions
// (e.g. "local_network" answers must not bleed into "default" cached responses).
type DNSCacheKey struct {
	Name   string
	Qtype  uint16
	Qclass uint16
	Route  string
}

// MEMORY OPTIMISATION: 16 shards is sufficient for a home router.
// Fewer lock/unlock cycles than 64 shards, still enough for udp_workers parallelism.
const shardCount = 16

type cacheItem struct {
	msgBytes   []byte
	expiration time.Time
}

type cacheShard struct {
	sync.RWMutex
	items map[DNSCacheKey]cacheItem
}

var (
	shards [shardCount]*cacheShard
	seed   maphash.Seed
)

func InitCache(maxSize int, minTTL int) {
	if !cfg.Cache.Enabled {
		return
	}
	seed = maphash.MakeSeed()
	for i := range shards {
		shards[i] = &cacheShard{
			items: make(map[DNSCacheKey]cacheItem),
		}
	}

	// Background sweeper: reclaims memory from naturally expired items.
	// 60s is safe — CacheGet already rejects expired entries, so the sweeper
	// only affects memory pressure, not query correctness.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for i := range shards {
				shards[i].Lock()
				for k, v := range shards[i].items {
					if now.After(v.expiration) {
						delete(shards[i].items, k)
					}
				}
				shards[i].Unlock()
			}
		}
	}()
}

// getShard hashes the struct fields via maphash (which requires bytes/strings).
// Field order: Name first (highest entropy for DNS workloads), then type/class, then route.
func getShard(key DNSCacheKey) *cacheShard {
	var h maphash.Hash
	h.SetSeed(seed)
	h.WriteString(key.Name)
	var tmp [4]byte
	tmp[0], tmp[1] = byte(key.Qtype>>8), byte(key.Qtype)
	tmp[2], tmp[3] = byte(key.Qclass>>8), byte(key.Qclass)
	h.Write(tmp[:])
	h.WriteString(key.Route)
	return shards[h.Sum64()&(shardCount-1)]
}

func CacheGet(key DNSCacheKey) *dns.Msg {
	if !cfg.Cache.Enabled {
		return nil
	}
	shard := getShard(key)
	shard.RLock()
	item, ok := shard.items[key]
	shard.RUnlock()

	if !ok || time.Now().After(item.expiration) {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(item.msgBytes); err != nil {
		return nil
	}
	remaining := uint32(time.Until(item.expiration).Seconds())
	if remaining == 0 {
		return nil
	}
	for _, rr := range msg.Answer {
		rr.Header().Ttl = remaining
	}
	return msg
}

func CacheSet(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil || msg.Rcode != dns.RcodeSuccess {
		return
	}
	var minTTL uint32 = 3600
	found := false
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
			found = true
		}
	}
	if !found {
		return
	}
	if int(minTTL) < cfg.Cache.MinTTL {
		minTTL = uint32(cfg.Cache.MinTTL)
	}
	packed, err := msg.Pack()
	if err != nil {
		return
	}
	expiration  := time.Now().Add(time.Duration(minTTL) * time.Second)
	maxPerShard := cfg.Cache.Size / shardCount
	if maxPerShard < 1 {
		maxPerShard = 1
	}
	shard := getShard(key)
	shard.Lock()
	// Zero-allocation pseudo-random eviction: Go map iteration order is randomised,
	// so deleting the first key we encounter is statistically fair and allocation-free.
	if len(shard.items) >= maxPerShard {
		for k := range shard.items {
			delete(shard.items, k)
			break
		}
	}
	shard.items[key] = cacheItem{msgBytes: packed, expiration: expiration}
	shard.Unlock()
}

