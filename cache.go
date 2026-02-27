/*
File: cache.go
Version: 1.10.0
Last Updated: 2026-02-27 20:41 CET
Description: A high-performance, sharded, non-blocking DNS cache mapping.
             OPTIMIZED FOR EMBEDDED: Removed heavy container/list LRU in favor of
             zero-allocation pseudo-random eviction. Reduced shard count.
*/

package main

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MEMORY OPTIMIZATION: Reduced from 64 to 16. A home router does not 
// process enough parallel requests to warrant 64 separate mutex locks.
const shardCount = 16 

type cacheItem struct {
	msgBytes   []byte
	expiration time.Time
}

type cacheShard struct {
	sync.RWMutex
	items map[string]cacheItem
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
	for i := 0; i < shardCount; i++ {
		shards[i] = &cacheShard{
			items: make(map[string]cacheItem),
		}
	}

	// Background Sweeper (runs every 10 seconds to clear naturally expired items)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			for i := 0; i < shardCount; i++ {
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

func getShard(key string) *cacheShard {
	var h maphash.Hash
	h.SetSeed(seed)
	h.WriteString(key)
	idx := h.Sum64() & (shardCount - 1)
	return shards[idx]
}

func CacheGet(key string) *dns.Msg {
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

	remaining := uint32(item.expiration.Sub(time.Now()).Seconds())
	if remaining == 0 {
		return nil
	}

	for _, rr := range msg.Answer {
		rr.Header().Ttl = remaining
	}

	return msg
}

func CacheSet(key string, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil || msg.Rcode != dns.RcodeSuccess {
		return
	}

	minTTL := uint32(3600)
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

	expiration := time.Now().Add(time.Duration(minTTL) * time.Second)

	// MEMORY OPTIMIZATION: Enforce strict capacity per shard
	maxPerShard := cfg.Cache.Size / shardCount
	if maxPerShard < 1 {
		maxPerShard = 1
	}

	shard := getShard(key)
	shard.Lock()
	
	// Zero-Allocation Pseudo-Random Eviction.
	// Go map iteration order is random. We grab the first key and delete it
	// if we are at capacity. This acts as a highly efficient eviction policy 
	// without the massive memory overhead of doubly-linked lists (LRU).
	if len(shard.items) >= maxPerShard {
		for k := range shard.items {
			delete(shard.items, k)
			break 
		}
	}

	shard.items[key] = cacheItem{
		msgBytes:   packed,
		expiration: expiration,
	}
	shard.Unlock()
}

