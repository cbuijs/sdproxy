/*
File: cache.go
Version: 1.13.0
Last Updated: 2026-03-02 20:00 CET
Description: High-performance, sharded, non-blocking DNS cache.
             Caches positive (NOERROR), negative (NXDOMAIN), and empty (NOERROR
             with no answer records) responses per RFC 2308.
             Optimised for embedded: struct-based zero-allocation cache keys,
             pseudo-random eviction, reduced shard count.

Changes:
  1.13.0 - [PERF] CacheGet: consolidated two time.Now() calls into one. The old
           code called time.Now() explicitly for the expiry check and then again
           implicitly via time.Until() for remaining TTL calculation. On some
           embedded targets (MIPS, older ARM) time.Now() is a real syscall, not a
           vDSO fast-path. Single call, reused for both checks.
  1.12.0 - [FIX]  Negative responses (NXDOMAIN, NOERROR/empty) were not cached —
           CacheSet rejected anything with Rcode != RcodeSuccess. Every negative
           answer hit upstream on every query. Now caches NXDOMAIN and empty
           NOERROR per RFC 2308 using the SOA minimum TTL from the authority
           section. Falls back to cfg.Cache.MinTTL when no SOA is present.
           SERVFAIL and other error codes are intentionally not cached as they
           indicate transient upstream failures.
  1.11.0 - [PERF] Replaced fmt.Sprintf string cache key with a plain comparable
           struct (DNSCacheKey). fmt.Sprintf involves reflection and heap allocation
           on every cache lookup. Go map lookups on comparable structs use direct
           field comparison — zero allocation, no reflection, faster hashing.
           [PERF] Increased background sweep interval from 10s to 60s. Expired
           entries are already filtered at CacheGet time, so the sweeper only
           affects memory reclamation, not correctness. 60s halves idle wakeups.
  1.10.0 - Initial sharded cache with pseudo-random eviction.
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

// getShard hashes the struct fields via maphash.
// Name first (highest entropy for DNS workloads), then type/class, then route.
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

	if !ok {
		return nil
	}

	// Single time.Now() call — reused for both expiry check and remaining TTL.
	// On some embedded targets (MIPS, older ARM without vDSO) time.Now() is a
	// real syscall. Calling it twice per cache hit is measurable overhead.
	now := time.Now()
	if now.After(item.expiration) {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(item.msgBytes); err != nil {
		return nil
	}
	remaining := uint32(item.expiration.Sub(now).Seconds())
	if remaining == 0 {
		return nil
	}
	// Update TTLs in the answer section to reflect remaining cache lifetime
	for _, rr := range msg.Answer {
		rr.Header().Ttl = remaining
	}
	return msg
}

func CacheSet(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	// Cacheable rcodes per RFC 2308:
	//   NOERROR  (0) — positive answer or empty (NOERROR/NODATA)
	//   NXDOMAIN (3) — name does not exist
	// Everything else (SERVFAIL, REFUSED, FORMERR, etc.) indicates a transient
	// or policy failure at the upstream — never cache these.
	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		// Cacheable — fall through
	default:
		return
	}

	// Determine TTL depending on response type:
	//
	// Positive (NOERROR with answers): use the minimum TTL across answer RRs.
	//
	// Negative (NXDOMAIN or NOERROR with no answers — RFC 2308 §5):
	//   Use the SOA MINIMUM field from the authority section if present,
	//   as this is the TTL the zone owner has designated for negative caching.
	//   Fall back to cfg.Cache.MinTTL when no SOA is available (e.g. when
	//   minimize_answer is enabled and Ns section has been stripped).
	var ttl uint32
	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0 {
		// Positive response — minimum TTL across all answer records
		ttl = ^uint32(0) // max uint32 as starting value
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		// Negative response (NXDOMAIN or NOERROR/NODATA) — use SOA minimum
		ttl = 0
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				// RFC 2308 §5: negative TTL = min(SOA TTL, SOA MINIMUM field)
				soaTTL := soa.Hdr.Ttl
				if soa.Minttl < soaTTL {
					soaTTL = soa.Minttl
				}
				ttl = soaTTL
				break
			}
		}
		if ttl == 0 {
			// No SOA in authority section — fall back to configured minimum.
			// This is the normal path when minimize_answer is enabled since
			// the Ns section is stripped before CacheSet is called.
			ttl = uint32(cfg.Cache.MinTTL)
		}
	}

	// Never cache below the configured floor
	if int(ttl) < cfg.Cache.MinTTL {
		ttl = uint32(cfg.Cache.MinTTL)
	}

	packed, err := msg.Pack()
	if err != nil {
		return
	}

	expiration  := time.Now().Add(time.Duration(ttl) * time.Second)
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

