/*
File: cache.go
Version: 1.14.0
Last Updated: 2026-03-03 16:00 CET
Description: High-performance, sharded, non-blocking DNS cache.
             Caches positive (NOERROR), negative (NXDOMAIN), and empty (NOERROR
             with no answer records) responses per RFC 2308.
             Optimised for embedded: struct-based zero-allocation cache keys,
             pseudo-random eviction, reduced shard count.

Changes:
  1.14.0 - [PERF] Replaced maphash.Hash shard selector with inline FNV-1a.
           maphash required creating a Hash struct, calling SetSeed, and invoking
           WriteString/Write methods on every cache operation. FNV-1a is pure
           arithmetic — no struct, no seed, no method calls, zero setup cost.
           Hash-DOS resistance (maphash's main advantage) is irrelevant for a
           private resolver; FNV-1a distribution is more than adequate for 16 shards.
           [PERF] Replaced DNSCacheKey.Route string with RouteIdx uint8. A string
           field in a map key requires Go to hash its backing bytes via a pointer
           chase. A uint8 is hashed inline with the rest of the struct — no pointer
           chase, smaller key (struct shrinks ~15 bytes), faster map operations.
           Route indices are assigned once at startup in main.go (routeIdxByName).
  1.13.0 - [PERF] CacheGet: consolidated two time.Now() calls into one.
  1.12.0 - [FIX]  Negative responses (NXDOMAIN, NOERROR/empty) now cached per RFC 2308.
  1.11.0 - [PERF] Struct-based DNSCacheKey, 60s sweep interval.
  1.10.0 - Initial sharded cache with pseudo-random eviction.
*/

package main

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSCacheKey is the map key for all cache lookups.
//
// RouteIdx replaces the previous Route string field. Route names are a small
// fixed set assigned at startup (see routeIdxByName in main.go). Storing an
// index instead of a string pointer eliminates the per-lookup pointer chase
// when Go hashes the struct key, and shrinks the struct by ~15 bytes.
//
// RouteIdx 0 is always reserved for "local" (hosts/leases answers). All other
// indices are assigned to upstream group names starting at 1.
type DNSCacheKey struct {
	Name     string
	Qtype    uint16
	Qclass   uint16
	RouteIdx uint8
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

var shards [shardCount]*cacheShard

func InitCache(maxSize int, minTTL int) {
	if !cfg.Cache.Enabled {
		return
	}
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

// getShard maps a cache key to a shard using FNV-1a.
//
// FNV-1a replaces maphash.Hash. The previous implementation created a Hash
// struct, called SetSeed, then WriteString/Write on every call. FNV-1a is
// purely arithmetic — no object, no seed lookup, no method dispatch — which
// matters on MIPS/ARM routers where every function call has non-trivial cost.
//
// Name is hashed first (highest entropy in DNS workloads). Qtype and Qclass
// are mixed together in one step. RouteIdx is a single byte — cheap XOR.
func getShard(key DNSCacheKey) *cacheShard {
	const (
		basis uint64 = 14695981039346656037
		prime uint64 = 1099511628211
	)
	h := basis
	for i := 0; i < len(key.Name); i++ {
		h ^= uint64(key.Name[i])
		h *= prime
	}
	// Fold Qtype and Qclass into a single 32-bit word, then mix once.
	h ^= uint64(key.Qtype)<<16 | uint64(key.Qclass)
	h *= prime
	h ^= uint64(key.RouteIdx)
	h *= prime
	return shards[h&(shardCount-1)]
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
	// Update TTLs in the answer section to reflect remaining cache lifetime.
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
		ttl = ^uint32(0)
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		ttl = 0
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				soaTTL := soa.Hdr.Ttl
				if soa.Minttl < soaTTL {
					soaTTL = soa.Minttl
				}
				ttl = soaTTL
				break
			}
		}
		if ttl == 0 {
			ttl = uint32(cfg.Cache.MinTTL)
		}
	}

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

