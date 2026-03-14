/*
File:    cache.go
Version: 1.19.0
Updated: 2026-03-14 15:00 CET
Description: High-performance, sharded, non-blocking DNS cache.
             Caches positive (NOERROR), negative (NXDOMAIN), and empty (NOERROR
             with no answer records) responses per RFC 2308.
             Optimised for embedded: struct-based zero-allocation cache keys,
             pseudo-random eviction.

Changes:
  1.19.0 - [FIX] Bug 4: CacheGet sub-second fresh-window edge case now falls
           through to the stale path when stale_ttl > 0, instead of returning a
           miss. Previously a record with <1s of TTL left was evicted from the
           fresh path but was never handed to backgroundRevalidate — causing an
           unnecessary synchronous upstream call in the last second of every TTL.
           When stale_ttl=0 the old miss behaviour is preserved.
           [FIX] Bug 6: Background sweeper now uses a two-phase
           read-then-write strategy. Phase 1 collects expired keys under a
           cheap RLock. Phase 2 re-acquires a full Lock only when there is
           actually work to do, and re-checks staleUntil before deleting to
           avoid evicting a freshly-populated entry that arrived between the
           two lock phases. On a MIPS/ARM home router where map iteration over
           128 items takes measurable time, this eliminates the periodic
           read-latency spike that the old full-write-lock-during-scan caused.
  1.18.0 - [FEAT] Serve-stale / background revalidation (RFC 8767).
           cacheItem gains staleUntil time.Time; CacheGet returns (msg, isStale bool).
           Stale entries served with TTL=0. Sweeper uses staleUntil as deletion fence.
           [FEAT] Dedicated NegativeTTL floor for NXDOMAIN/NODATA responses.
           [FEAT] cacheItem.routeName stored for background revalidation.
  1.17.0 - [PERF] shardCount 16→32. cacheItem stores *dns.Msg (not packed bytes).
  1.16.0 - [PERF] Pre-computed cacheMaxPerShard in InitCache.
  1.15.0 - [FEAT] max_ttl support.
  1.14.0 - [PERF] Inline FNV-1a shard selector, RouteIdx uint8 cache key.
  1.13.0 - [PERF] Single time.Now() per CacheGet call.
  1.12.0 - [FIX]  Negative responses cached per RFC 2308.
  1.11.0 - [PERF] Struct-based DNSCacheKey, 60 s sweep interval.
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
// Name must always be normalised (lowercase, no trailing dot) as produced by
// lowerTrimDot in process.go — ensures "GOOGLE.COM." and "google.com" share
// the same entry.
// RouteIdx uint8 replaces the Route string, eliminating the per-lookup pointer
// chase and shrinking the struct by ~15 bytes.
type DNSCacheKey struct {
	Name     string
	Qtype    uint16
	Qclass   uint16
	RouteIdx uint8
}

// shardCount controls how many independent RWMutex-protected map buckets the
// cache is split across. 32 is a good fit for a 10-worker UDP pool.
// MUST be a power of two — used as a bitmask in getShard.
const shardCount = 32

// cacheItem holds one cached DNS response.
//
// msg is an immutable deep copy created at CacheSet time. Callers receive their
// own msg.Copy() from CacheGet and may mutate it freely.
//
// expiration — the TTL-derived "fresh" deadline. Beyond this, isStale=true.
// staleUntil — expiration + StaleTTL. Beyond this, the entry is treated as a
//
//	miss. When StaleTTL=0, staleUntil==expiration (no stale window).
//
// routeName  — the upstream group that produced this entry; used by the
//
//	backgroundRevalidate path in process.go to find the right upstreams.
type cacheItem struct {
	msg        *dns.Msg  // immutable after store; callers always get a Copy
	expiration time.Time // end of fresh window
	staleUntil time.Time // end of stale window (== expiration when StaleTTL=0)
	routeName  string    // upstream group name (e.g. "default", "kids")
}

type cacheShard struct {
	sync.RWMutex
	items map[DNSCacheKey]cacheItem
}

var shards [shardCount]*cacheShard

// cacheMaxPerShard is the eviction threshold per shard, pre-computed in
// InitCache to avoid a division on every CacheSet call.
var cacheMaxPerShard int

// InitCache initialises all shards and starts the background sweeper.
// Called once from main() after cfg is populated.
func InitCache(maxSize int, _ int) {
	if !cfg.Cache.Enabled {
		return
	}
	for i := range shards {
		shards[i] = &cacheShard{
			items: make(map[DNSCacheKey]cacheItem),
		}
	}
	cacheMaxPerShard = maxSize / shardCount
	if cacheMaxPerShard < 1 {
		cacheMaxPerShard = 1
	}

	// Background sweeper — reclaims entries whose stale window has passed.
	//
	// 60 s tick is safe: CacheGet already rejects expired entries on read; the
	// sweeper only affects memory, not query correctness. Entries inside the
	// stale window (expiration < now < staleUntil) are kept alive intentionally
	// so backgroundRevalidate can serve them.
	//
	// Bug 6 fix: two-phase read-then-write strategy.
	//   Phase 1: collect expired keys under a cheap RLock — other readers and
	//            writers on this shard are not blocked.
	//   Phase 2: re-acquire a full Lock and delete. The staleUntil check is
	//            repeated inside the write lock to handle the race where a fresh
	//            upstream response re-populated the same key between the two
	//            phases; we must not evict an entry that just came back to life.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for i := range shards {
				shard := shards[i]

				// Phase 1: cheap read scan.
				shard.RLock()
				var toDelete []DNSCacheKey
				for k, v := range shard.items {
					if now.After(v.staleUntil) {
						toDelete = append(toDelete, k)
					}
				}
				shard.RUnlock()

				// Phase 2: delete only when there is actual work, and re-check
				// staleUntil under the write lock to avoid evicting a freshly
				// re-populated entry that arrived between the two phases.
				if len(toDelete) > 0 {
					shard.Lock()
					for _, k := range toDelete {
						if v, ok := shard.items[k]; ok && now.After(v.staleUntil) {
							delete(shard.items, k)
						}
					}
					shard.Unlock()
				}
			}
		}
	}()
}

// getShard maps a cache key to a shard using inline FNV-1a.
//
// Purely arithmetic — no object allocation, no method dispatch. Name is hashed
// first (highest entropy). Qtype and Qclass are mixed in one step. RouteIdx
// is a cheap single-byte XOR. Matters on MIPS/ARM where syscalls are expensive.
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
	h ^= uint64(key.Qtype)<<16 | uint64(key.Qclass)
	h *= prime
	h ^= uint64(key.RouteIdx)
	h *= prime
	return shards[h&(shardCount-1)]
}

// CacheGet returns a caller-owned copy of a cached response with TTLs rewritten
// to the remaining lifetime, plus an isStale flag.
//
//	isStale=false — fresh entry; TTLs reflect remaining lifetime normally.
//	isStale=true  — entry is past its TTL but inside the stale window.
//	                TTLs are set to 0 (RFC 8767 §4) so clients know the answer
//	                may be refreshed soon. ProcessDNS fires backgroundRevalidate.
//
// Returns (nil, false) on a complete miss or when the stale window has passed.
func CacheGet(key DNSCacheKey) (*dns.Msg, bool) {
	if !cfg.Cache.Enabled {
		return nil, false
	}
	shard := getShard(key)
	shard.RLock()
	item, ok := shard.items[key]
	shard.RUnlock()

	if !ok {
		return nil, false
	}

	// Single time.Now() — reused for both boundary checks and TTL math.
	// On embedded targets without vDSO, this is a real syscall.
	now := time.Now()

	// Past the full stale window — treat as miss (sweeper hasn't caught it yet).
	if now.After(item.staleUntil) {
		return nil, false
	}

	isStale := now.After(item.expiration)

	// Stale window only active when StaleTTL > 0. Reject expired entries otherwise.
	if isStale && cfg.Cache.StaleTTL <= 0 {
		return nil, false
	}

	// Compute remaining TTL for fresh entries.
	// Stale entries get TTL=0 per RFC 8767 §4.
	var remaining uint32
	if !isStale {
		r := item.expiration.Sub(now).Seconds()
		if r < 1 {
			// Bug 4 fix: sub-second fresh window — the entry is functionally expired.
			// When serve-stale is enabled, promote it to the stale path so
			// backgroundRevalidate fires and the client gets TTL=0 instead of a miss
			// that forces a synchronous upstream round-trip. Without serve-stale,
			// keep the old miss behaviour so the next query fetches fresh data.
			if cfg.Cache.StaleTTL <= 0 {
				return nil, false
			}
			// remaining stays 0, same wire behaviour as a deliberate stale hit.
			isStale = true
		} else {
			remaining = uint32(r)
		}
	}
	// remaining==0 for stale responses — intentional (RFC 8767 §4).

	// Deep copy: caller owns the result and may mutate it (patch ID, transforms).
	out := item.msg.Copy()

	// Rewrite TTLs in all sections to reflect actual remaining/stale lifetime.
	// OPT (TypeOPT) carries EDNS0 flags, not a TTL — never touch it.
	for _, rr := range out.Answer {
		rr.Header().Ttl = remaining
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = remaining
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = remaining
		}
	}
	return out, isStale
}

// CacheSet stores a deep copy of msg under key with a TTL-derived expiration.
//
// routeName is the upstream group that produced this response; stored in the
// item so backgroundRevalidate can look up the correct upstreams later.
//
// TTL derivation:
//
//	Positive (NOERROR with answers):  minimum TTL across all answer RRs.
//	Negative (NXDOMAIN or NODATA):    SOA minimum from authority section;
//	                                  falls back to NegativeTTL or MinTTL.
func CacheSet(key DNSCacheKey, msg *dns.Msg, routeName string) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	// Only NOERROR and NXDOMAIN are cacheable per RFC 2308.
	// SERVFAIL, REFUSED, FORMERR etc. are transient or policy failures — skip.
	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		// fall through
	default:
		return
	}

	// Classify response type once — reused for TTL derivation and floor selection.
	isNeg := msg.Rcode == dns.RcodeNameError ||
		(msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)

	var ttl uint32
	if !isNeg {
		// Positive NOERROR: minimum TTL across all answer records.
		ttl = ^uint32(0) // start at max; shrink to actual minimum
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		// Negative (NXDOMAIN or NOERROR/NODATA — RFC 2308 §5).
		// Prefer SOA minimum from the authority section when present.
		// CacheSet is called before transformResponse, so Ns is always intact
		// even when minimize_answer would later strip it.
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
		// No SOA: use NegativeTTL as the dedicated negative fallback,
		// or MinTTL when NegativeTTL is not configured (backwards compat).
		if ttl == 0 {
			if cfg.Cache.NegativeTTL > 0 {
				ttl = uint32(cfg.Cache.NegativeTTL)
			} else {
				ttl = uint32(cfg.Cache.MinTTL)
			}
		}
	}

	// Floor enforcement:
	//   Positive responses  → MinTTL.
	//   Negative responses  → NegativeTTL when explicitly set; else MinTTL.
	effectiveMin := cfg.Cache.MinTTL
	if isNeg && cfg.Cache.NegativeTTL > 0 {
		effectiveMin = cfg.Cache.NegativeTTL
	}
	if int(ttl) < effectiveMin {
		ttl = uint32(effectiveMin)
	}

	// Ceiling: max_ttl=0 means unlimited. Applies to both positive and negative.
	if cfg.Cache.MaxTTL > 0 && int(ttl) > cfg.Cache.MaxTTL {
		ttl = uint32(cfg.Cache.MaxTTL)
	}

	now        := time.Now()
	expiration := now.Add(time.Duration(ttl) * time.Second)

	// staleUntil extends past expiration by StaleTTL seconds.
	// When StaleTTL=0 (default), staleUntil==expiration — no stale window.
	staleUntil := expiration
	if cfg.Cache.StaleTTL > 0 {
		staleUntil = expiration.Add(time.Duration(cfg.Cache.StaleTTL) * time.Second)
	}

	// Deep copy so the caller may mutate msg after this call returns.
	stored := msg.Copy()

	shard := getShard(key)
	shard.Lock()
	// Zero-allocation pseudo-random eviction: Go map iteration order is
	// randomised — first key encountered is statistically fair. No division,
	// no sorting, no secondary data structure.
	if len(shard.items) >= cacheMaxPerShard {
		for k := range shard.items {
			delete(shard.items, k)
			break
		}
	}
	shard.items[key] = cacheItem{
		msg:        stored,
		expiration: expiration,
		staleUntil: staleUntil,
		routeName:  routeName,
	}
	shard.Unlock()
}

