/*
File: cache.go
Version: 1.18.0
Last Updated: 2026-03-10 12:00 CET
Description: High-performance, sharded, non-blocking DNS cache.
             Caches positive (NOERROR), negative (NXDOMAIN), and empty (NOERROR
             with no answer records) responses per RFC 2308.
             Optimised for embedded: struct-based zero-allocation cache keys,
             pseudo-random eviction.

             NEW — SERVE-STALE / BACKGROUND REVALIDATION (stale_ttl)
             ──────────────────────────────────────────────────────────
             Each cacheItem now carries two time boundaries:
               expiration  — the TTL-derived "fresh" window. CacheGet returns
                             (msg, isStale=false) while now < expiration.
               staleUntil  — expiration + cfg.Cache.StaleTTL. While the entry
                             lives in this extra window, CacheGet returns
                             (msg, isStale=true). ProcessDNS serves the stale
                             response immediately (zero latency for the client)
                             and fires a backgroundRevalidate goroutine.
                             When StaleTTL=0 (default), staleUntil==expiration
                             and behaviour is identical to v1.17.0.
             The background sweeper was updated to delete on now>staleUntil,
             keeping stale entries in memory for the full stale window.
             Per RFC 8767, stale responses are served with TTL=0 so clients
             know the answer may be refreshed shortly.

             NEW — DEDICATED NEGATIVE TTL (negative_ttl)
             ──────────────────────────────────────────────────────────
             negative_ttl gives operators a separate TTL floor specifically
             for NXDOMAIN and NOERROR/NODATA responses, independent of
             min_ttl (which now applies only to positive responses when
             negative_ttl is set). Useful on routers where you want to
             cache positive records for 60 s but cap negative/mistyped
             entries at 30 s to avoid long wait times after a typo.
             When negative_ttl=0 (default), behaviour is identical to v1.17.0
             (MinTTL applies as the floor for all response types).

             NEW — routeName stored in cacheItem
             ──────────────────────────────────────────────────────────
             cacheItem.routeName is the upstream group that produced this
             entry (e.g. "default", "kids"). Stored so backgroundRevalidate
             in process.go can look up the correct upstream group without
             needing a reverse routeIdx→name map.

Changes:
  1.18.0 - [FEAT] Serve-stale / background revalidation (RFC 8767).
           cacheItem gains staleUntil time.Time; CacheGet returns (msg, isStale bool).
           Stale entries served with TTL=0. Sweeper uses staleUntil as deletion fence.
           [FEAT] Dedicated NegativeTTL floor for NXDOMAIN/NODATA responses.
           Separates the min_ttl concern: positives use MinTTL, negatives use
           NegativeTTL (when set), falling back to MinTTL for backwards compat.
           [FEAT] cacheItem.routeName stored for background revalidation.
           CacheSet gains routeName string parameter; all callers updated.
  1.17.0 - [PERF] shardCount 16→32. cacheItem stores *dns.Msg (not packed bytes).
           CacheGet returns a fresh deep copy; CacheSet stores its own deep copy.
  1.16.0 - [PERF] Pre-computed cacheMaxPerShard in InitCache.
  1.15.0 - [FEAT] max_ttl support. CacheGet rewrites TTLs in Ns/Extra sections.
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
//              miss. When StaleTTL=0, staleUntil==expiration (no stale window).
// routeName  — the upstream group that produced this entry; used by the
//              backgroundRevalidate path in process.go to find the right upstreams.
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
	// 60 s is safe: CacheGet already rejects expired entries on read; the
	// sweeper only affects memory, not query correctness.
	// Entries in the stale window (expiration < now < staleUntil) are kept
	// alive intentionally so backgroundRevalidate can serve them.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			for i := range shards {
				shards[i].Lock()
				for k, v := range shards[i].items {
					// Delete only after the full stale window has passed.
					// When StaleTTL=0, staleUntil==expiration — same behaviour as before.
					if now.After(v.staleUntil) {
						delete(shards[i].items, k)
					}
				}
				shards[i].Unlock()
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
//   isStale=false — fresh entry; TTLs reflect remaining lifetime normally.
//   isStale=true  — entry is past its TTL but inside the stale window.
//                   TTLs are set to 0 (RFC 8767 §4) so clients know the answer
//                   may be refreshed soon. ProcessDNS will fire a background
//                   revalidation after writing the stale response.
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

	// Stale window only active when StaleTTL > 0. Otherwise reject expired entries.
	if isStale && cfg.Cache.StaleTTL <= 0 {
		return nil, false
	}

	// Compute remaining TTL for fresh entries.
	// Stale entries get TTL=0 per RFC 8767 §4 — the answer is valid but the
	// client should expect a fresh record soon.
	var remaining uint32
	if !isStale {
		r := item.expiration.Sub(now).Seconds()
		if r < 1 {
			// Sub-second fresh window — effectively expired; avoid TTL=0 confusion
			// with a deliberate stale response. Treat as miss.
			return nil, false
		}
		remaining = uint32(r)
	}
	// remaining=0 for stale responses — intentional.

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
// Storing a deep copy ensures the caller may mutate msg after CacheSet returns
// without corrupting the cached entry (needed by the in-place transform path).
//
// TTL derivation:
//   Positive (NOERROR with answers):  minimum TTL across all answer RRs.
//   Negative (NXDOMAIN or NODATA):    SOA minimum from authority section;
//                                     falls back to NegativeTTL or MinTTL.
//
// NegativeTTL acts as an independent floor for negative responses when set,
// allowing a shorter cache lifetime for NXDOMAIN without affecting positive TTLs.
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
	// This lets operators write `min_ttl: 60, negative_ttl: 30` to get a
	// shorter cache window for NXDOMAIN without affecting positive records.
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

	// Compute time boundaries.
	now := time.Now()
	expiration := now.Add(time.Duration(ttl) * time.Second)

	// staleUntil extends past expiration by StaleTTL seconds.
	// When StaleTTL=0 (default), staleUntil==expiration — no stale window,
	// behaviour is identical to v1.17.0.
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

