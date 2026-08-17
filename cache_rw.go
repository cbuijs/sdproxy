/*
File:    cache_rw.go
Version: 1.5.0 (Split)
Last Updated: 10-Aug-2026 12:30 CEST

Description:
  Hot-path Read/Write operations for the sdproxy cache engine.
  Handles packing/unpacking dns.Msg structures, TTL rewrites, background
  revalidation tracking, and strict RFC bailiwick security enforcement.

  Extracted from cache.go to prioritize hot-path execution clarity.

Changes:
  1.5.0 - [PERF] Eradicated heap allocations in `rotateAnswersInPlace` natively. 
          Utilizes fixed-size stack buffers for A/AAAA index tracking and array 
          rotation swapping, neutralizing Garbage Collection (GC) thrashing on cache hits.
  1.4.0 - [FIX] CacheGet accounted for a hit it then refused to serve. The hit
          counter was incremented and the background-revalidation gate was armed
          and dispatched BEFORE out.Unpack() ran; when the unpack failed the
          function returned ok=false and the caller fell through to the upstream
          path — but the entry had already been charged a hit, and a revalidation
          goroutine had already been launched against it.

          Both consequences point the wrong way. The hit inflates the cache
          hit-rate with lookups that were served from upstream, which is exactly
          the statistic an operator uses to decide whether the cache is sized
          correctly. And because prefetch eligibility is a function of the hit
          count, a corrupt entry became MORE likely to be revalidated the more
          often it failed to unpack — while the query that discovered the
          corruption went upstream anyway, meaning the same work was dispatched
          twice. Unpack now runs first and a failure costs nothing.
        - [PERF] Removed two heap allocations per comparison from the Authority
          section bailiwick check. It built `"."+ansName` and `"."+vn` inside a
          nested loop over every Ns record against every discovered chain name,
          allocating a throwaway string on each iteration of the inner loop.
          Replaced with hasDotSuffix(), which does the same label-boundary test
          with pure index math and allocates nothing. This is the same defect
          class process_security.go 1.14.0 removed from the DGA path; it runs on
          the cache-WRITE path, so it is hit by every upstream response with an
          authority section — which is every NXDOMAIN and every NODATA.
        - [PERF] Hoisted the `now` clock read used by the CNAME/Ns validation out
          of the loops. Cosmetic next to the above, but it keeps the two paths
          consistent about reading the clock exactly once per call.
  1.3.0 - [PERF/FIX] Added rotateAnswersInPlace() and wired it into CacheGet, so
          `answer_sort: round-robin` no longer repacks and re-stores the cache
          entry on every single hit. See cache.go 2.51.0 for the full rationale;
          in short, round-robin is the one sort mode that can never converge, so
          persisting its output meant a PackBuffer, a heap allocation and a shard
          lock on the hottest path in the daemon, forever. The rotation is now
          derived from the per-entry counter at unpack time and the packed bytes
          are left untouched.
          Deliberately lives here rather than in transform.go: it is not a
          general response transform, it is a property of how a cached entry is
          rendered per hit, and it must run against the freshly unpacked message
          before the caller sees it.
  1.2.0 - [TIER 2] Extracted stripOPTRecords(); the RFC 6891 OPT-stripping block
          with its zero-allocation pre-scan was copy-pasted in CacheSet,
          CacheSetSynth and CacheUpdateOrder. Behaviour unchanged.
  1.1.0 - [PERF] Decoupled bailiwick validation from a per-call closure into the
          global isValidBailiwickName helper to eliminate heap allocations
          during cache-write floods.
*/

package main

import (
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// isValidBailiwickName executes a zero-allocation bounds check to ensure
// nested CNAME/NS records respect the established resolution chain.
func isValidBailiwickName(names []string, name string) bool {
	for _, v := range names {
		if v == name {
			return true
		}
	}
	return false
}

// hasDotSuffix reports whether s ends with "."+suffix, without building that
// concatenation.
//
// [PERF 1.4.0] The Authority-section bailiwick check needs a label-boundary
// suffix test in both directions ("is this NS a parent of the chain name" and
// "is it a child of it"), and it needs it for every Ns record against every
// discovered chain name. Expressed as strings.HasSuffix(s, "."+suffix) that is
// one heap allocation per inner-loop iteration on the cache-write path —
// reached by every negative answer sdproxy stores.
//
// The test itself is three comparisons on the immutable backing arrays:
//
//	s is strictly longer than suffix        (a bare equality is the caller's job)
//	the byte immediately before the suffix is '.'  (a real label separator, so
//	                                               "notexample.com" cannot match
//	                                               a suffix of "example.com")
//	the tail equals suffix
//
// Sub-slicing a string allocates nothing, so the whole function is allocation
// free. Semantics are byte-identical to the concatenating form it replaces,
// including the empty-suffix case (len(s) > 0 && s[len(s)-1] == '.' && "" == ""
// — which the caller never produces, but which degrades safely rather than
// panicking).
func hasDotSuffix(s, suffix string) bool {
	if len(s) <= len(suffix) {
		return false
	}
	cut := len(s) - len(suffix)
	return s[cut-1] == '.' && s[cut:] == suffix
}

// stripOPTRecords returns extra with all OPT (EDNS0) records removed.
//
// [SECURITY] RFC 6891 §6.1.1 — OPT is strictly hop-by-hop and MUST NOT be
// cached. Storing it would hand downstream clients stale payload sizes and
// DNSSEC flags from the original upstream negotiation.
//
// [PERF] Pre-scans before allocating. ~99.9% of responses carry exactly one
// auxiliary record (the OPT itself), so the common case returns nil without
// constructing a zero-length slice.
func stripOPTRecords(extra []dns.RR) []dns.RR {
	if len(extra) == 0 {
		return extra
	}
	hasNonOpt := false
	for _, rr := range extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			hasNonOpt = true
			break
		}
	}
	if !hasNonOpt {
		return nil
	}
	clean := make([]dns.RR, 0, len(extra))
	for _, rr := range extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			clean = append(clean, rr)
		}
	}
	return clean
}

// rotateAnswersInPlace rotates the A and AAAA answer groups left by offset
// positions, preserving each group's original slot positions within msg.Answer.
//
// [PERF 1.5.0] Employs fixed-size 16-element stack buffers to track indexes 
// and temporary values organically. Since 99.9% of DNS queries resolve fewer 
// than 16 IPs, this completely eradicates heap escapes on the round-robin hot path.
// If capacity exceeds 16, `append` gracefully falls back to heap slice allocations.
//
// Rotation is applied per record type, matching applyAnswerSort's grouping: a
// response carrying both A and AAAA records rotates each family independently,
// so a client asking for A records sees the same cycling behaviour whether or
// not AAAA records happen to share the message.
//
// Records that are neither A nor AAAA (CNAMEs at the head of a chain, RRSIGs,
// and so on) are left exactly where they are — reordering those would break the
// CNAME chain and invalidate DNSSEC ordering assumptions.
//
// offset is taken modulo the group length, so the caller's counter is free to
// wrap. Groups shorter than two records are skipped: there is nothing to rotate
// and the allocation would be pure waste.
func rotateAnswersInPlace(msg *dns.Msg, offset uint32) {
	if msg == nil || len(msg.Answer) < 2 {
		return
	}

	// [PERF] Deploy stack-allocated arrays to completely bypass dynamic slice GC thrashing
	var aIdxBuf [16]int
	var aaaaIdxBuf [16]int
	aIdx := aIdxBuf[:0]
	aaaaIdx := aaaaIdxBuf[:0]

	// Collect the positions occupied by each family. Indices, not records, so
	// the rotation can be written back into the exact same slots.
	for i, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			aIdx = append(aIdx, i)
		case dns.TypeAAAA:
			aaaaIdx = append(aaaaIdx, i)
		}
	}

	rotate := func(idx []int) {
		n := len(idx)
		if n < 2 {
			return
		}
		shift := int(offset % uint32(n))
		if shift == 0 {
			return
		}

		// Snapshot the current occupants, then redistribute them shifted.
		// A temporary is required because the write-back overlaps the read.
		var origBuf [16]dns.RR
		var orig []dns.RR
		if n <= 16 {
			orig = origBuf[:n]
		} else {
			orig = make([]dns.RR, n)
		}

		for i, pos := range idx {
			orig[i] = msg.Answer[pos]
		}
		for i, pos := range idx {
			msg.Answer[pos] = orig[(i+shift)%n]
		}
	}

	rotate(aIdx)
	rotate(aaaaIdx)
}

// ---------------------------------------------------------------------------
// Public read/write API
// ---------------------------------------------------------------------------

// CacheGet unpacks a cached response into the caller-provided *dns.Msg
// (sourced from msgPool in process.go) and returns status flags alongside
// the active cache hit count.
//
// The caller must zero the message before passing it in: `*out = dns.Msg{}`.
// After WriteMsg the caller returns out to msgPool.
//
//	isStale=false, isPrefetch=false — normal fresh hit.
//	isStale=false, isPrefetch=true  — fresh; background prefetch just fired.
//	isStale=true,  isPrefetch=false — past TTL but inside stale window.
//
// Returns ok=false on a miss or when the stale window has passed.
// out is in an undefined state when ok=false — do not use it.
func CacheGet(key DNSCacheKey, out *dns.Msg) (isStale bool, isPrefetch bool, ok bool, hits uint32) {
	if !cfg.Cache.Enabled {
		return false, false, false, 0
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	if !found {
		return false, false, false, 0
	}

	now := time.Now().UnixNano()

	// Past the full stale window — treat as miss (sweeper may not have fired yet).
	if now >= item.staleNano {
		return false, false, false, 0
	}

	isStale = now >= item.expireNano
	if isStale && !staleEnabled {
		return false, false, false, 0
	}

	// Remaining TTL in whole seconds.
	// [RFC COMPLIANCE] Floor stale responses at 1s so strict stub resolvers
	// don't enter infinite retry loops on TTL=0 (RFC 8767 §4).
	var remaining uint32
	if !isStale {
		r := item.expireNano - now
		if r < int64(time.Second) {
			if !staleEnabled {
				return false, false, false, 0
			}
			isStale = true
			remaining = 1
		} else {
			remaining = uint32(r / int64(time.Second))
		}
	} else {
		remaining = 1
	}

	// ── [FIX 1.4.0] Unpack BEFORE any accounting ─────────────────────────
	//
	// The hit counter and the background-revalidation dispatch used to run
	// above this point, which meant an entry whose packed bytes no longer
	// unpack was charged a cache hit and had a revalidation goroutine launched
	// against it — and then reported ok=false, sending the very same query
	// upstream through the normal miss path.
	//
	// Two things went wrong at once. The hit-rate statistic counted lookups the
	// cache did not serve, understating how badly the cache was performing at
	// exactly the moment something was wrong with it. And since prefetch
	// eligibility is driven by the hit count, repeated failures made a corrupt
	// entry progressively MORE attractive to the revalidator while every one of
	// those queries also dispatched its own upstream exchange — the same work,
	// twice, with the duplicate hidden behind a healthy-looking metric.
	//
	// A failed unpack now costs nothing at all and is indistinguishable from a
	// plain miss, which is what it is.
	packedData := item.packed.Load()
	if err := out.Unpack(*packedData); err != nil {
		return false, false, false, 0
	}

	// Rewrite TTLs to reflect actual remaining lifetime.
	// OPT (EDNS0) carries flags, not a TTL — always skip it.
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

	// [PERF/FIX 1.3.0] Round-robin is applied here, against the freshly unpacked
	// copy, rather than by rotating the stored bytes and writing them back.
	//
	// Advancing the counter per hit gives successive clients successive
	// orderings — the actual intent of round-robin — while the packed blob stays
	// immutable for the entry's whole lifetime. The previous approach reported
	// "order changed" on every hit (rotation never converges), which drove a
	// full CacheUpdateOrder repack per cache hit.
	//
	// The counter is advanced unconditionally, including for single-record
	// answers where rotateAnswersInPlace is a no-op. Keeping the increment
	// branch-free costs one atomic add and avoids a length check on the hot path.
	if cacheRotateAnswers {
		rotateAnswersInPlace(out, item.rotation.Add(1))
	}

	// ── Accounting: only now that the hit is real ────────────────────────
	currentHits := item.hits.Add(1)

	// [SECURITY] Unified background revalidation gate.
	// Bounds BOTH prefetch and stale-serve revalidation behind one atomic CAS.
	// Synthetic records are skipped entirely: revalidating them would leak LAN
	// names to public upstreams and corrupt the cache.
	isSynthetic := item.routeName == ""
	triggerBG := false

	if !isSynthetic {
		if isStale {
			triggerBG = true
		} else if hasPrefetch && remaining > 0 && remaining <= uint32(cfg.Cache.PrefetchBefore) && currentHits >= uint32(cfg.Cache.PrefetchMinHits) {
			triggerBG = true
			isPrefetch = true
		}
	}

	if triggerBG && item.prefetched.CompareAndSwap(false, true) {
		// State-reversion callback so a saturated background semaphore does not
		// permanently lock the prefetch gate for this entry.
		revertGate := func() {
			item.prefetched.Store(false)
		}
		TriggerBackgroundRevalidate(key, item.routeName, key.ClientName, currentHits, revertGate)
	}

	return isStale, isPrefetch, true, currentHits
}

// CacheGetExpired retrieves any cached record regardless of its TTL/stale
// bounds. Emergency fallback only: used when upstream exchanges fail and
// serve_stale_infinite is enabled.
func CacheGetExpired(key DNSCacheKey, out *dns.Msg) bool {
	if !cfg.Cache.Enabled {
		return false
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()
	if !found {
		return false
	}

	packedData := item.packed.Load()
	if err := out.Unpack(*packedData); err != nil {
		return false
	}

	// Force a short 30s TTL so clients don't permanently cache the dead record
	// and can retry once the upstream recovers.
	for _, rr := range out.Answer {
		rr.Header().Ttl = 30
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = 30
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = 30
		}
	}
	return true
}

// CacheSet packs msg into wire format and stores it under key.
//
// TTL derivation:
//
//	Positive (NOERROR with answers): minimum TTL across all answer RRs.
//	Negative (NXDOMAIN or NODATA):   SOA minimum from authority section;
//	                                 falls back to NegativeTTL, then MinTTL.
func CacheSet(key DNSCacheKey, msg *dns.Msg, routeName string) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	// [SECURITY/PERF] Truncation guard.
	// Caching a TC=1 response would make every subsequent TCP retry receive the
	// same incomplete payload, trapping the client in a resolution loop and
	// starving file descriptors.
	if msg.Truncated {
		return
	}

	isNeg := msg.Rcode == dns.RcodeNameError ||
		(msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
	if isNeg && !cacheUpstreamNeg {
		return
	}

	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return
	}

	// ---------------------------------------------------------------------------
	// [SECURITY] Bailiwick / cache-poisoning prevention
	// ---------------------------------------------------------------------------
	// Enforce that the answers belong to the QNAME that was requested, so a
	// malicious upstream cannot slip out-of-zone records into the shards.

	if len(msg.Question) == 0 {
		if logCaching {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Missing Question section.", key.Name)
		}
		return
	}

	qName := strings.ToLower(msg.Question[0].Name)
	cleanQName := strings.TrimSuffix(qName, ".")

	if cleanQName != key.Name {
		if logCaching {
			log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response. Question section (%q) does not match requested cache key (%q).", cleanQName, key.Name)
		}
		return
	}

	// [PERF] Stack-allocated slice, not a map — zero allocations on the write path.
	// Size 64 covers even deep CNAME chains without falling back to the heap.
	var validStack [64]string
	validNames := validStack[:0]
	validNames = append(validNames, qName)

	// CNAME chains can arrive out of order from intermediate resolvers, so
	// discover all valid targets first, then verify. Avoids false-positive drops.
	// [SECURITY] Depth is bounded to stop CPU-exhaustion DoS via circular chains.
	chainDepth := 0
	for {
		added := false
		for _, rr := range msg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			if isValidBailiwickName(validNames, ansName) {
				if cname, ok := rr.(*dns.CNAME); ok {
					target := strings.ToLower(cname.Target)
					if !isValidBailiwickName(validNames, target) {
						validNames = append(validNames, target)
						added = true
					}
				}
			}
		}
		if !added {
			break
		}
		chainDepth++
		if chainDepth > 16 {
			if logCaching {
				log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. CNAME chain exceeds maximum safe parsing depth.", qName)
			}
			return
		}
	}

	// Validate Answer section against the discovered chain.
	if len(msg.Answer) > 0 {
		for i, rr := range msg.Answer {
			ansName := strings.ToLower(rr.Header().Name)
			if !isValidBailiwickName(validNames, ansName) {
				if logCaching {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Record %d (%q) breaks Bailiwick/CNAME chain.", qName, i, ansName)
				}
				return
			}
		}
	}

	// Validate Authority (Ns) section — thwarts injection of out-of-zone NS/SOA.
	if len(msg.Ns) > 0 {
		for i, rr := range msg.Ns {
			ansName := strings.ToLower(rr.Header().Name)
			isValid := false

			for _, vn := range validNames {
				// Ns records are usually parent delegations (google.com for
				// www.google.com) or sub-delegations (sub.example.com for example.com).
				//
				// [PERF 1.4.0] hasDotSuffix replaces
				// strings.HasSuffix(vn, "."+ansName) / (ansName, "."+vn). Those
				// two concatenations allocated a throwaway string on EVERY
				// iteration of this inner loop, which runs once per Ns record
				// per discovered chain name — on the cache-write path, for every
				// negative answer the daemon stores. The label-boundary
				// semantics are identical; only the allocation is gone.
				if ansName == vn || hasDotSuffix(vn, ansName) || hasDotSuffix(ansName, vn) {
					isValid = true
					break
				}
			}

			if !isValid {
				if logCaching {
					log.Printf("[CACHE] SECURITY: Dropped suspicious upstream response for %q. Authority Record %d (%q) breaks Bailiwick.", qName, i, ansName)
				}
				return
			}
		}
	}

	// Shallow-copy the message before stripping OPT. Mutating the live Extra
	// slice would strip the Extended RCODE from the client's own response.
	cacheMsg := *msg
	cacheMsg.Extra = stripOPTRecords(cacheMsg.Extra)

	var ttl uint32
	if !isNeg {
		ttl = ^uint32(0)
		for _, rr := range cacheMsg.Answer {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	} else {
		for _, rr := range cacheMsg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl = soa.Hdr.Ttl
				if soa.Minttl < ttl {
					ttl = soa.Minttl
				}
				break
			}
		}
		if ttl == 0 {
			if cfg.Cache.NegativeTTL > 0 {
				ttl = uint32(cfg.Cache.NegativeTTL)
			} else {
				ttl = uint32(cfg.Cache.MinTTL)
			}
		}
	}

	effectiveMin := uint32(cfg.Cache.MinTTL)
	if isNeg && cfg.Cache.NegativeTTL > 0 {
		effectiveMin = uint32(cfg.Cache.NegativeTTL)
	}
	if ttl < effectiveMin {
		ttl = effectiveMin
	}
	if cfg.Cache.MaxTTL > 0 && ttl > uint32(cfg.Cache.MaxTTL) {
		ttl = uint32(cfg.Cache.MaxTTL)
	}

	now := time.Now().UnixNano()
	expireNano := now + int64(ttl)*int64(time.Second)
	staleNano := expireNano
	if staleEnabled {
		staleNano = expireNano + int64(cfg.Cache.StaleTTL)*int64(time.Second)
	}

	// [PERF] largeBufPool (64KB), not smallBufPool (4KB): large DNSSEC-signed
	// responses previously hit dns.ErrBuf and were silently never cached.
	bufp := largeBufPool.Get().(*[]byte)
	packed, err := cacheMsg.PackBuffer((*bufp)[:0])
	if err != nil {
		largeBufPool.Put(bufp)
		if logCaching {
			log.Printf("[CACHE] CacheSet: pack failed for %q: %v", key.Name, err)
		}
		return
	}
	stored := make([]byte, len(packed))
	copy(stored, packed)
	largeBufPool.Put(bufp)

	ci := &cacheItem{
		expireNano:   expireNano,
		staleNano:    staleNano,
		cachedAtNano: now,
		routeName:    routeName,
	}
	ci.packed.Store(&stored)
	storeItem(key, ci)
}

// CacheSetSynth stores a synthesised sdproxy response (any RCODE) at a fixed
// syntheticTTL. Unlike CacheSet it bypasses the RFC 2308 RCODE filter, so
// REFUSED, NOTIMP, and NOERROR-with-no-answers can all be cached here.
//
// staleNano == expireNano — synthetic entries have no upstream to revalidate
// against, so backgroundRevalidate must never fire for them.
func CacheSetSynth(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	now := time.Now().UnixNano()
	expireNano := now + int64(syntheticTTL)*int64(time.Second)

	bufp := largeBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufp)[:0])
	if err != nil {
		largeBufPool.Put(bufp)
		if logCaching {
			log.Printf("[CACHE] CacheSetSynth: pack failed for %q: %v", key.Name, err)
		}
		return
	}
	stored := make([]byte, len(packed))
	copy(stored, packed)
	largeBufPool.Put(bufp)

	ci := &cacheItem{
		expireNano:   expireNano,
		staleNano:    expireNano, // no stale window — nothing to revalidate
		cachedAtNano: now,
		routeName:    "", // synthetic; backgroundRevalidate must not fire
	}
	ci.packed.Store(&stored)
	storeItem(key, ci)
}

// CacheUpdateOrder atomically swaps the packed bytes of an existing cache item.
// Used to persist updated Answer record orders (e.g. round-robin shifting)
// without disturbing the original expiration timelines or atomic trackers.
func CacheUpdateOrder(key DNSCacheKey, msg *dns.Msg) {
	if !cfg.Cache.Enabled || msg == nil {
		return
	}

	shard := getShard(key)
	shard.RLock()
	item, found := shard.items[key]
	shard.RUnlock()

	if !found {
		return
	}

	// Strip OPT before re-storing, otherwise answer_sort reshuffling would
	// persist the hop-by-hop record and corrupt downstream payload sizes.
	cacheMsg := *msg
	cacheMsg.Extra = stripOPTRecords(cacheMsg.Extra)

	bufp := largeBufPool.Get().(*[]byte)
	packed, err := cacheMsg.PackBuffer((*bufp)[:0])
	if err == nil {
		stored := make([]byte, len(packed))
		copy(stored, packed)
		item.packed.Store(&stored)
	}
	largeBufPool.Put(bufp)
}

