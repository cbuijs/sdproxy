/*
File:    ratelimit.go
Version: 1.18.0
Last Updated: 10-Aug-2026 12:30 CEST
Description:
  High-performance, lock-free (sharded) Token Bucket Rate Limiter and Penalty Box.
  Designed specifically to harden sdproxy when exposed to the public internet
  as an Open Resolver. Defends against DNS amplification, reflection, and
  volumetric DDoS attacks.

  - Groups queries by client IP address or subnet prefix (IPv4/IPv6 masks).
  - Pre-allocated 256 shards to completely eliminate mutex contention across
    highly parallel UDP/TCP/QUIC workers.
  - Background sweeper automatically reclaims memory from stale IPs.
  - Hard cap eviction logic prevents OOM from malicious spoofed-IP floods.
  - Integrated Penalty Box (blackhole) isolates severely abusive clients, silencing logs
    and saving significant CPU/IO bandwidth automatically.

Changes:
  1.18.0 - [PERF] Eradicated `sync.Map` boxing allocations on the hot path natively. 
           Replaced `fastPenaltyBox` with a dedicated 256-shard `sync.RWMutex` array. 
           Prevents `netip.Addr` struct-to-interface conversions from triggering 
           24-byte heap allocations per DNS query, neutralizing GC bottlenecks during floods.
  1.17.0 - [SECURITY/PERF] Replaced the shard eviction policy. When a shard hit
           its ceiling the code deleted the FIRST key Go's randomised map
           iteration happened to yield, which made an accumulated strike record
           exactly as likely to be discarded as an idle, well-behaved entry.

           That is a usable laundering primitive: an attacker who is
           accumulating strikes toward a ban can flood the same shard with
           spoofed sources and, with probability proportional to how much of the
           shard they fill, evict their own partially-punished bucket. The next
           query then re-creates it with a full burst and zero strikes, so the
           strike threshold is never reached and the Penalty Box never engages.
           Reaching a specific shard is not hard — getRLShard is seeded, but an
           attacker can simply flood broadly and let the birthday bound do the
           work.

           Eviction now samples up to rlEvictSampleSize entries and prefers the
           least valuable victim: an unpunished bucket over a striking one, and
           within that class the one idle longest. A bounded sample keeps the
           cost O(32) under the shard lock rather than O(shard size), which
           matters because this runs during exactly the floods it defends
           against. Punished buckets are only evicted when the whole sample is
           punished — space must still be freed — and even then the oldest is
           chosen.
         - [CLEANUP] Extracted admitToFastPenaltyBox(). AllowClient and
           PenalizeClient carried byte-identical twenty-line copies of the
           lock-free penalty-box insertion, including its capacity bound and its
           LoadOrStore race handling. Two copies of a concurrency-sensitive
           refcount is one copy too many; the accounting only stays correct if
           every future edit lands on both.
  1.16.0 - [SECURITY/FIX] AllowClient now fails CLOSED when handed an
           unidentifiable source address (audit item S-B). It previously
           returned "allowed" for any addr whose netip.Addr was invalid, which
           is the same fail-open shape that process_security.go 1.15.0 closed
           one layer above — and which that release's comments went on to
           describe, incorrectly, as a defence-in-depth guard. A token bucket is
           keyed on an identity; with no parseable address there is no key, no
           bucket and therefore no bound, so "allow" was never a safe default on
           a publicly reachable resolver. Unreachable in the intact pipeline
           (step 0.0 sheds these first whenever an admission control is enabled),
           which is exactly why it needed to hold the correct line.
  1.15.0 - [PERF] Eradicated massive string-allocation overheads natively on the 
           hot-path. Switched the map hashes, Fast-Path arrays, and bounding 
           functions to strictly operate on zero-allocation `netip.Addr` structures. 
           Eliminates millions of redundant string conversions per second.
  1.14.0 - [SECURITY/FIX] Eradicated a persistent zombie goroutine organically.
           The periodic sweeper now actively monitors the global `shutdownCh` to 
           surrender memory safely during OS-level termination boundaries natively.
  1.13.1 - [PERF] Optimized groupIPFast to return pre-normalized, unmapped ipStr directly
           when prefix limits are set to 32 (IPv4) or 128 (IPv6), avoiding redundant 
           netip.Addr.String() allocations on the query hot path.
*/

package main

import (
	"hash/maphash"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// rlShardCount determines the number of independent lock-shards.
// 256 effectively eliminates contention for normal/high multi-core traffic.
const rlShardCount = 256

// rlEvictSampleSize bounds the eviction scan.
//
// [SECURITY/PERF 1.17.0] Eviction runs while a shard is full, which on a public
// resolver means it runs during a source-address flood — the worst possible
// moment to hold a shard lock for a full linear scan. Sampling instead makes the
// cost a fixed O(32) regardless of rlMaxPerShard.
//
// 32 is chosen against the actual adversary rather than for statistical
// elegance. The property that matters is not "evict the globally oldest entry",
// it is "do not evict a bucket that is accumulating strikes while an idle one is
// available". With a sample of 32 drawn from Go's randomised map iteration, the
// probability that every sampled entry is punished — the only case in which a
// punished bucket is discarded — is negligible unless the shard is genuinely
// almost entirely made up of offenders, at which point evicting one of them is
// the correct outcome anyway.
const rlEvictSampleSize = 32

// rlBucket represents a single Token Bucket state for one Client IP / Subnet.
type rlBucket struct {
	tokens      float64
	lastRefill  int64 // unix nanoseconds
	lastLog     int64 // unix nanoseconds (used to debounce limit-hit logs)
	strikes     int   // consecutive rate limit violations
	bannedUntil int64 // unix nanoseconds (Penalty Box status)
}

// rlShard holds a chunk of the buckets, protected by its own Mutex.
type rlShard struct {
	sync.Mutex
	buckets map[netip.Addr]*rlBucket
}

// fastBanEntry represents a lock-free cache item for actively blackholed clients.
// Enforced via atomic.Int64 structures to ensure concurrent strike extensions 
// execute securely without map-level TOCTOU (Time-Of-Check to Time-Of-Use) regressions.
type fastBanEntry struct {
	expires atomic.Int64
	lastLog atomic.Int64
}

// fastBanShard isolates locked boundaries organically to bypass heavy boxing
// allocations caused by generalized sync.Map deployments.
type fastBanShard struct {
	sync.RWMutex
	bans map[netip.Addr]*fastBanEntry
}

var (
	rlShards       [rlShardCount]*rlShard
	fastBanShards  [rlShardCount]*fastBanShard

	// Configured parameters
	rlQPS              float64
	rlBurst            float64
	rlV4Bits           int
	rlV6Bits           int
	rlMaxPerShard      int
	
	// Exemptions (Bypass list)
	rlExempt []netip.Prefix
	
	// Penalty Box Config
	rlPenaltyEnabled   bool
	rlStrikeThreshold  int
	rlBanDurationNanos int64
	
	// fastPenaltyBoxCount strictly limits the unbounded growth of the fast-path map.
	fastPenaltyBoxCount atomic.Int32

	// rlHashSeed provides cryptographic randomization for the rate limit shard distribution.
	rlHashSeed maphash.Seed
)

// InitRateLimiter wires up the rate limiting subsystem based on the config.
func InitRateLimiter() {
	if !cfg.Server.RateLimit.Enabled {
		return
	}

	// Initialize the randomized seed for HashDoS protection
	rlHashSeed = maphash.MakeSeed()

	rlQPS = cfg.Server.RateLimit.QPS
	rlBurst = cfg.Server.RateLimit.Burst
	if rlQPS <= 0 {
		rlQPS = 20
	}
	if rlBurst <= 0 {
		rlBurst = 100
	}

	rlV4Bits = cfg.Server.RateLimit.IPv4PrefixLength
	rlV6Bits = cfg.Server.RateLimit.IPv6PrefixLength
	if rlV4Bits <= 0 || rlV4Bits > 32 {
		rlV4Bits = 32
	}
	if rlV6Bits <= 0 || rlV6Bits > 128 {
		rlV6Bits = 128
	}

	maxIPs := cfg.Server.RateLimit.MaxTrackedIPs
	if maxIPs <= 0 {
		maxIPs = 100000 // Default: safely bound to ~100k distinct tracked IPs
	}
	cfg.Server.RateLimit.MaxTrackedIPs = maxIPs
	
	rlMaxPerShard = maxIPs / rlShardCount
	if rlMaxPerShard < 1 {
		rlMaxPerShard = 1
	}

	// Parse Exemption List
	rlExempt = parseACL(cfg.Server.RateLimit.Exempt)

	// Setup Penalty Box Configs
	rlPenaltyEnabled = cfg.Server.RateLimit.PenaltyBox.Enabled
	rlStrikeThreshold = cfg.Server.RateLimit.PenaltyBox.StrikeThreshold
	if rlStrikeThreshold <= 0 {
		rlStrikeThreshold = 100 // Reasonable default threshold
	}
	
	banMins := cfg.Server.RateLimit.PenaltyBox.BanDurationMin
	if banMins <= 0 {
		banMins = 15 // Default 15 min ban
	}
	rlBanDurationNanos = int64(banMins) * 60 * 1e9

	for i := 0; i < rlShardCount; i++ {
		rlShards[i] = &rlShard{
			buckets: make(map[netip.Addr]*rlBucket),
		}
		fastBanShards[i] = &fastBanShard{
			bans: make(map[netip.Addr]*fastBanEntry),
		}
	}

	log.Printf("[RATELIMIT] Active: %.1f QPS (Burst: %.0f) | Grouping: IPv4 /%d, IPv6 /%d | Max Tracked IPs: %d",
		rlQPS, rlBurst, rlV4Bits, rlV6Bits, maxIPs)
		
	if rlPenaltyEnabled {
		log.Printf("[RATELIMIT] Penalty Box Enabled: Blackholing offenders for %d mins after %d strikes.", banMins, rlStrikeThreshold)
	}
	if len(rlExempt) > 0 {
		log.Printf("[RATELIMIT] Exemption List: %d IP/Subnet rule(s) configured for unlimited access.", len(rlExempt))
	}

	// Sweeper prevents OOM by clearing stale IPs
	go runRateLimitSweeper()
}

// isExempt verifies if a parsed netip.Addr belongs to the RateLimit exempt list.
// Evaluated natively to eliminate redundant string parsing.
func isExempt(addr netip.Addr) bool {
	if len(rlExempt) == 0 || !addr.IsValid() {
		return false
	}
	for _, prefix := range rlExempt {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// getRLShard hashes a netip.Addr key to one of the 256 shards using maphash natively.
func getRLShard(key netip.Addr) *rlShard {
	b := key.As16()
	h := maphash.Bytes(rlHashSeed, b[:])
	return rlShards[h&(rlShardCount-1)]
}

// getFastBanShard securely extracts the zero-allocation RWMutex partition naturally.
func getFastBanShard(key netip.Addr) *fastBanShard {
	b := key.As16()
	h := maphash.Bytes(rlHashSeed, b[:])
	return fastBanShards[h&(rlShardCount-1)]
}

// groupIPFast masks the incoming IP address according to configured prefix lengths.
// Operates exclusively on and returns netip.Addr structures natively to preserve zero-allocation pipelines.
func groupIPFast(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}

	if addr.Is4() {
		if rlV4Bits == 32 {
			return addr
		}
		prefix, _ := addr.Prefix(rlV4Bits)
		return prefix.Masked().Addr()
	} else if addr.Is6() {
		if rlV6Bits == 128 {
			return addr
		}
		prefix, _ := addr.Prefix(rlV6Bits)
		return prefix.Masked().Addr()
	}

	return addr
}

// evictOneLocked frees exactly one slot in a full shard.
//
// The shard mutex MUST already be held.
//
// [SECURITY/PERF 1.17.0] This replaces `for k := range shard.buckets { delete(...); break }`
// — "delete whatever Go's randomised iteration yields first".
//
// That was not merely arbitrary, it was exploitable. A bucket carrying
// accumulated strikes (or an active but map-resident ban) was exactly as likely
// to be chosen as an idle bucket belonging to a well-behaved client. An
// attacker climbing toward the strike threshold could therefore flood the shard
// with spoofed sources and, with probability proportional to their share of it,
// evict their OWN partially-punished record. The next query re-creates the
// bucket from scratch with a full burst and zero strikes, so the threshold is
// never reached, the Penalty Box never engages, and the fast-path blackhole
// that exists to make floods cheap never gets to do its job.
//
// The policy is therefore "evict the least valuable entry we can see":
//
//	Tier 1 (preferred) — unpunished: no strikes AND no live ban. Among these,
//	                     the one whose bucket has been idle longest, since that
//	                     is the entry the sweeper would have reclaimed next
//	                     anyway.
//	Tier 2 (fallback)  — everything else, again oldest-first. Only reached when
//	                     the entire sample is punished, in which case the shard
//	                     genuinely is full of offenders and something has to go.
//
// The scan is bounded to rlEvictSampleSize because this executes under the
// shard lock during precisely the floods it defends against; a full linear scan
// of rlMaxPerShard entries per new source would hand the attacker a second,
// cheaper denial vector than the one being mitigated.
func evictOneLocked(shard *rlShard, now int64) {
	var (
		bestKey      netip.Addr
		bestRefill   int64
		bestFound    bool
		bestUnpunish bool

		scanned int
	)

	for k, b := range shard.buckets {
		unpunished := b.strikes == 0 && b.bannedUntil <= now

		// A candidate wins if it is in a strictly better tier, or in the same
		// tier and idle longer.
		better := !bestFound ||
			(unpunished && !bestUnpunish) ||
			(unpunished == bestUnpunish && b.lastRefill < bestRefill)

		if better {
			bestKey, bestRefill, bestUnpunish, bestFound = k, b.lastRefill, unpunished, true
		}

		scanned++
		if scanned >= rlEvictSampleSize {
			break
		}
	}

	if bestFound {
		delete(shard.buckets, bestKey)
	}
}

// admitToFastPenaltyBox publishes (or extends) a ban in the lock-free fast path.
//
// [CLEANUP 1.17.0] AllowClient and PenalizeClient held identical inline copies
// of this, refcount handling included. The capacity accounting is only correct
// if the LoadOrStore result is inspected on every insertion path, which is
// exactly the kind of invariant that survives a copy-paste but not the next
// edit to one of the copies.
//
// Capacity is bounded by MaxTrackedIPs. An offender who cannot be admitted
// because the map is full is NOT unpunished: bucket.bannedUntil has already
// been set by the caller, so the shard-locked slow path in AllowClient still
// blackholes them. They merely lose the lock-free shortcut.
func admitToFastPenaltyBox(key netip.Addr, banUntil, now int64) {
	fShard := getFastBanShard(key)
	fShard.RLock()
	existing, ok := fShard.bans[key]
	fShard.RUnlock()

	// Rapid atomic horizon extension for known offenders
	if ok {
		existing.expires.Store(banUntil)
		return
	}

	// Strictly limit the unbounded growth of the fast-path arrays organically
	if fastPenaltyBoxCount.Load() >= int32(cfg.Server.RateLimit.MaxTrackedIPs) {
		return
	}

	fShard.Lock()
	if existing, stillOk := fShard.bans[key]; stillOk {
		existing.expires.Store(banUntil)
	} else {
		fastEntry := &fastBanEntry{}
		fastEntry.expires.Store(banUntil)
		fastEntry.lastLog.Store(now)
		fShard.bans[key] = fastEntry
		fastPenaltyBoxCount.Add(1)
	}
	fShard.Unlock()
}

// AllowClient checks whether the client IP has enough tokens to execute a query.
// It also evaluates the Penalty Box (blackhole) status.
// Returns two booleans: `allowed` indicating if the query can proceed, and 
// `isBanned` indicating if the client is currently in the Penalty Box.
func AllowClient(_ string, addr netip.Addr) (allowed bool, isBanned bool) {
	// ── [SECURITY/FIX 1.16.0] Fail closed on an unidentifiable source (S-B) ──
	//
	// This branch previously returned (true, false) — "allow" — with the
	// rationale that an internal query lacking a physical IP should not be
	// policed. process_security.go 1.15.0 then went on to describe this very
	// check as a defence-in-depth guard for any future caller that bypasses the
	// pipeline, which it was not: it was the exact fail-open behaviour that
	// 1.15.0 had just spent an entire release closing one layer higher up.
	//
	// The whole point of a token bucket is that it is keyed on an identity.
	// An address that cannot be parsed produces no key, so there is no bucket
	// to debit and no bound to enforce. On a publicly reachable resolver the
	// only safe reading of "I cannot identify this caller" is denial, never
	// exemption — otherwise anything that can strip or mangle the source
	// address (a misconfigured proxy, a tunnel, a future transport whose
	// net.Addr we do not yet decode) becomes a complete rate-limit bypass.
	//
	// Reachability note: with the pipeline intact this is unreachable, because
	// process_security.go step 0.0 already sheds unparseable sources whenever
	// hasDNSACL || hasRateLimit. That is precisely why it must be correct here
	// — an unreachable guard is only worth having if it holds the right line
	// the day something starts reaching it.
	//
	// isBanned is reported as false rather than true so the caller still emits
	// its "DROPPED (Rate Limit Exceeded)" line: this is a diagnosable
	// configuration fault, not a known abuser being silently blackholed, and
	// suppressing the log would hide the very misconfiguration that caused it.
	if !addr.IsValid() {
		return false, false
	}

	key := groupIPFast(addr)

	// -----------------------------------------------------------------------
	// 1. LOCK-FREE FAST-PATH (Penalty Box)
	// -----------------------------------------------------------------------
	// Bypasses Mutex locking and exemption loops entirely for actively 
	// blackholed IPs. Extremely critical for maintaining node stability during 
	// volumetric spoofed-IP or brute-force DDoS attacks.
	fShard := getFastBanShard(key)
	fShard.RLock()
	banEntry, fastOk := fShard.bans[key]
	fShard.RUnlock()

	if fastOk {
		nowNanos := time.Now().UnixNano()
		if nowNanos < banEntry.expires.Load() {
			// Debounce the silent-drop log using atomic operations to protect I/O capacity
			last := banEntry.lastLog.Load()
			if nowNanos-last > int64(10*time.Second) {
				if banEntry.lastLog.CompareAndSwap(last, nowNanos) {
					log.Printf("[RATELIMIT] SECURITY: Silently dropping traffic from %s (IP is blackholed/in Penalty Box - Fast Path)", key.String())
				}
			}
			return false, true
		}
		// Ban has naturally expired, remove from fast-path and fall through.
		fShard.Lock()
		if _, loaded := fShard.bans[key]; loaded {
			delete(fShard.bans, key)
			fastPenaltyBoxCount.Add(-1) // Free capacity immediately
		}
		fShard.Unlock()
	}

	// -----------------------------------------------------------------------
	// 2. EXEMPTIONS
	// -----------------------------------------------------------------------
	// Exemptions natively bypass the shard locks and math. Checked strictly
	// AFTER the fast penalty box drop to prevent DDoS abuse against the prefix loop.
	if isExempt(addr) {
		return true, false
	}

	shard := getRLShard(key)
	now := time.Now().UnixNano()

	shard.Lock()
	defer shard.Unlock()

	bucket, exists := shard.buckets[key]
	if !exists {
		// Hard memory limit check: free a slot if the shard is full.
		// Protects strictly against OOM from spoofed-source DNS floods.
		//
		// [SECURITY/FIX 1.17.0] evictOneLocked replaces "delete the first key
		// the map iterator yields", which allowed an offender to launder away
		// their own accumulated strikes by flooding the shard. See the function
		// comment for the full mechanism.
		if len(shard.buckets) >= rlMaxPerShard {
			evictOneLocked(shard, now)
		}

		// New client: grant full burst capacity minus the one token being consumed
		shard.buckets[key] = &rlBucket{
			tokens:     rlBurst - 1.0,
			lastRefill: now,
			lastLog:    0,
		}
		return true, false
	}

	// -----------------------------------------------------------------------
	// Slow-Path Penalty Box Check (Fail-Safe)
	// -----------------------------------------------------------------------
	if rlPenaltyEnabled && bucket.bannedUntil > 0 {
		if bucket.bannedUntil > now {
			// IP is actively blackholed but somehow bypassed the fast path map.
			// Debounce the silent-drop log to protect I/O capacity.
			if now-bucket.lastLog > int64(10*time.Second) {
				bucket.lastLog = now
				log.Printf("[RATELIMIT] SECURITY: Silently dropping traffic from %s (IP is blackholed/in Penalty Box)", key.String())
			}
			return false, true
		} else {
			// Penalty Box duration has naturally expired
			bucket.bannedUntil = 0
			bucket.strikes = 0
			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s Penalty Box ban expired. Access restored.", key.String())
		}
	}

	// Calculate tokens generated since last refill
	deltaNanos := now - bucket.lastRefill
	if deltaNanos > 0 {
		deltaTokens := float64(deltaNanos) * rlQPS / 1e9
		bucket.tokens += deltaTokens
		if bucket.tokens > rlBurst {
			bucket.tokens = rlBurst
		}
		bucket.lastRefill = now
	} else if deltaNanos < 0 {
		// [SECURITY/FIX] NTP Clock reverse shift protection.
		// Prevent tokens from stagnating indefinitely if the wall clock jumps backward natively.
		bucket.lastRefill = now
	}

	// If bucket has fully refilled, we can assume the IP has behaved well for a 
	// full recovery cycle. Forgive any accumulated strikes to prevent false-positives over time.
	if bucket.tokens >= rlBurst && bucket.strikes > 0 {
		bucket.strikes = 0 
	}

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true, false
	}

	// -----------------------------------------------------------------------
	// Rate Limit Exceeded - Apply Strike or Drop
	// -----------------------------------------------------------------------
	if rlPenaltyEnabled {
		bucket.strikes++
		if bucket.strikes >= rlStrikeThreshold {
			banUntil := now + rlBanDurationNanos
			bucket.bannedUntil = banUntil
			bucket.lastLog = now

			// Inject offender into the lock-free fast-path organically, bounded by capacity
			admitToFastPenaltyBox(key, banUntil, now)

			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Strike threshold reached)", key.String(), cfg.Server.RateLimit.PenaltyBox.BanDurationMin)
			return false, true
		}
	}

	// The token bucket is exhausted. We will drop the query.
	// To provide operational visibility without causing a log-storm (I/O exhaustion) 
	// during an active reflection/flood attack, we debounce the rate-limit log.
	if now-bucket.lastLog > int64(10*time.Second) {
		bucket.lastLog = now
		log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s exceeded limit of %.1f QPS (Burst: %.0f). Queries dropped.", key.String(), rlQPS, rlBurst)
	}

	return false, false
}

// PenalizeClient is a direct-action hook allowing protocol handlers to immediately
// strike or instantly-ban IPs for extreme offenses (e.g., malformed packets, fuzzing).
// A severity of -1 issues an instant ban, regardless of current strike count.
func PenalizeClient(_ string, addr netip.Addr, severity int) {
	if !cfg.Server.RateLimit.Enabled || !rlPenaltyEnabled || !addr.IsValid() {
		return
	}
	
	key := groupIPFast(addr)

	// Exemptions are immune to direct penalties
	if isExempt(addr) {
		return
	}
	
	shard := getRLShard(key)
	now := time.Now().UnixNano()

	shard.Lock()
	defer shard.Unlock()

	bucket, exists := shard.buckets[key]
	if !exists {
		// Bound constraints identically to normal Allow logic.
		// [SECURITY/FIX 1.17.0] Same strike-preserving eviction policy.
		if len(shard.buckets) >= rlMaxPerShard {
			evictOneLocked(shard, now)
		}
		bucket = &rlBucket{
			tokens:     rlBurst,
			lastRefill: now,
		}
		shard.buckets[key] = bucket
	}

	// Ignore if they are already serving a ban to prevent log spam
	if bucket.bannedUntil > now {
		return
	}

	if severity == -1 {
		bucket.strikes = rlStrikeThreshold // Instant Ban Trigger
	} else {
		bucket.strikes += severity
	}

	if bucket.strikes >= rlStrikeThreshold {
		banUntil := now + rlBanDurationNanos
		bucket.bannedUntil = banUntil
		bucket.lastLog = now

		// Inject offender into the lock-free fast-path map, strictly bounded by capacity
		admitToFastPenaltyBox(key, banUntil, now)

		log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Severe Infraction/Malformed Traffic)", key.String(), cfg.Server.RateLimit.PenaltyBox.BanDurationMin)
	}
}

// runRateLimitSweeper periodically purges buckets that have been inactive
// long enough to fully refill their burst capacity, preventing memory leaks
// from short-lived client IPs or UDP spoofing scans.
func runRateLimitSweeper() {
	// Calculate the exact time required to completely refill the burst bucket.
	// We add 1 minute of margin to avoid premature eviction edge cases.
	refillDurationSecs := rlBurst / rlQPS
	idleHorizon := time.Duration(refillDurationSecs+60) * time.Second

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			horizonNanos := now - idleHorizon.Nanoseconds()
			
			// Prune the lock-free fast-path map natively
			for i := 0; i < rlShardCount; i++ {
				fShard := fastBanShards[i]
				fShard.Lock()
				for key, value := range fShard.bans {
					if now > value.expires.Load() {
						delete(fShard.bans, key)
						fastPenaltyBoxCount.Add(-1)
					}
				}
				fShard.Unlock()
			}

			// Prune the sharded buckets
			for i := 0; i < rlShardCount; i++ {
				shard := rlShards[i]
				shard.Lock()
				for k, bucket := range shard.buckets {
					// Evict the bucket ONLY if it's inactive AND its Penalty Box ban has fully expired
					if bucket.lastRefill < horizonNanos && bucket.bannedUntil < now {
						delete(shard.buckets, k)
					}
				}
				shard.Unlock()
			}
		case <-shutdownCh:
			return
		}
	}
}

