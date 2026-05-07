/*
File:    ratelimit.go
Version: 1.11.0
Updated: 07-May-2026 12:48 CEST

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
  1.11.0 - [SECURITY] Protected the Token Bucket refill calculus against wall-clock regressions.
           If the underlying NTP service dynamically adjusts the system clock backwards, 
           the bucket natively absorbs the timeline shift rather than perpetually locking 
           the client out by inverting their refill boundary constraints.
  1.10.0 - [SECURITY] Resolved a critical Penalty Box expiration regression. 
           `fastBanEntry` now utilizes `atomic.Int64` for its `expires` field, 
           guaranteeing that continuous repeat offenders have their ban horizons 
           extended natively in real-time across the lock-free sync.Map without 
           vulnerable TOCTOU overwrites.
  1.9.0  - [SECURITY] Resolved a Time-Of-Check to Time-Of-Use (TOCTOU) race condition in 
           the Penalty Box fast-path tracker. Implemented `LoadAndDelete` across Sweeper 
           and Admission threads to guarantee deterministic exact-counting of 
           `fastPenaltyBoxCount`, preventing map-capacity starvation during continuous 
           high-volume DDoS floods.
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
	buckets map[string]*rlBucket
}

// fastBanEntry represents a lock-free cache item for actively blackholed clients.
// Enforced via atomic.Int64 structures to ensure concurrent strike extensions 
// execute securely without map-level TOCTOU (Time-Of-Check to Time-Of-Use) regressions.
type fastBanEntry struct {
	expires atomic.Int64
	lastLog atomic.Int64
}

var (
	rlShards [rlShardCount]*rlShard

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

	// fastPenaltyBox provides a lock-free, O(1) fast-path for actively blackholed IPs.
	// This prevents shard-mutex contention during high-volume spoofed DDoS attacks.
	fastPenaltyBox sync.Map
	
	// fastPenaltyBoxCount strictly limits the unbounded growth of the sync.Map above.
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
			buckets: make(map[string]*rlBucket),
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

// getRLShard hashes a string key to one of the 256 shards using maphash.
func getRLShard(key string) *rlShard {
	h := maphash.String(rlHashSeed, key)
	return rlShards[h&(rlShardCount-1)]
}

// groupIPFast masks the incoming IP address according to configured prefix lengths.
// Utilizes pre-parsed netip.Addr to eliminate redundant allocations on the hot path.
func groupIPFast(ipStr string, addr netip.Addr) string {
	if !addr.IsValid() {
		return ipStr
	}

	if addr.Is4() {
		if rlV4Bits == 32 {
			return ipStr
		}
		prefix, _ := addr.Prefix(rlV4Bits)
		return prefix.Masked().Addr().String()
	} else if addr.Is6() {
		if rlV6Bits == 128 {
			return ipStr
		}
		prefix, _ := addr.Prefix(rlV6Bits)
		return prefix.Masked().Addr().String()
	}

	return ipStr
}

// AllowClient checks whether the client IP has enough tokens to execute a query.
// It also evaluates the Penalty Box (blackhole) status.
// Returns two booleans: `allowed` indicating if the query can proceed, and 
// `isBanned` indicating if the client is currently in the Penalty Box.
func AllowClient(clientIP string, addr netip.Addr) (allowed bool, isBanned bool) {
	if clientIP == "" {
		return true, false // Allow internal queries if they lack an IP
	}

	key := groupIPFast(clientIP, addr)

	// -----------------------------------------------------------------------
	// 1. LOCK-FREE FAST-PATH (Penalty Box)
	// -----------------------------------------------------------------------
	// Bypasses shard-mutex locking and exemption loops entirely for actively 
	// blackholed IPs. Extremely critical for maintaining node stability during 
	// volumetric spoofed-IP or brute-force DDoS attacks.
	if entryRaw, ok := fastPenaltyBox.Load(key); ok {
		banEntry := entryRaw.(*fastBanEntry)
		nowNanos := time.Now().UnixNano()
		if nowNanos < banEntry.expires.Load() {
			// Debounce the silent-drop log using atomic operations to protect I/O capacity
			last := banEntry.lastLog.Load()
			if nowNanos-last > int64(10*time.Second) {
				if banEntry.lastLog.CompareAndSwap(last, nowNanos) {
					log.Printf("[RATELIMIT] SECURITY: Silently dropping traffic from %s (IP is blackholed/in Penalty Box - Fast Path)", key)
				}
			}
			return false, true
		}
		// Ban has naturally expired, remove from fast-path and fall through.
		// LoadAndDelete guarantees exact-counting, preventing multiple parallel queries
		// or the sweeper from decrementing the active limit tracker multiple times.
		if _, loaded := fastPenaltyBox.LoadAndDelete(key); loaded {
			fastPenaltyBoxCount.Add(-1) // Free capacity immediately
		}
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
		// Hard memory limit check: Evict a pseudo-random entry if shard is full.
		// Protects strictly against OOM from spoofed-source DNS floods.
		if len(shard.buckets) >= rlMaxPerShard {
			for k := range shard.buckets {
				delete(shard.buckets, k)
				break
			}
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
				log.Printf("[RATELIMIT] SECURITY: Silently dropping traffic from %s (IP is blackholed/in Penalty Box)", key)
			}
			return false, true
		} else {
			// Penalty Box duration has naturally expired
			bucket.bannedUntil = 0
			bucket.strikes = 0
			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s Penalty Box ban expired. Access restored.", key)
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
			
			// Inject offender into the lock-free fast-path map, strictly bounded by capacity
			if existingRaw, loaded := fastPenaltyBox.Load(key); loaded {
				existing := existingRaw.(*fastBanEntry)
				existing.expires.Store(banUntil) // Safely extend lock-free horizon
			} else if fastPenaltyBoxCount.Load() < int32(cfg.Server.RateLimit.MaxTrackedIPs) {
				fastEntry := &fastBanEntry{}
				fastEntry.expires.Store(banUntil)
				fastEntry.lastLog.Store(now)
				// LoadOrStore guarantees we only increment capacity if we actually contributed the record
				if existingConcurrent, loaded := fastPenaltyBox.LoadOrStore(key, fastEntry); !loaded {
					fastPenaltyBoxCount.Add(1)
				} else {
					// Extremely parallel edge-case where the IP was inserted directly prior
					existing := existingConcurrent.(*fastBanEntry)
					existing.expires.Store(banUntil)
				}
			}
			
			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Strike threshold reached)", key, cfg.Server.RateLimit.PenaltyBox.BanDurationMin)
			return false, true
		}
	}

	// The token bucket is exhausted. We will drop the query.
	// To provide operational visibility without causing a log-storm (I/O exhaustion) 
	// during an active reflection/flood attack, we debounce the rate-limit log.
	if now-bucket.lastLog > int64(10*time.Second) {
		bucket.lastLog = now
		log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s exceeded limit of %.1f QPS (Burst: %.0f). Queries dropped.", key, rlQPS, rlBurst)
	}

	return false, false
}

// PenalizeClient is a direct-action hook allowing protocol handlers to immediately
// strike or instantly-ban IPs for extreme offenses (e.g., malformed packets, fuzzing).
// A severity of -1 issues an instant ban, regardless of current strike count.
func PenalizeClient(clientIP string, addr netip.Addr, severity int) {
	if !cfg.Server.RateLimit.Enabled || !rlPenaltyEnabled || clientIP == "" {
		return
	}
	
	key := groupIPFast(clientIP, addr)

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
		// Bound constraints identically to normal Allow logic
		if len(shard.buckets) >= rlMaxPerShard {
			for k := range shard.buckets {
				delete(shard.buckets, k)
				break
			}
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
		if existingRaw, loaded := fastPenaltyBox.Load(key); loaded {
			existing := existingRaw.(*fastBanEntry)
			existing.expires.Store(banUntil) // Safely extend lock-free horizon
		} else if fastPenaltyBoxCount.Load() < int32(cfg.Server.RateLimit.MaxTrackedIPs) {
			fastEntry := &fastBanEntry{}
			fastEntry.expires.Store(banUntil)
			fastEntry.lastLog.Store(now)
			// LoadOrStore guarantees we only increment capacity if we actually contributed the record
			if existingConcurrent, loaded := fastPenaltyBox.LoadOrStore(key, fastEntry); !loaded {
				fastPenaltyBoxCount.Add(1)
			} else {
				// Extremely parallel edge-case where the IP was inserted directly prior
				existing := existingConcurrent.(*fastBanEntry)
				existing.expires.Store(banUntil)
			}
		}
		
		log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Severe Infraction/Malformed Traffic)", key, cfg.Server.RateLimit.PenaltyBox.BanDurationMin)
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

	for range ticker.C {
		now := time.Now().UnixNano()
		horizonNanos := now - idleHorizon.Nanoseconds()
		
		// Prune the lock-free fast-path map natively
		fastPenaltyBox.Range(func(key, value any) bool {
			if now > value.(*fastBanEntry).expires.Load() {
				if _, loaded := fastPenaltyBox.LoadAndDelete(key); loaded {
					fastPenaltyBoxCount.Add(-1)
				}
			}
			return true
		})

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
	}
}

