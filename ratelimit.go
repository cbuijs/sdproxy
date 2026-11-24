/*
File:    ratelimit.go
Version: 1.21.0
Last Updated: 24-Nov-2026 12:56 CET

Description:
  High-performance, sharded Token Bucket Rate Limiter and Penalty Box.
  Defends against DNS amplification, reflection, and volumetric DDoS attacks.

Changes:
  1.21.0 - [SECURITY/FIX] Re-verified `nowNanos >= cur.expires.Load()` under
           `fShard.Lock()` before deleting expired fast-path bans in `AllowClient`
           to prevent TOCTOU deletion of concurrently refreshed bans.
         - [FIX] Used ceiling division `(maxIPs + rlShardCount - 1) / rlShardCount`
           for `rlMaxPerShard` so default `max_tracked_ips: 1000` allocates full
           capacity across all 256 shards instead of truncating to 768, and
           aligned fallback `maxIPs` with `validateConfig` (1000).
  1.20.0 - [FIX] Guarded `[RATELIMIT]` log lines with `if logSystem`.
  1.19.0 - [CLEANUP] Streamlined `groupIPFast`.
  1.18.0 - [PERF] Replaced `fastPenaltyBox` `sync.Map` with 256-shard `RWMutex`.
  1.17.0 - [SECURITY/PERF] 2-tier sampled shard eviction policy.
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

const rlShardCount = 256
const rlEvictSampleSize = 32

type rlBucket struct {
	tokens      float64
	lastRefill  int64
	lastLog     int64
	strikes     int
	bannedUntil int64
}

type rlShard struct {
	sync.Mutex
	buckets map[netip.Addr]*rlBucket
}

type fastBanEntry struct {
	expires atomic.Int64
	lastLog atomic.Int64
}

type fastBanShard struct {
	sync.RWMutex
	bans map[netip.Addr]*fastBanEntry
}

var (
	rlShards      [rlShardCount]*rlShard
	fastBanShards [rlShardCount]*fastBanShard

	rlQPS         float64
	rlBurst       float64
	rlV4Bits      int
	rlV6Bits      int
	rlMaxPerShard int

	rlExempt []netip.Prefix

	rlPenaltyEnabled   bool
	rlStrikeThreshold  int
	rlBanDurationNanos int64

	fastPenaltyBoxCount atomic.Int32

	rlHashSeed maphash.Seed
)

func InitRateLimiter() {
	if !cfg.Server.RateLimit.Enabled {
		return
	}

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
		maxIPs = 1000
	}
	cfg.Server.RateLimit.MaxTrackedIPs = maxIPs

	rlMaxPerShard = max((maxIPs+rlShardCount-1)/rlShardCount, 1)

	rlExempt = parseACL(cfg.Server.RateLimit.Exempt)

	rlPenaltyEnabled = cfg.Server.RateLimit.PenaltyBox.Enabled
	rlStrikeThreshold = cfg.Server.RateLimit.PenaltyBox.StrikeThreshold
	if rlStrikeThreshold <= 0 {
		rlStrikeThreshold = 100
	}

	banMins := cfg.Server.RateLimit.PenaltyBox.BanDurationMin
	if banMins <= 0 {
		banMins = 15
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

	if logSystem {
		log.Printf("[RATELIMIT] Active: %.1f QPS (Burst: %.0f) | Grouping: IPv4 /%d, IPv6 /%d | Max Tracked IPs: %d",
			rlQPS, rlBurst, rlV4Bits, rlV6Bits, maxIPs)

		if rlPenaltyEnabled {
			log.Printf("[RATELIMIT] Penalty Box Enabled: Blackholing offenders for %d mins after %d strikes.", banMins, rlStrikeThreshold)
		}
		if len(rlExempt) > 0 {
			log.Printf("[RATELIMIT] Exemption List: %d IP/Subnet rule(s) configured for unlimited access.", len(rlExempt))
		}
	}

	go runRateLimitSweeper()
}

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

func getRLShard(key netip.Addr) *rlShard {
	b := key.As16()
	h := maphash.Bytes(rlHashSeed, b[:])
	return rlShards[h&(rlShardCount-1)]
}

func getFastBanShard(key netip.Addr) *fastBanShard {
	b := key.As16()
	h := maphash.Bytes(rlHashSeed, b[:])
	return fastBanShards[h&(rlShardCount-1)]
}

func groupIPFast(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}

	bits := rlV6Bits
	if addr.Is4() {
		bits = rlV4Bits
		if bits >= 32 {
			return addr
		}
	} else if addr.Is6() {
		if bits >= 128 {
			return addr
		}
	} else {
		return addr
	}

	prefix, _ := addr.Prefix(bits)
	return prefix.Masked().Addr()
}

func evictOneLocked(shard *rlShard, now int64) {
	var (
		bestKey      netip.Addr
		bestRefill   int64
		bestFound    bool
		bestUnpunish bool
		scanned      int
	)

	for k, b := range shard.buckets {
		unpunished := b.strikes == 0 && b.bannedUntil <= now

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

func admitToFastPenaltyBox(key netip.Addr, banUntil, now int64) {
	fShard := getFastBanShard(key)
	fShard.RLock()
	existing, ok := fShard.bans[key]
	fShard.RUnlock()

	if ok {
		existing.expires.Store(banUntil)
		return
	}

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

func AllowClient(_ string, addr netip.Addr) (allowed bool, isBanned bool) {
	if !addr.IsValid() {
		return false, false
	}

	key := groupIPFast(addr)

	// 1. Fast-Path Penalty Box Check
	fShard := getFastBanShard(key)
	fShard.RLock()
	banEntry, fastOk := fShard.bans[key]
	fShard.RUnlock()

	if fastOk {
		nowNanos := time.Now().UnixNano()
		if nowNanos < banEntry.expires.Load() {
			last := banEntry.lastLog.Load()
			if nowNanos-last > int64(10*time.Second) {
				if banEntry.lastLog.CompareAndSwap(last, nowNanos) {
					if logSystem {
						log.Printf("[RATELIMIT] SECURITY: Silently dropping traffic from %s (IP is blackholed/in Penalty Box - Fast Path)", key.String())
					}
				}
			}
			return false, true
		}
		fShard.Lock()
		if cur, loaded := fShard.bans[key]; loaded && nowNanos >= cur.expires.Load() {
			delete(fShard.bans, key)
			fastPenaltyBoxCount.Add(-1)
		}
		fShard.Unlock()
	}

	// 2. Exemptions
	if isExempt(addr) {
		return true, false
	}

	shard := getRLShard(key)
	now := time.Now().UnixNano()

	shard.Lock()
	defer shard.Unlock()

	bucket, exists := shard.buckets[key]
	if !exists {
		if len(shard.buckets) >= rlMaxPerShard {
			evictOneLocked(shard, now)
		}

		shard.buckets[key] = &rlBucket{
			tokens:     rlBurst - 1.0,
			lastRefill: now,
			lastLog:    0,
		}
		return true, false
	}

	// 3. Slow-Path Penalty Box Check
	if rlPenaltyEnabled && bucket.bannedUntil > 0 {
		if bucket.bannedUntil > now {
			if now-bucket.lastLog > int64(10*time.Second) {
				bucket.lastLog = now
				if logSystem {
					log.Printf("[RATELIMIT] SECURITY: Silently dropping traffic from %s (IP is blackholed/in Penalty Box)", key.String())
				}
			}
			return false, true
		}
		bucket.bannedUntil = 0
		bucket.strikes = 0
		if logSystem {
			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s Penalty Box ban expired. Access restored.", key.String())
		}
	}

	deltaNanos := now - bucket.lastRefill
	if deltaNanos > 0 {
		deltaTokens := float64(deltaNanos) * rlQPS / 1e9
		bucket.tokens += deltaTokens
		if bucket.tokens > rlBurst {
			bucket.tokens = rlBurst
		}
		bucket.lastRefill = now
	} else if deltaNanos < 0 {
		bucket.lastRefill = now
	}

	if bucket.tokens >= rlBurst && bucket.strikes > 0 {
		bucket.strikes = 0
	}

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true, false
	}

	// 4. Rate Limit Exceeded - Apply Strike or Drop
	if rlPenaltyEnabled {
		bucket.strikes++
		if bucket.strikes >= rlStrikeThreshold {
			banUntil := now + rlBanDurationNanos
			bucket.bannedUntil = banUntil
			bucket.lastLog = now

			admitToFastPenaltyBox(key, banUntil, now)

			if logSystem {
				log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Strike threshold reached)", key.String(), cfg.Server.RateLimit.PenaltyBox.BanDurationMin)
			}
			return false, true
		}
	}

	if now-bucket.lastLog > int64(10*time.Second) {
		bucket.lastLog = now
		if logSystem {
			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s exceeded limit of %.1f QPS (Burst: %.0f). Queries dropped.", key.String(), rlQPS, rlBurst)
		}
	}

	return false, false
}

func PenalizeClient(_ string, addr netip.Addr, severity int) {
	if !cfg.Server.RateLimit.Enabled || !rlPenaltyEnabled || !addr.IsValid() {
		return
	}

	key := groupIPFast(addr)

	if isExempt(addr) {
		return
	}

	shard := getRLShard(key)
	now := time.Now().UnixNano()

	shard.Lock()
	defer shard.Unlock()

	bucket, exists := shard.buckets[key]
	if !exists {
		if len(shard.buckets) >= rlMaxPerShard {
			evictOneLocked(shard, now)
		}
		bucket = &rlBucket{
			tokens:     rlBurst,
			lastRefill: now,
		}
		shard.buckets[key] = bucket
	}

	if bucket.bannedUntil > now {
		return
	}

	if severity == -1 {
		bucket.strikes = rlStrikeThreshold
	} else {
		bucket.strikes += severity
	}

	if bucket.strikes >= rlStrikeThreshold {
		banUntil := now + rlBanDurationNanos
		bucket.bannedUntil = banUntil
		bucket.lastLog = now

		admitToFastPenaltyBox(key, banUntil, now)

		if logSystem {
			log.Printf("[RATELIMIT] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Severe Infraction/Malformed Traffic)", key.String(), cfg.Server.RateLimit.PenaltyBox.BanDurationMin)
		}
	}
}

func runRateLimitSweeper() {
	refillDurationSecs := rlBurst / rlQPS
	idleHorizon := time.Duration(refillDurationSecs+60) * time.Second

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			horizonNanos := now - idleHorizon.Nanoseconds()

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

			for i := 0; i < rlShardCount; i++ {
				shard := rlShards[i]
				shard.Lock()
				for k, bucket := range shard.buckets {
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
