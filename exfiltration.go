/*
File:    exfiltration.go
Version: 1.24.0
Last Updated: 24-Nov-2026 12:46 CET

Description:
  Volumetric baseline profiling for DNS tunneling and covert exfiltration detection.
  Implements a sharded Exponential Moving Average (EMA) byte-tracker per client
  IP address or subnet prefix with a lock-free fast-path Penalty Box.

Changes:
  1.24.0 - [SECURITY/FIX] Upgraded shard capacity eviction (`evictExfilOneLocked`)
           to a 2-tier unpunished-first sampled policy (`b.strikes == 0 && b.bannedUntil <= now`)
           so spoofed IP floods cannot evict strike-carrying or banned buckets.
         - [SECURITY/FIX] Re-verified `nowNanos >= cur.expires.Load()` under
           `fShard.Lock()` before deleting an expired fast-path ban entry to
           prevent TOCTOU deletion of concurrently refreshed bans.
         - [PERF/FIX] Precomputed `exfilMaxPerShard` with ceiling division once
           at startup in `InitExfiltration`.
  1.23.1 - [SECURITY/FIX] Scaled micro-burst multiplier relative to time window.
  1.23.0 - [SECURITY/FIX] Added `lastStrike` rate-limiting to strike accrual.
  1.22.0 - [SECURITY/FIX] Removed premature `recentBytes` and `lastUpdate` resets
           inside the micro-burst block.
  1.21.0 - [CLEANUP] Standardized ceiling evaluations using `math.MaxInt64`.
  1.20.0 - [CLEANUP] Removed unused `clientIP` parameter from `AnalyzeExfiltration`.
  1.19.0 - [SECURITY/FIX] Excluded anomalous spikes from EMA baseline updates.
  1.18.0 - [CLEANUP] Streamlined `groupExfilIP`.
  1.17.0 - [SECURITY/FIX] Sampled eviction on shard capacity ceiling.
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

const (
	exfilShardCount      = 256
	exfilEvictSampleSize = 32
)

type exfilBucket struct {
	emaBps      float64
	recentBytes int
	lastUpdate  int64
	lastLog     int64
	lastStrike  int64
	strikes     int
	bannedUntil int64
}

type exfilShard struct {
	sync.Mutex
	buckets map[netip.Addr]*exfilBucket
}

type fastExfilBan struct {
	expires atomic.Int64
	lastLog atomic.Int64
}

type fastExfilShard struct {
	sync.RWMutex
	bans map[netip.Addr]*fastExfilBan
}

var (
	exfilShards       [exfilShardCount]*exfilShard
	fastExfilShards   [exfilShardCount]*fastExfilShard
	exfilHashSeed     maphash.Seed
	exfilExempt       []netip.Prefix
	exfilMaxPerShard  int
	fastExfilBoxCount atomic.Int32
)

func InitExfiltration() {
	if !cfg.Server.Exfiltration.Enabled {
		return
	}

	hasExfiltration = true
	exfilHashSeed = maphash.MakeSeed()
	exfilExempt = parseACL(cfg.Server.Exfiltration.Exempt)

	maxIPs := cfg.Server.Exfiltration.MaxTrackedIPs
	if maxIPs <= 0 {
		maxIPs = 50000
	}
	cfg.Server.Exfiltration.MaxTrackedIPs = maxIPs
	exfilMaxPerShard = max((maxIPs+exfilShardCount-1)/exfilShardCount, 1)

	for i := 0; i < exfilShardCount; i++ {
		exfilShards[i] = &exfilShard{
			buckets: make(map[netip.Addr]*exfilBucket),
		}
		fastExfilShards[i] = &fastExfilShard{
			bans: make(map[netip.Addr]*fastExfilBan),
		}
	}

	if logSystem {
		log.Printf("[EXFILTRATION] Active: Threshold %.0f BPS | Multiplier %.1fx | Action: %s",
			cfg.Server.Exfiltration.MinThresholdBPS, cfg.Server.Exfiltration.AnomalyMultiplier, cfg.Server.Exfiltration.Action)

		if cfg.Server.Exfiltration.PenaltyBox.Enabled {
			log.Printf("[EXFILTRATION] Penalty Box Enabled: Blackholing offenders for %d mins after %d strikes.",
				cfg.Server.Exfiltration.PenaltyBox.BanDurationMin, cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold)
		}
	}

	go runExfilSweeper()
}

func isExfilExempt(addr netip.Addr) bool {
	if len(exfilExempt) == 0 || !addr.IsValid() {
		return false
	}
	for _, prefix := range exfilExempt {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func getExfilShard(key netip.Addr) *exfilShard {
	b := key.As16()
	h := maphash.Bytes(exfilHashSeed, b[:])
	return exfilShards[h&(exfilShardCount-1)]
}

func getFastExfilShard(key netip.Addr) *fastExfilShard {
	b := key.As16()
	h := maphash.Bytes(exfilHashSeed, b[:])
	return fastExfilShards[h&(exfilShardCount-1)]
}

func groupExfilIP(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}

	bits := cfg.Server.Exfiltration.IPv6PrefixLength
	if addr.Is4() {
		bits = cfg.Server.Exfiltration.IPv4PrefixLength
		if bits <= 0 || bits >= 32 {
			return addr
		}
	} else if addr.Is6() {
		if bits <= 0 || bits >= 128 {
			return addr
		}
	} else {
		return addr
	}

	prefix, _ := addr.Prefix(bits)
	return prefix.Masked().Addr()
}

func evictExfilOneLocked(shard *exfilShard, now int64) {
	var (
		bestKey      netip.Addr
		bestTS       int64
		bestFound    bool
		bestUnpunish bool
		sampled      int
	)

	for k, b := range shard.buckets {
		unpunished := b.strikes == 0 && b.bannedUntil <= now
		better := !bestFound ||
			(unpunished && !bestUnpunish) ||
			(unpunished == bestUnpunish && b.lastUpdate < bestTS)
		if better {
			bestKey, bestTS, bestUnpunish, bestFound = k, b.lastUpdate, unpunished, true
		}
		sampled++
		if sampled >= exfilEvictSampleSize {
			break
		}
	}

	if bestFound {
		delete(shard.buckets, bestKey)
	}
}

func AnalyzeExfiltration(addr netip.Addr, reqSize int) (allowed bool, isBanned bool, bps float64) {
	if !addr.IsValid() {
		return true, false, 0
	}

	key := groupExfilIP(addr)

	// 1. Fast-Path Penalty Box Check
	fShard := getFastExfilShard(key)
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
						log.Printf("[EXFILTRATION] SECURITY: Silently dropping traffic from %s (IP is blackholed - Fast Path)", key.String())
					}
				}
			}
			return false, true, 0
		}
		fShard.Lock()
		if cur, loaded := fShard.bans[key]; loaded && nowNanos >= cur.expires.Load() {
			delete(fShard.bans, key)
			fastExfilBoxCount.Add(-1)
		}
		fShard.Unlock()
	}

	if isExfilExempt(addr) {
		return true, false, 0
	}

	shard := getExfilShard(key)
	now := time.Now().UnixNano()

	shard.Lock()
	defer shard.Unlock()

	b, exists := shard.buckets[key]
	if !exists {
		if len(shard.buckets) >= exfilMaxPerShard {
			evictExfilOneLocked(shard, now)
		}

		b = &exfilBucket{
			lastUpdate: now,
		}
		shard.buckets[key] = b
		b.recentBytes += reqSize
		return true, false, 0
	}

	// 2. Slow-Path Penalty Box Check
	if cfg.Server.Exfiltration.PenaltyBox.Enabled && b.bannedUntil > 0 {
		if b.bannedUntil > now {
			if now-b.lastLog > int64(10*time.Second) {
				b.lastLog = now
				if logSystem {
					log.Printf("[EXFILTRATION] SECURITY: Silently dropping traffic from %s (IP is blackholed)", key.String())
				}
			}
			return false, true, 0
		}
		b.bannedUntil = 0
		b.strikes = 0
		if logSystem {
			log.Printf("[EXFILTRATION] SECURITY: Client/Subnet %s Penalty Box ban expired. Access restored.", key.String())
		}
	}

	b.recentBytes += reqSize
	deltaNanos := now - b.lastUpdate
	if deltaNanos < 0 {
		b.lastUpdate = now
		deltaNanos = 0
	}

	currentBPS := 0.0
	anomalous := false

	threshold := cfg.Server.Exfiltration.MinThresholdBPS
	multiplier := cfg.Server.Exfiltration.AnomalyMultiplier

	// 3. Alpha-Smoothed EMA Recalculation
	if deltaNanos >= 1e9 {
		deltaSecs := float64(deltaNanos) / 1e9
		currentBPS = float64(b.recentBytes) / deltaSecs

		evalBaseline := b.emaBps
		if evalBaseline == 0 {
			evalBaseline = threshold
		}

		if currentBPS > threshold && currentBPS > (evalBaseline*multiplier) {
			anomalous = true
		} else {
			if b.strikes > 0 {
				b.strikes--
			}
			if b.emaBps == 0 {
				b.emaBps = threshold
			} else {
				b.emaBps = (0.2 * currentBPS) + (0.8 * b.emaBps)
			}
		}

		b.recentBytes = 0
		b.lastUpdate = now
	} else {
		// 4. Micro-Burst Projection
		deltaSecs := float64(deltaNanos) / 1e9
		if deltaSecs < 0.001 {
			deltaSecs = 0.001
		}

		currentBPS = float64(b.recentBytes) / deltaSecs

		if b.recentBytes >= 32768 {
			evalBaseline := b.emaBps
			if evalBaseline == 0 {
				evalBaseline = threshold
			}

			effectiveMultiplier := multiplier
			if deltaSecs < 0.25 {
				effectiveMultiplier *= 2.0
			} else if deltaSecs < 0.5 {
				effectiveMultiplier *= 1.5
			}

			if currentBPS > threshold && currentBPS > (evalBaseline*effectiveMultiplier) {
				anomalous = true
			}
		}
	}

	// 5. Strike Enforcement & Blackholing
	if anomalous {
		if now-b.lastStrike >= 1e9 {
			b.strikes++
			b.lastStrike = now
		} else {
			return false, false, currentBPS
		}

		if cfg.Server.Exfiltration.PenaltyBox.Enabled && b.strikes >= cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold {
			banMins := cfg.Server.Exfiltration.PenaltyBox.BanDurationMin
			if banMins <= 0 {
				banMins = 15
			}
			banUntil := now + (int64(banMins) * 60 * 1e9)
			b.bannedUntil = banUntil
			b.lastLog = now

			fShard.RLock()
			existing, ok := fShard.bans[key]
			fShard.RUnlock()

			if ok {
				existing.expires.Store(banUntil)
			} else if fastExfilBoxCount.Load() < int32(cfg.Server.Exfiltration.MaxTrackedIPs) {
				fShard.Lock()
				if existing, stillOk := fShard.bans[key]; stillOk {
					existing.expires.Store(banUntil)
				} else {
					fastEntry := &fastExfilBan{}
					fastEntry.expires.Store(banUntil)
					fastEntry.lastLog.Store(now)
					fShard.bans[key] = fastEntry
					fastExfilBoxCount.Add(1)
				}
				fShard.Unlock()
			}

			if logSystem {
				log.Printf("[EXFILTRATION] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Exfiltration Detected)", key.String(), banMins)
			}
			return false, true, currentBPS
		}
		return false, false, currentBPS
	}

	return true, false, currentBPS
}

func runExfilSweeper() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			horizonNanos := now - int64(5*time.Minute)

			for i := 0; i < exfilShardCount; i++ {
				fShard := fastExfilShards[i]
				fShard.Lock()
				for key, value := range fShard.bans {
					if now > value.expires.Load() {
						delete(fShard.bans, key)
						fastExfilBoxCount.Add(-1)
					}
				}
				fShard.Unlock()
			}

			for i := 0; i < exfilShardCount; i++ {
				shard := exfilShards[i]
				shard.Lock()
				for k, bucket := range shard.buckets {
					if bucket.lastUpdate < horizonNanos && bucket.bannedUntil < now {
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
