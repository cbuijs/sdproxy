/*
File:    exfiltration.go
Version: 1.17.0
Last Updated: 17-Aug-2026 18:00 CEST
Description:
  Volumetric baseline profiling for DNS tunneling and covert exfiltration detection.
  Implements a high-performance, sharded, lock-free Exponential Moving Average (EMA) 
  byte-tracker per client IP address or subnet prefix.

  Tracks real-time bandwidth limits across UDP/TCP/QUIC and dynamically intercepts 
  clients transmitting anomalous data volumes over port 53.

Changes:
  1.17.0 - [SECURITY/FIX] Replaced blind map eviction during HashDoS floods with
           Power-of-N-Choices sampled eviction natively. Eliminates the vulnerability 
           where attackers could artificially launder their data-exfiltration strikes 
           by flooding the shard capacities organically to trigger blind deletions.
  1.16.0 - [PERF] Eradicated `sync.Map` boxing allocations on the hot path natively. 
           Replaced `fastExfilBox` with a dedicated 256-shard `sync.RWMutex` array. 
           Prevents `netip.Addr` struct-to-interface conversions from allocating 
           heap memory on every evaluation, drastically reducing GC pressure during floods.
  1.15.0 - [DEAD-CODE/FIX] Excised an unreachable clamp from the Micro-Burst
           Projection cold-start path. `baselineCap := threshold * 5.0` followed by
           `if evalBaseline > baselineCap` could never evaluate true, because
           evalBaseline was assigned `threshold` on the immediately preceding line.
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

// exfilShardCount specifies the number of independent Mutex locks.
// Distributing state across 256 shards practically eliminates lock contention
// under extreme multi-core volumetric floods.
const exfilShardCount = 256

// exfilBucket maintains the historical throughput context for a single IP or Subnet.
type exfilBucket struct {
	emaBps      float64 // Exponential Moving Average (Baseline throughput)
	recentBytes int     // Accumulator for bytes transferred in the current evaluation tick
	lastUpdate  int64   // Unix nanoseconds of the last EMA recalculation
	lastLog     int64   // Unix nanoseconds to debounce duplicate logs
	strikes     int     // Consecutive penalty infractions
	bannedUntil int64   // Expiration of the Penalty Box sentence
}

type exfilShard struct {
	sync.Mutex
	buckets map[netip.Addr]*exfilBucket
}

// fastExfilBan provides lock-free verification for actively blackholed clients.
// Uses atomics to eliminate TOCTOU (Time-Of-Check to Time-Of-Use) vulnerabilities
// and map-contention during high-volume spoofing attacks.
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
	fastExfilBoxCount atomic.Int32
)

// InitExfiltration configures and instantiates the volumetric profiling data structures.
func InitExfiltration() {
	if !cfg.Server.Exfiltration.Enabled {
		return
	}

	hasExfiltration = true
	// Seeded cryptographically to neutralize HashDoS attacks against the tracking map
	exfilHashSeed = maphash.MakeSeed()
	exfilExempt = parseACL(cfg.Server.Exfiltration.Exempt)

	maxIPs := cfg.Server.Exfiltration.MaxTrackedIPs
	if maxIPs <= 0 {
		maxIPs = 50000
	}
	cfg.Server.Exfiltration.MaxTrackedIPs = maxIPs 

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

// getExfilShard securely routes the client netip.Addr key to its designated Mutex bucket.
func getExfilShard(key netip.Addr) *exfilShard {
	b := key.As16()
	h := maphash.Bytes(exfilHashSeed, b[:])
	return exfilShards[h&(exfilShardCount-1)]
}

// getFastExfilShard natively routes the netip.Addr to the zero-allocation 
// RWMutex fast-path shard.
func getFastExfilShard(key netip.Addr) *fastExfilShard {
	b := key.As16()
	h := maphash.Bytes(exfilHashSeed, b[:])
	return fastExfilShards[h&(exfilShardCount-1)]
}

// groupExfilIP masks the incoming IP address according to configured prefix lengths natively.
// Operates exclusively on and returns netip.Addr structures natively to preserve zero-allocation pipelines.
func groupExfilIP(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}

	if addr.Is4() {
		bits := cfg.Server.Exfiltration.IPv4PrefixLength
		if bits <= 0 || bits > 32 {
			bits = 32
		}
		if bits == 32 {
			return addr
		}
		prefix, _ := addr.Prefix(bits)
		return prefix.Masked().Addr()
	} else if addr.Is6() {
		bits := cfg.Server.Exfiltration.IPv6PrefixLength
		if bits <= 0 || bits > 128 {
			bits = 128
		}
		if bits == 128 {
			return addr
		}
		prefix, _ := addr.Prefix(bits)
		return prefix.Masked().Addr()
	}

	return addr
}

// AnalyzeExfiltration evaluates the payload size of an incoming query against the client's historical
// baseline to identify data exfiltration. Uses an Alpha-smoothed Exponential Moving Average (EMA).
// Returns whether the request is allowed, if the client is actively blackholed, and the instantaneous BPS.
func AnalyzeExfiltration(_ string, addr netip.Addr, reqSize int) (allowed bool, isBanned bool, bps float64) {
	if !addr.IsValid() {
		return true, false, 0
	}

	key := groupExfilIP(addr)

	// -----------------------------------------------------------------------
	// 1. Lock-free Fast-Path Verification
	// -----------------------------------------------------------------------
	// Natively intercepts and drops actively blackholed tunnelers using `RWMutex`.
	// Bypasses the Mutex operations entirely to preserve I/O capacity during floods, 
	// while avoiding the 24-byte struct boxing allocation caused by `sync.Map`.
	fShard := getFastExfilShard(key)
	fShard.RLock()
	banEntry, fastOk := fShard.bans[key]
	fShard.RUnlock()

	if fastOk {
		nowNanos := time.Now().UnixNano()
		if nowNanos < banEntry.expires.Load() {
			last := banEntry.lastLog.Load()
			// Debounce logs atomically to prevent CPU/Disk I/O exhaustion
			if nowNanos-last > int64(10*time.Second) {
				if banEntry.lastLog.CompareAndSwap(last, nowNanos) {
					if logSystem {
						log.Printf("[EXFILTRATION] SECURITY: Silently dropping traffic from %s (IP is blackholed - Fast Path)", key.String())
					}
				}
			}
			return false, true, 0
		}
		// Penalty expired, dynamically prune the Fast-Path. Lock ensures clean counting.
		fShard.Lock()
		if _, loaded := fShard.bans[key]; loaded {
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
		maxIPs := cfg.Server.Exfiltration.MaxTrackedIPs
		if maxIPs <= 0 {
			maxIPs = 50000
		}
		maxPerShard := maxIPs / exfilShardCount
		if maxPerShard < 1 {
			maxPerShard = 1
		}

		// Hard constraint: Prevent memory exhaustion/HashDoS during spoofing attacks
		// [SECURITY/FIX] Use power-of-n-choices sampled eviction to prevent attackers 
		// from blindly laundering strikes via spoofed IP floods natively.
		if len(shard.buckets) >= maxPerShard {
			var oldestKey netip.Addr
			var oldestTS int64 = 1<<63 - 1
			var sampled int
			
			for k, b := range shard.buckets {
				if b.lastUpdate < oldestTS {
					oldestTS = b.lastUpdate
					oldestKey = k
				}
				sampled++
				if sampled >= 32 {
					break
				}
			}
			delete(shard.buckets, oldestKey)
		}

		b = &exfilBucket{
			lastUpdate: now,
		}
		shard.buckets[key] = b
		b.recentBytes += reqSize
		return true, false, 0
	}

	// -----------------------------------------------------------------------
	// 2. Slow-Path Penalty Box Check
	// -----------------------------------------------------------------------
	// Failsafe in case a banned client bypasses the fast-path (e.g., memory eviction).
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
		// Natural expiration of the penalty box
		b.bannedUntil = 0
		b.strikes = 0
		if logSystem {
			log.Printf("[EXFILTRATION] SECURITY: Client/Subnet %s Penalty Box ban expired. Access restored.", key.String())
		}
	}

	b.recentBytes += reqSize
	deltaNanos := now - b.lastUpdate
	
	// [SECURITY/FIX] Protect against NTP reverse clock drifts causing negative delta bounds natively
	if deltaNanos < 0 {
		b.lastUpdate = now
		deltaNanos = 0
	}
	
	currentBPS := 0.0
	anomalous := false

	threshold := cfg.Server.Exfiltration.MinThresholdBPS
	multiplier := cfg.Server.Exfiltration.AnomalyMultiplier

	// -----------------------------------------------------------------------
	// 3. Alpha-Smoothed EMA Recalculation
	// -----------------------------------------------------------------------
	// Executed strictly at 1-second boundaries. Averages historical throughput
	// to establish a "normal" baseline for the client.
	if deltaNanos >= 1e9 {
		deltaSecs := float64(deltaNanos) / 1e9
		currentBPS = float64(b.recentBytes) / deltaSecs

		if b.emaBps == 0 {
			b.emaBps = threshold
		} else {
			b.emaBps = (0.2 * currentBPS) + (0.8 * b.emaBps)
		}

		b.recentBytes = 0
		b.lastUpdate = now

		// The client must exceed the raw minimum threshold AND heavily outpace 
		// their own historical norm. This prevents punishing heavy legitimate usage.
		if currentBPS > threshold && currentBPS > (b.emaBps*multiplier) {
			anomalous = true
		} else if b.strikes > 0 {
			b.strikes-- // Forgive behavior naturally over sustained clean periods
		}
	} else {
		// -----------------------------------------------------------------------
		// 4. Micro-Burst Projection
		// -----------------------------------------------------------------------
		// Instantly intercepts micro-burst exfiltration attempts prior to the 
		// 1-second interval tick. Projects accumulated payload against the precise
		// fractional timeframe to establish the true instantaneous BPS.
		deltaSecs := float64(deltaNanos) / 1e9
		if deltaSecs < 0.001 { 
			// Enforce a strict 1ms floor to prevent division-by-zero infinity anomalies
			// and ensure hyper-velocity floods correctly scale to astronomical BPS ratings.
			deltaSecs = 0.001
		}
		
		currentBPS = float64(b.recentBytes) / deltaSecs

		// [SECURITY/FIX] Enforce a strict absolute payload mass (32KB) before anomaly extrapolation.
		// Projecting small payloads over microscopic timeframes produces astronomical 
		// BPS false-positives during standard OS stub-resolver burst phases.
		// Modern browsers routinely fire 30-50 concurrent queries, which when artificially 
		// padded via EDNS0 over DoH (e.g., 468 bytes), can easily exceed 20KB instantaneously.
		// Note: The absolute accumulated bytes are explicitly NOT evaluated against the 
		// BPS threshold here, ensuring high-velocity micro-payloads are correctly apprehended.
		if b.recentBytes >= 32768 {
			evalBaseline := b.emaBps
			if evalBaseline == 0 {
				// Cold-start seeding: a bucket that has not yet completed a full
				// 1-second EMA tick has no historical baseline of its own, so the
				// configured MinThresholdBPS floor stands in as the comparison
				// baseline for this single evaluation.
				evalBaseline = threshold
			}
			
			if currentBPS > threshold && currentBPS > (evalBaseline*multiplier) {
				anomalous = true
				b.recentBytes = 0
				b.lastUpdate = now
			}
		}
	}

	// -----------------------------------------------------------------------
	// 5. Strike Enforcement & Blackholing
	// -----------------------------------------------------------------------
	if anomalous {
		b.strikes++
		if cfg.Server.Exfiltration.PenaltyBox.Enabled && b.strikes >= cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold {
			banMins := cfg.Server.Exfiltration.PenaltyBox.BanDurationMin
			if banMins <= 0 {
				banMins = 15
			}
			banUntil := now + (int64(banMins) * 60 * 1e9)
			b.bannedUntil = banUntil
			b.lastLog = now

			// Elevate the offender into the lock-free Fast-Path
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

// runExfilSweeper periodically cleans out inactive client telemetry structures,
// freeing RAM across the internal shards natively.
func runExfilSweeper() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			horizonNanos := now - int64(5*time.Minute)

			// Clean Fast-Path allocations directly per shard organically
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

			// Clean Slow-Path telemetry allocations
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

