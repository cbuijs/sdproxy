/*
File:    exfiltration.go
Version: 1.9.0
Updated: 07-May-2026 12:48 CEST

Description:
  Volumetric baseline profiling for DNS tunneling and covert exfiltration detection.
  Implements a high-performance, sharded, lock-free Exponential Moving Average (EMA) 
  byte-tracker per client IP address or subnet prefix.

  Tracks real-time bandwidth limits across UDP/TCP/QUIC and dynamically intercepts 
  clients transmitting anomalous data volumes over port 53.

Changes:
  1.9.0 - [SECURITY] Shielded the EMA baseline calculator against NTP reverse clock drifts. 
          Prevents volumetric anomalies scaling astronomically (or stagnating infinitely) 
          if the system wall clock organically leaps backward during a micro-burst phase natively.
  1.8.0 - [SECURITY/FIX] Sealed a critical First-Tick EMA Poisoning vulnerability. 
          If a malicious client fired a massive micro-burst immediately upon connection, 
          the engine natively adopted the payload as their baseline (`emaBps = currentBps`), 
          permanently blinding the system to their tunnel. The inaugural EMA baseline 
          is now strictly capped by a mathematical multiplier.
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
	buckets map[string]*exfilBucket
}

// fastExfilBan provides lock-free verification for actively blackholed clients.
// Uses atomics to eliminate TOCTOU (Time-Of-Check to Time-Of-Use) vulnerabilities
// and map-contention during high-volume spoofing attacks.
type fastExfilBan struct {
	expires atomic.Int64
	lastLog atomic.Int64
}

var (
	exfilShards       [exfilShardCount]*exfilShard
	exfilHashSeed     maphash.Seed
	exfilExempt       []netip.Prefix
	fastExfilBox      sync.Map
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

	for i := 0; i < exfilShardCount; i++ {
		exfilShards[i] = &exfilShard{
			buckets: make(map[string]*exfilBucket),
		}
	}

	log.Printf("[EXFILTRATION] Active: Threshold %.0f BPS | Multiplier %.1fx | Action: %s",
		cfg.Server.Exfiltration.MinThresholdBPS, cfg.Server.Exfiltration.AnomalyMultiplier, cfg.Server.Exfiltration.Action)

	if cfg.Server.Exfiltration.PenaltyBox.Enabled {
		log.Printf("[EXFILTRATION] Penalty Box Enabled: Blackholing offenders for %d mins after %d strikes.",
			cfg.Server.Exfiltration.PenaltyBox.BanDurationMin, cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold)
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

// getExfilShard securely routes the client key to its designated Mutex bucket.
func getExfilShard(key string) *exfilShard {
	h := maphash.String(exfilHashSeed, key)
	return exfilShards[h&(exfilShardCount-1)]
}

// groupExfilIP masks the incoming IP address according to configured prefix lengths natively.
// This allows tracking volumetric constraints across entire Subnets (e.g., /24 or /64) 
// rather than just isolated client IPs.
func groupExfilIP(ipStr string, addr netip.Addr) string {
	if !addr.IsValid() {
		return ipStr
	}

	if addr.Is4() {
		bits := cfg.Server.Exfiltration.IPv4PrefixLength
		if bits <= 0 || bits > 32 {
			bits = 32
		}
		if bits == 32 {
			return ipStr
		}
		prefix, _ := addr.Prefix(bits)
		return prefix.Masked().Addr().String()
	} else if addr.Is6() {
		bits := cfg.Server.Exfiltration.IPv6PrefixLength
		if bits <= 0 || bits > 128 {
			bits = 128
		}
		if bits == 128 {
			return ipStr
		}
		prefix, _ := addr.Prefix(bits)
		return prefix.Masked().Addr().String()
	}

	return ipStr
}

// AnalyzeExfiltration evaluates the payload size of an incoming query against the client's historical
// baseline to identify data exfiltration. Uses an Alpha-smoothed Exponential Moving Average (EMA).
// Returns whether the request is allowed, if the client is actively blackholed, and the instantaneous BPS.
func AnalyzeExfiltration(clientIP string, addr netip.Addr, reqSize int) (allowed bool, isBanned bool, bps float64) {
	if clientIP == "" {
		return true, false, 0
	}

	key := groupExfilIP(clientIP, addr)

	// -----------------------------------------------------------------------
	// 1. Lock-free Fast-Path Verification
	// -----------------------------------------------------------------------
	// Natively intercepts and drops actively blackholed tunnelers using `sync.Map`.
	// Bypasses the Mutex operations entirely to preserve I/O capacity during floods.
	if entryRaw, ok := fastExfilBox.Load(key); ok {
		banEntry := entryRaw.(*fastExfilBan)
		nowNanos := time.Now().UnixNano()
		if nowNanos < banEntry.expires.Load() {
			last := banEntry.lastLog.Load()
			// Debounce logs atomically to prevent CPU/Disk I/O exhaustion
			if nowNanos-last > int64(10*time.Second) {
				if banEntry.lastLog.CompareAndSwap(last, nowNanos) {
					log.Printf("[EXFILTRATION] SECURITY: Silently dropping traffic from %s (IP is blackholed - Fast Path)", key)
				}
			}
			return false, true, 0
		}
		// Penalty expired, dynamically prune the Fast-Path. LoadAndDelete prevents race-condition miscounts.
		if _, loaded := fastExfilBox.LoadAndDelete(key); loaded {
			fastExfilBoxCount.Add(-1)
		}
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
		if len(shard.buckets) >= maxPerShard {
			for k := range shard.buckets {
				delete(shard.buckets, k)
				break
			}
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
				log.Printf("[EXFILTRATION] SECURITY: Silently dropping traffic from %s (IP is blackholed)", key)
			}
			return false, true, 0
		}
		// Natural expiration of the penalty box
		b.bannedUntil = 0
		b.strikes = 0
		log.Printf("[EXFILTRATION] SECURITY: Client/Subnet %s Penalty Box ban expired. Access restored.", key)
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
			b.emaBps = currentBPS
			// [SECURITY/FIX] Prevent initial massive floods from establishing a 
			// permanently high, unblockable baseline. Cap the inaugural EMA at 
			// 5x the minimum threshold.
			baselineCap := threshold * 5.0
			if b.emaBps > baselineCap {
				b.emaBps = baselineCap
			}
		} else {
			// EMA Math: (Alpha * Current) + ((1 - Alpha) * Historical)
			// Alpha = 0.2 provides substantial smoothing weight to historical norms, 
			// meaning sudden malicious spikes won't drag the baseline up quickly enough 
			// to mask the exfiltration attempt.
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
			// [SECURITY/FIX] Dynamically constrain the evaluation baseline if the payload 
			// burst occurs on the inaugural connection tick before EMA formulation completes.
			if evalBaseline == 0 {
				evalBaseline = currentBPS
				baselineCap := threshold * 5.0
				if evalBaseline > baselineCap {
					evalBaseline = baselineCap
				}
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
			if existingRaw, loaded := fastExfilBox.Load(key); loaded {
				existing := existingRaw.(*fastExfilBan)
				existing.expires.Store(banUntil)
			} else if fastExfilBoxCount.Load() < int32(cfg.Server.Exfiltration.MaxTrackedIPs) {
				fastEntry := &fastExfilBan{}
				fastEntry.expires.Store(banUntil)
				fastEntry.lastLog.Store(now)
				// Ensure atomicity so we don't bleed capacity bounds
				if existingConcurrent, loaded := fastExfilBox.LoadOrStore(key, fastEntry); !loaded {
					fastExfilBoxCount.Add(1)
				} else {
					existing := existingConcurrent.(*fastExfilBan)
					existing.expires.Store(banUntil)
				}
			}
			log.Printf("[EXFILTRATION] SECURITY: Client/Subnet %s instantly blackholed for %d mins (Exfiltration Detected)", key, banMins)
			return false, true, currentBPS
		}
		return false, false, currentBPS
	}

	return true, false, currentBPS
}

// runExfilSweeper periodically cleans out inactive client telemetry structures,
// freeing RAM across the 256 internal shards.
func runExfilSweeper() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().UnixNano()
		horizonNanos := now - int64(5*time.Minute)

		fastExfilBox.Range(func(key, value any) bool {
			if now > value.(*fastExfilBan).expires.Load() {
				if _, loaded := fastExfilBox.LoadAndDelete(key); loaded {
					fastExfilBoxCount.Add(-1)
				}
			}
			return true
		})

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
	}
}

