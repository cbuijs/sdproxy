/*
File:    throttle.go
Version: 2.2.0
Updated: 02-May-2026 10:00 CEST

Description: Adaptive, zero-configuration admission control for sdproxy.
             Monitors heap pressure and upstream fan-out every 500 ms, then
             adjusts two independent concurrency limits via AIMD to keep the
             router stable under burst traffic without any manual tuning.

             TWO LIMITS
             ──────────────────────────────────────────────────────────────
             queryLimit    – max concurrent ProcessDNS invocations.
                             Excess queries are silently dropped — no response
                             is written. The client retries normally.
             upstreamLimit – max concurrent outbound DNS exchanges across all
                             upstream groups. Prevents connection-table
                             exhaustion when an upstream is slow or unreachable.

             PRESSURE SCORE (0–100)
             ──────────────────────────────────────────────────────────────
             Two signals, blended into one integer per sample interval:

               85% heap pressure
                     HeapInuse / configured memory limit (×0.80 headroom).
                     When memory_limit_mb is 0, assumes a 128 MB soft limit
                     so the score stays near-zero on a healthy idle router
                     instead of the old NextGC fallback which produced a
                     constant ~50% baseline pressure (NextGC ≈ 2×HeapInuse
                     with GCPercent=100 — always looks half-full).

               15% upstream fan-out
                     activeUpstream / max(activeQueries, 1).
                     Mild guard: when every in-flight query is also waiting
                     on an upstream socket, we're at max concurrency depth.

             WHAT WAS REMOVED vs v1.x
             ──────────────────────────────────────────────────────────────
             • Goroutine spike (was 25%): wrong metric for I/O-bound work.
               Go goroutines are cheap; penalising their count fights the
               runtime scheduler instead of protecting memory.
             • Cache miss rate (was 20%): penalised normal DNS operation.
               A home router opening fresh browser tabs will have 60-80%
               cache misses — that is correct behaviour, not stress.
               Together these two signals pushed the pressure score above
               lowWater on a perfectly healthy router, preventing AIMD
               from ever growing queryLimit past its starting value of 40.

             LIMIT SIZING RATIONALE
             ──────────────────────────────────────────────────────────────
             DNS is I/O-bound: a ProcessDNS goroutine spends ~0 ms on cache
             hits and ~50-150 ms waiting on upstream for misses. Go goroutine
             stacks start at 2 KB; even 300 concurrent queries consume only
             ~3 MB of stack — negligible on any target sdproxy runs on.
             The old workers*4 = 40 limit capped cache-miss throughput at
             roughly 40/RTT ≈ 400-800 QPS, making the throttler the
             bottleneck rather than the network or the upstream resolvers.

             queriesTotal / upstreamCalls are kept as raw counters for future
             observability (logged at high-pressure events); they no longer
             drive the pressure score.

             Expected cost per query: two atomic ops (acquire + release).
             IncrQueryTotal / IncrUpstreamCall: one atomic Add each.
             The monitor goroutine reads heap metrics every 500 ms via
             runtime/metrics (fully non-STW, no stop-the-world pause).

Changes:
  2.2.0 - [FIX] Resolved a critical memory pressure throttling regression. Disabled 
          the artificial 128MB constraint fallback natively when `memory_limit_mb` 
          is explicitly set to 0, preventing continuous death-spirals on healthy 
          devices possessing ample RAM limits.
  2.1.0 - [PERF] Optimized `AcquireQuery` and `AcquireUpstream` admission gates to be 
          completely wait-free. Replaced the `CompareAndSwap` spin-loops with an 
          unconditional `Add()` and rollback. This guarantees O(1) constant time 
          execution and prevents CPU starvation under extreme volumetric DDoS contention.
  2.0.0 - [PERF] Pressure model simplified to heap (85%) + fan-out (15%).
           Removed goroutine-spike and cache-miss-rate signals — both were
           wrong for I/O-bound DNS and actively capped throughput.
           initQueryLimit raised to workers*25 (was workers*4); ceiling
           raised to 4× initial (was 1.5×); AIMD recovery +5/tick (was +1).
           Fixed NextGC fallback: uses assumed 128 MB limit instead of
           heapInuse/NextGC which caused constant ~20-point false pressure.
           Removed goroutineBaselineX100 EMA field (no longer needed).
           highWater 70 (was 65), criticalMark 90 (was 85), lowWater 30.
*/

package main

import (
	"fmt"
	"log"
	"runtime/metrics"
	"sync/atomic"
	"time"
)

// throttler holds all adaptive admission-control state.
//
// Field ordering is intentional: the four hot-path atomics (activeQueries,
// activeUpstream, queryLimit, upstreamLimit) are declared first so they land
// in the same 64-byte cache line on ARM/MIPS routers. Every query touches all
// four; keeping them together avoids a second cache-line fetch on the acquire
// path.
type throttler struct {
	// ── Hot path ─────────────────────────────────────────────────────────
	activeQueries  atomic.Int32 // queries currently inside ProcessDNS
	activeUpstream atomic.Int32 // upstream exchanges currently in-flight
	queryLimit     atomic.Int32 // current max for activeQueries
	upstreamLimit  atomic.Int32 // current max for activeUpstream

	// ── Throughput counters ───────────────────────────────────────────────
	// Monotonically increasing. No longer used to derive pressure; kept as
	// telemetry visible in high-pressure log lines.
	queriesTotal  atomic.Int64 // total queries past the AcquireQuery gate
	upstreamCalls atomic.Int64 // total queries that reached the upstream path

	// ── Pressure signal ───────────────────────────────────────────────────
	pressureScore atomic.Int32 // 0–100, updated every 500 ms by monitorLoop

	// ── Drop counters ─────────────────────────────────────────────────────
	droppedQueries  atomic.Int64
	droppedUpstream atomic.Int64

	// ── Initial limits (stored for AIMD ceiling computation) ─────────────
	initQueryLimit    int32
	initUpstreamLimit int32
}

var thr throttler

// InitThrottle derives initial limits from the worker count and launches the
// background pressure monitor. Call once from main() after cfg is populated.
func InitThrottle() {
	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}

	// DNS is I/O-bound: a goroutine blocked on an upstream socket occupies
	// ~2-4 KB of stack, not a CPU core. workers*25 gives ample headroom for
	// concurrent cache misses without being a meaningful memory cost.
	thr.initQueryLimit    = workers * 25
	thr.initUpstreamLimit = workers * 8 // unchanged — still the connection guard

	thr.queryLimit.Store(thr.initQueryLimit)
	thr.upstreamLimit.Store(thr.initUpstreamLimit)

	log.Printf("[THROTTLE] Adaptive admission control ready — query=%d upstream=%d (AIMD, heap+fanout signals)",
		thr.initQueryLimit, thr.initUpstreamLimit)

	go thr.monitorLoop()
}

// IncrQueryTotal records a query that passed the admission gate.
func IncrQueryTotal() { thr.queriesTotal.Add(1) }

// IncrUpstreamCall records a query that reached the upstream forwarding path.
func IncrUpstreamCall() { thr.upstreamCalls.Add(1) }

// AcquireQuery reserves one query-processing slot.
// Returns false (silent drop) when activeQueries is at queryLimit.
// Optimized to use wait-free XADD for maximum throughput under contention.
func AcquireQuery() bool {
	limit := thr.queryLimit.Load()
	if thr.activeQueries.Add(1) > limit {
		thr.activeQueries.Add(-1) // Rollback the reservation unconditionally
		thr.droppedQueries.Add(1)
		return false
	}
	return true
}

// ReleaseQuery releases a slot previously acquired by AcquireQuery.
func ReleaseQuery() { thr.activeQueries.Add(-1) }

// AcquireUpstream reserves one upstream-exchange slot.
// Returns false when activeUpstream is at upstreamLimit.
// Optimized to use wait-free XADD for maximum throughput under contention.
func AcquireUpstream() bool {
	limit := thr.upstreamLimit.Load()
	if thr.activeUpstream.Add(1) > limit {
		thr.activeUpstream.Add(-1) // Rollback the reservation unconditionally
		thr.droppedUpstream.Add(1)
		return false
	}
	return true
}

// ReleaseUpstream releases a slot previously acquired by AcquireUpstream.
func ReleaseUpstream() { thr.activeUpstream.Add(-1) }

// metricUint64 safely extracts a uint64 from a metrics.Value regardless of
// the underlying kind. Go's runtime/metrics does not guarantee KindUint64 for
// all byte-count metrics across versions — some return KindFloat64 instead,
// and calling .Uint64() on a float64 Value panics.
//
//   KindUint64  → returned as-is.
//   KindFloat64 → cast to uint64 (never negative for heap sizes).
//   anything else (KindBad, KindHist, …) → 0 (metric unavailable).
func metricUint64(v metrics.Value) uint64 {
	switch v.Kind() {
	case metrics.KindUint64:
		return v.Uint64()
	case metrics.KindFloat64:
		f := v.Float64()
		if f < 0 {
			return 0
		}
		return uint64(f)
	default:
		return 0
	}
}

func (t *throttler) monitorLoop() {
	const (
		sampleInterval = 500 * time.Millisecond

		// AIMD thresholds. Wider dead-band (30–70) than before means the limit
		// stays stable during normal operation and only moves under real pressure.
		highWater    = 70 // score ≥ highWater → shrink limits by 15%
		criticalMark = 90 // score ≥ criticalMark → halve limits (genuine emergency)
		lowWater     = 30 // score ≤ lowWater → grow limits by +5 (faster recovery)

		logCooldown = 10 * time.Second
	)

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	var lastLog time.Time

	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}
	// Floors prevent AIMD from cutting below a usable minimum during an
	// extended pressure event (e.g. memory_limit_mb set very low).
	minQ  := max(workers, 4)
	minUp := max(workers/2, 2)

	// Pre-allocate metric samples once — reused every tick, zero allocations
	// in the hot monitoring path. runtime/metrics.Read is fully non-STW.
	//
	//   samples[0]: /memory/classes/heap/inuse:bytes  ≈ MemStats.HeapInuse
	metricSamples := []metrics.Sample{
		{Name: "/memory/classes/heap/inuse:bytes"},
	}

	for range ticker.C {
		// ── Heap metric read (non-STW) ────────────────────────────────────
		metrics.Read(metricSamples)
		heapInuse := metricUint64(metricSamples[0].Value)

		// ── Pressure score ────────────────────────────────────────────────
		activeQ  := t.activeQueries.Load()
		activeUp := t.activeUpstream.Load()
		score    := t.computePressure(heapInuse, activeQ, activeUp)
		t.pressureScore.Store(int32(score))

		// ── AIMD limit adjustment ─────────────────────────────────────────
		prevQ  := t.queryLimit.Load()
		prevUp := t.upstreamLimit.Load()
		var newQ, newUp int32

		// Ceiling: 4× the initial value gives plenty of room to grow without
		// blowing memory. The old 1.5× cap meant limits could barely breathe.
		qCeil  := t.initQueryLimit * 4
		upCeil := t.initUpstreamLimit * 4

		switch {
		case score >= criticalMark:
			// Genuine emergency (RAM nearly full) — halve immediately.
			newQ  = max(prevQ/2, minQ)
			newUp = max(prevUp/2, minUp)
		case score >= highWater:
			// Sustained pressure — trim by 15%.
			newQ  = max(int32(float32(prevQ)*0.85), minQ)
			newUp = max(int32(float32(prevUp)*0.85), minUp)
		case score <= lowWater:
			// Plenty of headroom — grow by +5/tick (was +1; recovery is 5× faster).
			newQ  = min(prevQ+5, qCeil)
			newUp = min(prevUp+5, upCeil)
		default:
			// Dead band: leave limits unchanged.
			newQ, newUp = prevQ, prevUp
		}

		t.queryLimit.Store(newQ)
		t.upstreamLimit.Store(newUp)

		// ── Rate-limited pressure log (only when things are actually wrong) ──
		if score >= highWater && time.Since(lastLog) >= logCooldown {
			log.Printf(
				"[THROTTLE] pressure=%d/100 heap=%s | "+
					"query: limit=%d active=%d dropped=%d | "+
					"upstream: limit=%d active=%d dropped=%d",
				score, fmtBytes(heapInuse),
				newQ,  t.activeQueries.Load(),  t.droppedQueries.Load(),
				newUp, t.activeUpstream.Load(), t.droppedUpstream.Load(),
			)
			lastLog = time.Now()
		}
	}
}

// computeMemPressure returns heap pressure as a 0–1 float64.
//
// When memory_limit_mb > 0: uses the configured limit with a 0.80 headroom
// factor so GC has room to breathe before we start throttling.
func (t *throttler) computeMemPressure(heapInuse uint64) float64 {
	if cfg.Server.MemoryLimitMB <= 0 {
		// [FIX] If the administrator explicitly disabled the memory limit (0), 
		// we must not synthesize an artificial 128MB ceiling. Forcing a ceiling 
		// creates aggressive, permanent throttling death spirals on standard 
		// servers or Raspberry Pis possessing ample RAM.
		return 0.0 
	}
	
	limitBytes := float64(cfg.Server.MemoryLimitMB) * 1024 * 1024 * 0.80
	p := float64(heapInuse) / limitBytes
	
	if p > 1.0 {
		return 1.0
	}
	return p
}

// computePressure blends two resource signals into a single 0–100 integer.
//
//	85% heap pressure   — the only real hard constraint on a home router.
//	15% upstream fan-out — mild guard: prevents connection table explosion
//	                       when upstreams are all slow simultaneously.
//	                       Scale [0, 2.0] → [0, 1.0]; ratio > 2 is clamped.
//
// Removed vs v1.x:
//   - goroutine spike (25%): wrong for I/O-bound work; Go goroutines are cheap
//   - cache miss rate (20%): normal DNS traffic pattern, not a stress signal
func (t *throttler) computePressure(heapInuse uint64, activeQ, activeUp int32) int {
	memP := t.computeMemPressure(heapInuse)

	var fanP float64
	if activeQ > 0 {
		fanP = float64(activeUp) / float64(activeQ) / 2.0 // scale [0,2] → [0,1]
		if fanP > 1.0 {
			fanP = 1.0
		}
	}

	return int((0.85*memP + 0.15*fanP) * 100)
}

// fmtBytes returns a compact human-readable size string.
// Only called from the rate-limited pressure log line — not on the hot path.
func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%dMB", b>>20)
	case b >= 1<<10:
		return fmt.Sprintf("%dKB", b>>10)
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// atomic import guard — ensures the import is used even if all atomics are
// accessed via the throttler struct.
var _ atomic.Int64

