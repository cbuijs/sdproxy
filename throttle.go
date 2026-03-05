/*
File: throttle.go
Version: 1.0.0
Last Updated: 2026-03-05 19:00 CET
Description: Adaptive, zero-configuration admission control for sdproxy.
             Monitors goroutine count and heap pressure every 500 ms, then
             adjusts two independent concurrency limits via AIMD to keep the
             router stable under burst traffic without any manual tuning.

             TWO LIMITS
             ──────────────────────────────────────────────────────────────
             queryLimit    – max concurrent ProcessDNS invocations.
                             Excess queries are silently dropped — no response
                             is written. The client times out normally and
                             retries, without any error state being set on
                             its end. Safer than SERVFAIL which some
                             resolvers treat as a permanent failure signal.
             upstreamLimit – max concurrent outbound DNS exchanges across
                             all upstream groups. Prevents connection-table
                             exhaustion and goroutine-stack memory explosion
                             when an upstream is slow or unreachable.

             PRESSURE SCORE (0–100)
             ──────────────────────────────────────────────────────────────
             Three signals, blended into one integer per sample interval:

               50% heap pressure
                     HeapInuse / configured memory limit (×0.80 headroom),
                     or HeapInuse / NextGC when no limit is set.
                     Most reliable signal; directly bounded.

               30% goroutine spike
                     (current − baseline) / (baseline × 8).
                     Baseline is the average goroutine count during the
                     first 30 s of uptime ("warm but idle"). Each goroutine
                     has a ~2–8 KB initial stack; spikes matter on routers.

               20% upstream fill ratio
                     activeUpstream / upstreamLimit.
                     Feeds back directly: rising upstream pressure is a
                     leading indicator of slow upstreams before heap spikes.

             AIMD RESPONSE TABLE
             ──────────────────────────────────────────────────────────────
             score ≤ 40    additive increase   limit += 1
                                               ceiling: 1.5× initial value
             41–64         hold steady         no change
             65–84         moderate back-off   limit ×= 0.80
             ≥ 85          aggressive back-off limit ×= 0.50
                                               floor: worker count (queries)
                                                      worker count / 2 (upstream)

             HOT-PATH OVERHEAD
             ──────────────────────────────────────────────────────────────
             AcquireQuery / AcquireUpstream are lock-free CAS loops.
             Expected cost per query: two atomic ops (acquire + release).
             The monitor goroutine calls runtime.ReadMemStats every 500 ms
             (brief STW, ~1 µs); all query goroutines are unaffected.

Changes:
  1.0.0 - Initial implementation.
*/

package main

import (
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"time"
)

// throttler holds all adaptive admission-control state.
//
// Field ordering is intentional: the four hot-path atomics (activeQueries,
// activeUpstream, queryLimit, upstreamLimit) are declared first so they land
// in the same 64-byte cache line on ARM/MIPS routers. Every query touches all
// four; keeping them together avoids a second cache-line fetch.
type throttler struct {
	// ── Hot path ─────────────────────────────────────────────────────────
	// Read and written on every query and every upstream exchange.
	activeQueries  atomic.Int32 // queries currently inside ProcessDNS
	activeUpstream atomic.Int32 // upstream exchanges currently in-flight
	queryLimit     atomic.Int32 // current max for activeQueries
	upstreamLimit  atomic.Int32 // current max for activeUpstream

	// ── Pressure signal ───────────────────────────────────────────────────
	// Written by the monitor goroutine; read by the rate-limited log line.
	pressureScore atomic.Int32 // 0–100, updated every 500 ms

	// ── Drop counters ─────────────────────────────────────────────────────
	// Incremented when Acquire returns false; never reset.
	// Reported in the pressure log line so trends are visible without noise.
	droppedQueries  atomic.Int64
	droppedUpstream atomic.Int64

	// ── Baseline learning ─────────────────────────────────────────────────
	// Goroutine count averaged over the first 30 s of uptime.
	// Written once when baselineLearned flips to true; read-only after that.
	goroutineBaseline atomic.Int32
	baselineLearned   atomic.Bool

	// ── Initial limits ────────────────────────────────────────────────────
	// Snapshotted at InitThrottle time. Used as the recovery ceiling and to
	// compute the absolute floor. Plain int32 — written once, no sync needed.
	initQueryLimit    int32
	initUpstreamLimit int32
}

// thr is the package-level singleton. Direct access (no pointer indirection)
// keeps the hot-path CAS ops as cheap as possible.
var thr throttler

// InitThrottle derives initial limits from the worker count and launches the
// background pressure monitor. Call once from main() after cfg is populated.
func InitThrottle() {
	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}

	// Start generous: allow 4× workers concurrent queries and 2× workers
	// concurrent upstream exchanges. The monitor backs these off under pressure
	// and restores them (up to 1.5× these values) once resources free up.
	thr.initQueryLimit    = workers * 4
	thr.initUpstreamLimit = workers * 2

	thr.queryLimit.Store(thr.initQueryLimit)
	thr.upstreamLimit.Store(thr.initUpstreamLimit)

	log.Printf("[THROTTLE] Adaptive admission control ready — query=%d upstream=%d (AIMD, no config needed)",
		thr.initQueryLimit, thr.initUpstreamLimit)

	go thr.monitorLoop()
}

// AcquireQuery reserves one query-processing slot.
//
// Returns false when activeQueries is at queryLimit — the caller must return
// immediately without writing any response (silent drop). The client will
// time out and retry naturally; no error state is set on the client side.
// Non-blocking: uses a CAS loop with no channels and no mutexes.
// Expected fast-path cost: one Load + one successful CAS = ~2 atomic ops.
func AcquireQuery() bool {
	limit := thr.queryLimit.Load()
	for {
		cur := thr.activeQueries.Load()
		if cur >= limit {
			thr.droppedQueries.Add(1)
			return false
		}
		if thr.activeQueries.CompareAndSwap(cur, cur+1) {
			return true
		}
		// CAS missed: another goroutine changed the counter; retry immediately.
		// Contention windows are nanosecond-scale on a DNS proxy — no sleep needed.
	}
}

// ReleaseQuery releases a slot previously acquired by AcquireQuery.
// Always defer this immediately after a successful AcquireQuery.
func ReleaseQuery() { thr.activeQueries.Add(-1) }

// AcquireUpstream reserves one upstream-exchange slot.
//
// Returns false when activeUpstream is at upstreamLimit. The caller should
// return an error so raceExchange/sequentialExchange can surface a SERVFAIL.
func AcquireUpstream() bool {
	limit := thr.upstreamLimit.Load()
	for {
		cur := thr.activeUpstream.Load()
		if cur >= limit {
			thr.droppedUpstream.Add(1)
			return false
		}
		if thr.activeUpstream.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// ReleaseUpstream releases a slot previously acquired by AcquireUpstream.
func ReleaseUpstream() { thr.activeUpstream.Add(-1) }

// monitorLoop runs in a dedicated goroutine. Every 500 ms it:
//  1. Samples goroutine count and heap stats.
//  2. Computes a 0–100 pressure score.
//  3. Adjusts queryLimit and upstreamLimit via AIMD.
//  4. Emits a log line at most once per 10 s when pressure is elevated.
func (t *throttler) monitorLoop() {
	const (
		sampleInterval = 500 * time.Millisecond
		baselineWindow = 30 * time.Second  // collect goroutine samples for this long
		lowWater       = 40                // score below which limits grow
		highWater      = 65                // score above which limits shrink
		criticalMark   = 85                // score triggering aggressive halving
		logCooldown    = 10 * time.Second  // minimum gap between [THROTTLE] pressure lines
	)

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	start      := time.Now()
	lastLog    := time.Time{}
	gorSamples := make([]int, 0, 64) // accumulates goroutine counts during baseline window

	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}
	// Absolute floor — limits never drop below these regardless of pressure,
	// so the proxy always has headroom equal to its own worker pool.
	minQ  := max(workers, 4)
	minUp := max(workers/2, 2)

	for range ticker.C {

		// ── 1. Goroutine baseline learning ────────────────────────────────
		//
		// We learn what "normal" looks like over the first 30 s rather than
		// hard-coding a threshold. This makes the signal self-calibrating for
		// both tiny 32-MB routers and full-size Linux boxes.
		goroutines := int32(runtime.NumGoroutine())
		if !t.baselineLearned.Load() {
			gorSamples = append(gorSamples, int(goroutines))
			if time.Since(start) >= baselineWindow && len(gorSamples) > 0 {
				sum := 0
				for _, v := range gorSamples {
					sum += v
				}
				baseline := int32(sum / len(gorSamples))
				if baseline < 5 {
					baseline = 5
				}
				t.goroutineBaseline.Store(baseline)
				t.baselineLearned.Store(true)
				gorSamples = nil // release backing array; no longer needed
				log.Printf("[THROTTLE] Goroutine baseline learned: %d (from %d samples over 30 s)",
					baseline, len(gorSamples)+1)
			}
		}

		// ── 2. Heap memory snapshot ───────────────────────────────────────
		//
		// runtime.ReadMemStats causes a brief stop-the-world (~1 µs in Go ≥1.15).
		// Calling it once per 500 ms from a background goroutine is negligible.
		// We read HeapInuse (memory committed to in-use spans) and NextGC
		// (heap size target for the next GC cycle — a natural capacity signal).
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		// ── 3. Pressure score ─────────────────────────────────────────────
		score := t.computePressure(goroutines, ms.HeapInuse, ms.NextGC)
		t.pressureScore.Store(int32(score))

		// ── 4. AIMD limit adjustment ──────────────────────────────────────
		prevQ  := t.queryLimit.Load()
		prevUp := t.upstreamLimit.Load()
		var newQ, newUp int32

		switch {
		case score >= criticalMark:
			// Router is under serious pressure — halve both limits immediately.
			newQ  = max(prevQ/2,                             minQ)
			newUp = max(prevUp/2,                            minUp)

		case score >= highWater:
			// Sustained elevated pressure — reduce by 20 % (multiplicative decrease).
			newQ  = max(int32(float32(prevQ) *0.80), minQ)
			newUp = max(int32(float32(prevUp)*0.80), minUp)

		case score <= lowWater:
			// Resources are healthy — grow by 1 (additive increase).
			// Cap at 1.5× the initial value to stay conservative during recovery.
			newQ  = min(prevQ+1,  t.initQueryLimit+t.initQueryLimit/2)
			newUp = min(prevUp+1, t.initUpstreamLimit+t.initUpstreamLimit/2)

		default:
			// Score is between the watermarks — hold steady.
			newQ, newUp = prevQ, prevUp
		}

		t.queryLimit.Store(newQ)
		t.upstreamLimit.Store(newUp)

		// ── 5. Rate-limited pressure log ──────────────────────────────────
		//
		// Only emitted when pressure is elevated and enough time has passed
		// since the last line. Keeps logs quiet during normal operation while
		// giving clear visibility during incidents.
		if score >= highWater && time.Since(lastLog) >= logCooldown {
			log.Printf(
				"[THROTTLE] pressure=%d/100 goroutines=%d heap=%s nextGC=%s | "+
					"query: limit=%d active=%d dropped=%d | "+
					"upstream: limit=%d active=%d dropped=%d",
				score, goroutines, fmtBytes(ms.HeapInuse), fmtBytes(ms.NextGC),
				newQ,  t.activeQueries.Load(),  t.droppedQueries.Load(),
				newUp, t.activeUpstream.Load(), t.droppedUpstream.Load(),
			)
			lastLog = time.Now()
		}
	}
}

// computePressure blends three resource signals into a single 0–100 integer.
// All three components are clamped to [0, 1] before weighting so no single
// signal can dominate beyond its assigned weight.
func (t *throttler) computePressure(goroutines int32, heapInuse, nextGC uint64) int {

	// ── Heap pressure (weight 0.50) ───────────────────────────────────────
	//
	// Primary signal. Two sub-cases:
	//   a) memory_limit_mb is set  → pressure against 80% of the hard ceiling.
	//      We leave a 20% GC runway before we hit the wall, so we start
	//      throttling while the GC can still keep up rather than after.
	//   b) no hard limit           → HeapInuse / NextGC.
	//      When heap approaches the GC trigger target, allocations slow down;
	//      this catches the same moment from the GC scheduler's perspective.
	var memP float32
	if cfg.Server.MemoryLimitMB > 0 {
		limit := float32(cfg.Server.MemoryLimitMB) * 1024 * 1024 * 0.80
		if limit > 0 {
			memP = float32(heapInuse) / limit
		}
	} else if nextGC > 0 {
		memP = float32(heapInuse) / float32(nextGC)
	}
	if memP > 1.0 {
		memP = 1.0
	}

	// ── Goroutine pressure (weight 0.30) ──────────────────────────────────
	//
	// Scales from 0 at the learned baseline to 1.0 at baseline×8.
	// Example: baseline of 30 → full goroutine pressure at 240 goroutines.
	// Each blocked goroutine holds a 2–8 KB stack; a spike to 8× baseline
	// on a 32 MB router is genuinely critical.
	//
	// Before the baseline is learned (first 30 s) we use a conservative
	// fallback: 0 below 50 goroutines, full pressure at 500.
	var gorP float32
	baseline := t.goroutineBaseline.Load()
	if t.baselineLearned.Load() && baseline > 0 {
		if goroutines > baseline {
			gorP = float32(goroutines-baseline) / float32(baseline*8)
		}
	} else {
		if goroutines > 50 {
			gorP = float32(goroutines-50) / 450.0
		}
	}
	if gorP > 1.0 {
		gorP = 1.0
	}

	// ── Upstream fill ratio (weight 0.20) ─────────────────────────────────
	//
	// Leading indicator: upstream exchanges saturating their limit predicts
	// an imminent goroutine and heap spike before it shows in the other two
	// signals. Weighting it at 20% gives early warning without over-reacting
	// to momentary bursts.
	var upP float32
	if ul := t.upstreamLimit.Load(); ul > 0 {
		upP = float32(t.activeUpstream.Load()) / float32(ul)
	}
	if upP > 1.0 {
		upP = 1.0
	}

	return int((0.50*memP + 0.30*gorP + 0.20*upP) * 100)
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

