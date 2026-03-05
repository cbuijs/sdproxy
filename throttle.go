/*
File: throttle.go
Version: 1.1.0
Last Updated: 2026-03-05 21:00 CET
Description: Adaptive, zero-configuration admission control for sdproxy.
             Monitors goroutine count and heap pressure every 500 ms, then
             adjusts two independent concurrency limits via AIMD to keep the
             router stable under burst traffic without any manual tuning.

             TWO LIMITS
             ──────────────────────────────────────────────────────────────
             queryLimit    – max concurrent ProcessDNS invocations.
                             Excess queries are silently dropped — no
                             response is written. The client times out
                             normally and retries without any error state
                             being set on its end.
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
                     Baseline is a continuous EMA (α=0.02, τ≈25 s) of the
                     goroutine count, updated only while heap pressure is
                     below 40%. This means:
                       • The baseline includes all library goroutines
                         (quic-go, http2, miekg/dns) at normal load —
                         runtime.NumGoroutine() is process-wide and
                         cannot be filtered by package.
                       • The baseline naturally adapts as traffic patterns
                         change over time (more DoH clients = more http2
                         goroutines = higher baseline = no false alarms).
                       • The baseline freezes during pressure events so
                         the spike signal stays meaningful when it matters.
                     Contrast with v1.0.0 which used a one-shot 30 s
                     startup window when the server was idle — that
                     baseline was always too low because no library
                     goroutines had been spawned yet.

               20% upstream fill ratio
                     activeUpstream / upstreamLimit.
                     Leading indicator: upstream saturation predicts heap
                     and goroutine spikes before they materialise.

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
             (brief STW pause, ~1 µs on Go ≥ 1.15); query goroutines are
             not affected.

Changes:
  1.1.0 - [FIX]  Replaced one-shot 30 s startup goroutine baseline with a
           continuous EMA (α=0.02, τ≈25 s) updated only while heap pressure
           is below 40%. The old baseline was learned while the server was
           idle, so it never included quic-go/http2/miekg goroutines and
           caused false goroutine-spike alarms under normal load.
           The EMA approach makes the baseline self-calibrating: it tracks
           "what normal looks like right now" and freezes automatically
           during pressure events. Removed baselineLearned flag and
           gorSamples accumulator — simpler and more correct.
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
	activeQueries  atomic.Int32 // queries currently inside ProcessDNS
	activeUpstream atomic.Int32 // upstream exchanges currently in-flight
	queryLimit     atomic.Int32 // current max for activeQueries
	upstreamLimit  atomic.Int32 // current max for activeUpstream

	// ── Pressure signal ───────────────────────────────────────────────────
	pressureScore atomic.Int32 // 0–100, updated every 500 ms

	// ── Drop counters ─────────────────────────────────────────────────────
	droppedQueries  atomic.Int64
	droppedUpstream atomic.Int64

	// ── Goroutine baseline — continuous EMA ───────────────────────────────
	// Updated every 500 ms tick, but ONLY when heap pressure is below 40%.
	// Stored as a fixed-point integer (actual value × 100) so it can live in
	// an atomic without a mutex. The monitor goroutine is the only writer;
	// computePressure reads it. Using ×100 gives two decimal places of
	// precision for the EMA without needing float64.
	//
	// Why freeze on pressure? When the server is under load the goroutine
	// count is elevated — updating the baseline then would permanently raise
	// it and blind the spike detector to genuine problems. Freezing preserves
	// the "what normal looks like" reference.
	goroutineBaselineX100 atomic.Int64 // baseline × 100; 0 = not yet set

	// ── Initial limits ────────────────────────────────────────────────────
	initQueryLimit    int32
	initUpstreamLimit int32
}

var thr throttler

// emaAlpha is the EMA smoothing factor. At a 500 ms tick rate:
//   τ = tick_interval / α = 500 ms / 0.02 = 25 s
// So the baseline tracks a ~25 s exponential moving average of the goroutine
// count during healthy periods — long enough to ignore short bursts, short
// enough to adapt to genuine shifts in library goroutine counts over minutes.
const emaAlpha = float64(0.02)

// InitThrottle derives initial limits from the worker count and launches the
// background pressure monitor. Call once from main() after cfg is populated.
func InitThrottle() {
	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}

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
	}
}

// ReleaseQuery releases a slot previously acquired by AcquireQuery.
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
//  1. Samples goroutine count and heap stats via runtime.ReadMemStats.
//  2. Updates the EMA goroutine baseline when heap is healthy (< 40 % pressure).
//  3. Computes a 0–100 pressure score.
//  4. Adjusts queryLimit and upstreamLimit via AIMD.
//  5. Emits a log line at most once per 10 s when pressure is elevated.
func (t *throttler) monitorLoop() {
	const (
		sampleInterval  = 500 * time.Millisecond
		highWater       = 65  // score above which limits shrink
		criticalMark    = 85  // score triggering aggressive halving
		lowWater        = 40  // score below which limits grow
		baselineFreezeP = 0.40 // heap pressure fraction above which EMA freezes
		logCooldown     = 10 * time.Second
	)

	ticker  := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	var lastLog time.Time

	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}
	minQ  := max(workers, 4)
	minUp := max(workers/2, 2)

	for range ticker.C {

		goroutines := int32(runtime.NumGoroutine())

		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		// ── 1. Compute heap pressure first — needed for EMA freeze decision ─
		memP := t.computeMemPressure(ms.HeapInuse, ms.NextGC)

		// ── 2. EMA goroutine baseline update ─────────────────────────────────
		//
		// Only update when heap is healthy. This ensures the baseline reflects
		// "normal operating goroutine count" (which includes all library
		// goroutines from quic-go, http2, miekg, etc. at typical load) and
		// not a burst or pressure event.
		//
		// First sample: store directly (no prior data to average with).
		// Subsequent samples: apply EMA with α=0.02.
		//
		// Stored as int64 × 100 to keep fixed-point precision in an atomic.
		if memP < baselineFreezeP {
			prev := t.goroutineBaselineX100.Load()
			gorX100 := int64(goroutines) * 100
			if prev == 0 {
				// First sample — set directly so the baseline is immediately useful.
				t.goroutineBaselineX100.Store(gorX100)
			} else {
				// EMA: new = prev×(1−α) + current×α
				newVal := int64(float64(prev)*(1-emaAlpha) + float64(gorX100)*emaAlpha)
				if newVal < 500 { // floor: 5.00 goroutines × 100
					newVal = 500
				}
				t.goroutineBaselineX100.Store(newVal)
			}
		}
		// When memP >= baselineFreezeP: baseline stays frozen at its last
		// healthy value so the goroutine spike signal remains calibrated.

		// ── 3. Full pressure score ────────────────────────────────────────────
		score := t.computePressure(goroutines, memP)
		t.pressureScore.Store(int32(score))

		// ── 4. AIMD limit adjustment ──────────────────────────────────────────
		prevQ  := t.queryLimit.Load()
		prevUp := t.upstreamLimit.Load()
		var newQ, newUp int32

		switch {
		case score >= criticalMark:
			newQ  = max(prevQ/2,                              minQ)
			newUp = max(prevUp/2,                             minUp)

		case score >= highWater:
			newQ  = max(int32(float32(prevQ) *0.80), minQ)
			newUp = max(int32(float32(prevUp)*0.80), minUp)

		case score <= lowWater:
			newQ  = min(prevQ+1,  t.initQueryLimit+t.initQueryLimit/2)
			newUp = min(prevUp+1, t.initUpstreamLimit+t.initUpstreamLimit/2)

		default:
			newQ, newUp = prevQ, prevUp
		}

		t.queryLimit.Store(newQ)
		t.upstreamLimit.Store(newUp)

		// ── 5. Rate-limited pressure log ──────────────────────────────────────
		if score >= highWater && time.Since(lastLog) >= logCooldown {
			baselineReal := float64(t.goroutineBaselineX100.Load()) / 100.0
			log.Printf(
				"[THROTTLE] pressure=%d/100 goroutines=%d (baseline=%.1f) heap=%s nextGC=%s | "+
					"query: limit=%d active=%d dropped=%d | "+
					"upstream: limit=%d active=%d dropped=%d",
				score, goroutines, baselineReal, fmtBytes(ms.HeapInuse), fmtBytes(ms.NextGC),
				newQ,  t.activeQueries.Load(),  t.droppedQueries.Load(),
				newUp, t.activeUpstream.Load(), t.droppedUpstream.Load(),
			)
			lastLog = time.Now()
		}
	}
}

// computeMemPressure returns the heap pressure as a 0–1 float32.
// Extracted from computePressure so monitorLoop can use it for the EMA freeze
// decision before the full blended score is available.
//
// Two cases:
//   a) memory_limit_mb configured → pressure against 80% of the hard ceiling.
//      We start throttling with a 20% GC runway still available.
//   b) no hard limit → HeapInuse / NextGC.
//      Pressure rises as the heap approaches the GC trigger target.
func (t *throttler) computeMemPressure(heapInuse, nextGC uint64) float64 {
	if cfg.Server.MemoryLimitMB > 0 {
		limit := float64(cfg.Server.MemoryLimitMB) * 1024 * 1024 * 0.80
		if limit > 0 {
			p := float64(heapInuse) / limit
			if p > 1.0 {
				return 1.0
			}
			return p
		}
	}
	if nextGC > 0 {
		p := float64(heapInuse) / float64(nextGC)
		if p > 1.0 {
			return 1.0
		}
		return p
	}
	return 0
}

// computePressure blends three resource signals into a single 0–100 integer.
//
//   50% heap  — direct memory ceiling signal (see computeMemPressure)
//   30% goroutine spike — (current − EMA baseline) / (baseline × 8)
//   20% upstream fill  — activeUpstream / upstreamLimit
//
// All components are clamped to [0, 1] before weighting. memP is passed in
// from monitorLoop to avoid calling computeMemPressure twice per tick.
func (t *throttler) computePressure(goroutines int32, memP float64) int {

	// ── Goroutine spike (weight 0.30) ─────────────────────────────────────
	//
	// Baseline is the EMA of goroutine count during healthy periods (see
	// monitorLoop). Because the EMA is updated only under low heap pressure,
	// it naturally includes the steady-state goroutines spawned by quic-go,
	// http2, and miekg at normal load — no manual baseline tuning needed.
	//
	// Scale: 0 at baseline, 1.0 at baseline × 9 (i.e. 8× above baseline).
	// Example: EMA baseline of 80 goroutines → full goroutine pressure at 720.
	// That's a genuine crisis on any router. Moderate load that adds 20–30
	// goroutines above baseline scores well below 1.0 and doesn't trigger
	// unnecessary throttling.
	//
	// Before the first EMA sample (goroutineBaselineX100 == 0) we use a
	// conservative static fallback to avoid dividing by zero.
	var gorP float64
	baseX100 := t.goroutineBaselineX100.Load()
	if baseX100 > 0 {
		baseline := float64(baseX100) / 100.0
		if float64(goroutines) > baseline {
			gorP = (float64(goroutines) - baseline) / (baseline * 8)
		}
	} else {
		// Static fallback during first tick before any EMA sample exists.
		// 0 below 50 goroutines, full pressure at 500.
		if goroutines > 50 {
			gorP = float64(goroutines-50) / 450.0
		}
	}
	if gorP > 1.0 {
		gorP = 1.0
	}

	// ── Upstream fill ratio (weight 0.20) ─────────────────────────────────
	var upP float64
	if ul := t.upstreamLimit.Load(); ul > 0 {
		upP = float64(t.activeUpstream.Load()) / float64(ul)
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

