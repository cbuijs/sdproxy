/*
File: throttle.go
Version: 1.2.0
Last Updated: 2026-03-05 23:00 CET
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
             Four signals, blended into one integer per sample interval:

               40% heap pressure
                     HeapInuse / configured memory limit (×0.80 headroom),
                     or HeapInuse / NextGC when no limit is set.
                     Most reliable signal; directly bounded.

               25% goroutine spike
                     (current − EMA baseline) / (baseline × 8).
                     Baseline is a continuous EMA (α=0.02, τ≈25 s) of the
                     goroutine count, updated only while heap pressure is
                     below 40%. This makes the baseline self-calibrating:
                     it includes all library goroutines (quic-go, http2,
                     miekg/dns) at normal load and freezes automatically
                     during pressure events so the signal stays meaningful.

               20% cache miss rate
                     Δupstream_calls / Δtotal_queries per 500 ms window.
                     Measures what fraction of incoming queries had to be
                     forwarded to an upstream (i.e. were cache misses).
                     Leading indicator: a rising miss rate under load
                     predicts upstream saturation and goroutine pile-up
                     before heap pressure materialises.
                     Normal range: 0.10–0.30 (cache absorbing most load).
                     Not penalised during cold-start (first 10 s) to avoid
                     false alarms while the cache warms up.

               15% upstream fan-out ratio
                     activeUpstream / max(activeQueries, 1).
                     Measures how many outbound exchanges each active query
                     is generating. When > 1.0, staggered parallel racing
                     (upstream_stagger_ms) is firing on most queries —
                     a strong signal that upstreams are degraded.
                     Complements miss rate: miss rate says "how often are
                     we going upstream?", fan-out says "how hard is each
                     upstream call hitting the connection pool?"

             WHY FOUR SIGNALS
             ──────────────────────────────────────────────────────────────
             The old single upstream fill ratio (activeUpstream/limit) only
             told you "are we near the limit?" — a self-referential metric
             that says nothing about why. Miss rate and fan-out together
             diagnose the upstream relationship:

               High miss rate + low fan-out  = cold cache or query burst,
                                               upstreams keeping up fine.
               Low miss rate  + high fan-out = few misses but each one is
                                               spawning a stagger race —
                                               upstreams are degraded.
               High miss rate + high fan-out = every query misses and fans
                                               out — worst case, likely a
                                               random-subdomain attack or
                                               complete upstream failure.

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
             IncrQueryTotal / IncrUpstreamCall: one atomic Add each,
             called once per query from process.go.
             The monitor goroutine calls runtime.ReadMemStats every 500 ms
             (brief STW pause, ~1 µs on Go ≥ 1.15); query goroutines are
             not affected.

Changes:
  1.2.0 - [FEAT] Added cache miss rate and upstream fan-out ratio as two
           new pressure signals, replacing the simple fill ratio from v1.0.0.
           Miss rate (Δupstream_calls/Δtotal_queries per window) is a leading
           indicator of upstream saturation. Fan-out (activeUpstream /
           activeQueries) reveals whether stagger racing is firing broadly,
           indicating degraded upstreams. Together they make the pressure
           score diagnose *why* the upstream pool is busy, not just whether
           it is. New counters: queriesTotal and upstreamCalls (both atomic
           Int64, incremented from process.go). Cold-start suppression: miss
           rate signal is zeroed for the first 10 s to avoid penalising normal
           cache warm-up. Weights rebalanced: heap 40%, goroutine 25%,
           miss rate 20%, fan-out 15%.
  1.1.0 - [FIX]  Replaced one-shot 30 s startup goroutine baseline with a
           continuous EMA (α=0.02, τ≈25 s) updated only while heap pressure
           is below 40%. Removed baselineLearned flag and gorSamples
           accumulator.
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

	// ── Throughput counters ───────────────────────────────────────────────
	// Monotonically increasing. The monitor reads them each tick, computes
	// interval deltas, and derives the cache miss rate. Never reset — deltas
	// are always safe even across a wrap (int64 overflows in ~300 years at
	// 1M qps, not a concern).
	queriesTotal  atomic.Int64 // total queries past the AcquireQuery gate
	upstreamCalls atomic.Int64 // total queries that reached the upstream path

	// ── Pressure signal ───────────────────────────────────────────────────
	pressureScore atomic.Int32 // 0–100, updated every 500 ms

	// ── Drop counters ─────────────────────────────────────────────────────
	droppedQueries  atomic.Int64
	droppedUpstream atomic.Int64

	// ── Goroutine baseline — continuous EMA ───────────────────────────────
	// Updated every tick while heap pressure < 40%; frozen otherwise.
	// Stored ×100 as int64 for atomic fixed-point arithmetic (two decimal
	// places of precision without float64 in the atomic path).
	goroutineBaselineX100 atomic.Int64

	// ── Startup timestamp ─────────────────────────────────────────────────
	// Used to suppress the miss-rate signal during cache warm-up. Set once
	// in InitThrottle; read-only after that.
	startTime time.Time

	// ── Initial limits ────────────────────────────────────────────────────
	initQueryLimit    int32
	initUpstreamLimit int32
}

var thr throttler

// emaAlpha is the EMA smoothing factor. At a 500 ms tick rate:
//   τ = tick_interval / α = 500 ms / 0.02 = 25 s
const emaAlpha = float64(0.02)

// coldStartDuration is the period after startup during which the miss-rate
// signal is suppressed. The cache is always cold at startup, so a high miss
// rate in the first 10 s is expected and should not trigger throttling.
const coldStartDuration = 10 * time.Second

// InitThrottle derives initial limits from the worker count and launches the
// background pressure monitor. Call once from main() after cfg is populated.
func InitThrottle() {
	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}

	thr.initQueryLimit    = workers * 4
	thr.initUpstreamLimit = workers * 2
	thr.startTime         = time.Now()

	thr.queryLimit.Store(thr.initQueryLimit)
	thr.upstreamLimit.Store(thr.initUpstreamLimit)

	log.Printf("[THROTTLE] Adaptive admission control ready — query=%d upstream=%d (AIMD, no config needed)",
		thr.initQueryLimit, thr.initUpstreamLimit)

	go thr.monitorLoop()
}

// IncrQueryTotal records a query that passed the admission gate.
// Called once per query from ProcessDNS immediately after AcquireQuery.
// Single atomic Add — negligible hot-path cost.
func IncrQueryTotal() { thr.queriesTotal.Add(1) }

// IncrUpstreamCall records a query that reached the upstream forwarding path
// (i.e. a cache miss that required an outbound DNS exchange).
// Called once per forwarded query from ProcessDNS at step 6.
// Single atomic Add — negligible hot-path cost.
func IncrUpstreamCall() { thr.upstreamCalls.Add(1) }

// AcquireQuery reserves one query-processing slot.
//
// Returns false when activeQueries is at queryLimit — the caller must return
// immediately without writing any response (silent drop). The client will
// time out and retry naturally; no error state is set on the client side.
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
// Returns false when activeUpstream is at upstreamLimit. The caller returns
// an error so raceExchange can try the next upstream or surface a SERVFAIL.
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

// monitorLoop runs in a dedicated goroutine every 500 ms.
func (t *throttler) monitorLoop() {
	const (
		sampleInterval  = 500 * time.Millisecond
		highWater       = 65
		criticalMark    = 85
		lowWater        = 40
		baselineFreezeP = 0.40
		logCooldown     = 10 * time.Second
	)

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	var (
		lastLog          time.Time
		prevQueriesTotal int64
		prevUpstreamCall int64
	)

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

		// ── 1. Heap pressure (needed for EMA freeze decision) ─────────────
		memP := t.computeMemPressure(ms.HeapInuse, ms.NextGC)

		// ── 2. EMA goroutine baseline ─────────────────────────────────────
		// Update only when heap is healthy so the baseline reflects "normal
		// goroutine count at typical load" — including all library goroutines
		// from quic-go, http2, miekg — and not a burst or pressure event.
		if memP < baselineFreezeP {
			prev   := t.goroutineBaselineX100.Load()
			gorX100 := int64(goroutines) * 100
			if prev == 0 {
				t.goroutineBaselineX100.Store(gorX100)
			} else {
				newVal := int64(float64(prev)*(1-emaAlpha) + float64(gorX100)*emaAlpha)
				if newVal < 500 {
					newVal = 500
				}
				t.goroutineBaselineX100.Store(newVal)
			}
		}

		// ── 3. Miss rate — interval delta ─────────────────────────────────
		//
		// missRate = upstream_calls_this_window / queries_this_window.
		// Both counters are monotonically increasing; we diff them each tick.
		//
		// Suppressed during cold-start (first 10 s): the cache is always
		// empty at startup so a miss rate of 1.0 is expected and harmless —
		// penalising it would throttle perfectly normal warm-up traffic.
		//
		// A zero-query window (e.g. idle server) produces missRate=0, which
		// is correct: no upstream pressure.
		curQ  := t.queriesTotal.Load()
		curUp := t.upstreamCalls.Load()
		deltaQ  := curQ  - prevQueriesTotal
		deltaUp := curUp - prevUpstreamCall
		prevQueriesTotal = curQ
		prevUpstreamCall = curUp

		var missRate float64
		if time.Since(t.startTime) >= coldStartDuration && deltaQ > 0 {
			missRate = float64(deltaUp) / float64(deltaQ)
			if missRate > 1.0 {
				// Can exceed 1.0 if stagger launches multiple Exchange() calls
				// for a single query. Cap at 1.0 for the pressure calculation;
				// the fan-out signal below already captures this separately.
				missRate = 1.0
			}
		}

		// ── 4. Fan-out ratio ──────────────────────────────────────────────
		//
		// activeUpstream / max(activeQueries, 1).
		// Values > 1.0 mean stagger racing is firing (multiple upstream
		// goroutines per active client query) — a leading indicator that
		// upstreams are slow or unreachable.
		//
		// Scale: 0 → 1.0 mapped onto [0, 3.0] so a fan-out of 3.0
		// (every query racing three upstreams simultaneously) scores 1.0.
		// A typical healthy value is 0.2–0.4 (most queries are cache hits,
		// only a fraction reach even one upstream).
		activeQ  := t.activeQueries.Load()
		activeUp := t.activeUpstream.Load()
		var fanOut float64
		if activeQ > 0 {
			fanOut = float64(activeUp) / float64(activeQ)
		}

		// ── 5. Full pressure score ────────────────────────────────────────
		score := t.computePressure(goroutines, memP, missRate, fanOut)
		t.pressureScore.Store(int32(score))

		// ── 6. AIMD limit adjustment ──────────────────────────────────────
		prevQ  := t.queryLimit.Load()
		prevUp := t.upstreamLimit.Load()
		var newQ, newUp int32

		switch {
		case score >= criticalMark:
			newQ  = max(prevQ/2,                             minQ)
			newUp = max(prevUp/2,                            minUp)

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

		// ── 7. Rate-limited pressure log ──────────────────────────────────
		if score >= highWater && time.Since(lastLog) >= logCooldown {
			baselineReal := float64(t.goroutineBaselineX100.Load()) / 100.0
			log.Printf(
				"[THROTTLE] pressure=%d/100 goroutines=%d (baseline=%.1f) "+
					"heap=%s nextGC=%s missRate=%.2f fanOut=%.2f | "+
					"query: limit=%d active=%d dropped=%d | "+
					"upstream: limit=%d active=%d dropped=%d",
				score, goroutines, baselineReal,
				fmtBytes(ms.HeapInuse), fmtBytes(ms.NextGC),
				missRate, fanOut,
				newQ,  t.activeQueries.Load(),  t.droppedQueries.Load(),
				newUp, t.activeUpstream.Load(), t.droppedUpstream.Load(),
			)
			lastLog = time.Now()
		}
	}
}

// computeMemPressure returns heap pressure as a 0–1 float64.
// Extracted so monitorLoop can use it for the EMA freeze decision before
// the full blended score is computed.
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

// computePressure blends four resource signals into a single 0–100 integer.
//
//   40% heap pressure   — are we running out of memory?              (reactive)
//   25% goroutine spike — are we spawning too many goroutines?       (semi-leading)
//   20% miss rate       — is the cache helping?                      (leading)
//   15% fan-out ratio   — are upstreams slow / stagger firing?       (leading)
//
// memP is passed in from monitorLoop to avoid a redundant syscall.
func (t *throttler) computePressure(goroutines int32, memP, missRate, fanOut float64) int {

	// ── Goroutine spike (weight 0.25) ─────────────────────────────────────
	var gorP float64
	baseX100 := t.goroutineBaselineX100.Load()
	if baseX100 > 0 {
		baseline := float64(baseX100) / 100.0
		if float64(goroutines) > baseline {
			gorP = (float64(goroutines) - baseline) / (baseline * 8)
		}
	} else {
		// Static fallback before first EMA sample.
		if goroutines > 50 {
			gorP = float64(goroutines-50) / 450.0
		}
	}
	if gorP > 1.0 {
		gorP = 1.0
	}

	// ── Miss rate (weight 0.20) ───────────────────────────────────────────
	// missRate is already clamped to [0, 1.0] in monitorLoop and is 0 during
	// cold-start. Used directly — no further transformation needed.

	// ── Fan-out ratio (weight 0.15) ───────────────────────────────────────
	// Scale [0, 3.0] → [0, 1.0]. A fan-out of 3.0 means every active query
	// has three concurrent upstream exchanges (all three stagger slots firing).
	fanP := fanOut / 3.0
	if fanP > 1.0 {
		fanP = 1.0
	}

	return int((0.40*memP + 0.25*gorP + 0.20*missRate + 0.15*fanP) * 100)
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

