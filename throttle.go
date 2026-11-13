/*
File:    throttle.go
Version: 2.7.0
Last Updated: 05-Nov-2026 16:36 CET

Description:
  Adaptive, zero-configuration admission control for sdproxy.
  Monitors heap pressure and upstream fan-out every 500 ms, then adjusts two
  independent concurrency limits via AIMD to keep the router stable under
  burst traffic without any manual tuning.

Changes:
  2.7.0 - [CRITICAL/FIX] Added `BypassUpstreamThrottle(ctx)` context marker so
          internal sub-probes (`for_sale`, `parked`, `backgroundRevalidate`, and
          startup bootstrap/DDR probes) do not consume client-facing
          `AcquireUpstream` slots while the parent query already holds an active
          query/SingleFlight slot. Eliminates self-deadlock and upstream slot
          starvation under concurrent cache-miss bursts when `for_sale`, `parked`,
          and `strategy: secure` are active simultaneously.
  2.6.0 - [CRITICAL/FIX] Expanded `initUpstreamLimit` to `workers * 16` with a
          minimum floor of 128.
  2.5.0 - [DEAD-CODE/BLOAT] Removed the trailing `var _ atomic.Int64` "atomic
          import guard" and its comment.
  2.4.0 - [SECURITY/FIX] Eradicated a persistent zombie goroutine organically.
  2.3.0 - [LOGGING] Managed initialization and active pressure diagnostic events 
          natively via the `logSystem` toggle.
  2.2.0 - [FIX] Resolved a critical memory pressure throttling regression.
  2.1.0 - [PERF] Optimized `AcquireQuery` and `AcquireUpstream` admission gates to be 
          completely wait-free.
*/

package main

import (
	"context"
	"fmt"
	"log"
	"runtime/metrics"
	"sync/atomic"
	"time"
)

type bypassThrottleKey struct{}

// WithBypassUpstreamThrottle marks a context as an internal probe or background
// revalidation so it does not consume client-facing AcquireUpstream slots.
func WithBypassUpstreamThrottle(ctx context.Context) context.Context {
	return context.WithValue(ctx, bypassThrottleKey{}, true)
}

// IsBypassUpstreamThrottle reports whether ctx carries the internal probe marker.
func IsBypassUpstreamThrottle(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(bypassThrottleKey{}).(bool)
	return v
}

type throttler struct {
	// ── Hot path ─────────────────────────────────────────────────────────
	activeQueries  atomic.Int32 // queries currently inside ProcessDNS
	activeUpstream atomic.Int32 // upstream exchanges currently in-flight
	queryLimit     atomic.Int32 // current max for activeQueries
	upstreamLimit  atomic.Int32 // current max for activeUpstream

	// ── Throughput counters ───────────────────────────────────────────────
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

	thr.initQueryLimit = max(workers*25, 128)
	thr.initUpstreamLimit = max(workers*16, 128)

	thr.queryLimit.Store(thr.initQueryLimit)
	thr.upstreamLimit.Store(thr.initUpstreamLimit)

	if logSystem {
		log.Printf("[THROTTLE] Adaptive admission control ready — query=%d upstream=%d (AIMD, heap+fanout signals)",
			thr.initQueryLimit, thr.initUpstreamLimit)
	}

	go thr.monitorLoop()
}

// IncrQueryTotal records a query that passed the admission gate.
func IncrQueryTotal() { thr.queriesTotal.Add(1) }

// IncrUpstreamCall records a query that reached the upstream forwarding path.
func IncrUpstreamCall() { thr.upstreamCalls.Add(1) }

// AcquireQuery reserves one query-processing slot.
func AcquireQuery() bool {
	limit := thr.queryLimit.Load()
	if thr.activeQueries.Add(1) > limit {
		thr.activeQueries.Add(-1)
		thr.droppedQueries.Add(1)
		return false
	}
	return true
}

// ReleaseQuery releases a slot previously acquired by AcquireQuery.
func ReleaseQuery() { thr.activeQueries.Add(-1) }

// AcquireUpstream reserves one upstream-exchange slot.
func AcquireUpstream() bool {
	limit := thr.upstreamLimit.Load()
	if thr.activeUpstream.Add(1) > limit {
		thr.activeUpstream.Add(-1)
		thr.droppedUpstream.Add(1)
		return false
	}
	return true
}

// ReleaseUpstream releases a slot previously acquired by AcquireUpstream.
func ReleaseUpstream() { thr.activeUpstream.Add(-1) }

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

		highWater    = 70
		criticalMark = 90
		lowWater     = 30

		logCooldown = 10 * time.Second
	)

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	var lastLog time.Time

	workers := int32(cfg.Server.UDPWorkers)
	if workers <= 0 {
		workers = 10
	}
	minQ := max(workers*4, 32)
	minUp := max(workers*4, 32)

	metricSamples := []metrics.Sample{
		{Name: "/memory/classes/heap/inuse:bytes"},
	}

	for {
		select {
		case <-ticker.C:
			metrics.Read(metricSamples)
			heapInuse := metricUint64(metricSamples[0].Value)

			activeQ := t.activeQueries.Load()
			activeUp := t.activeUpstream.Load()
			score := t.computePressure(heapInuse, activeQ, activeUp)
			t.pressureScore.Store(int32(score))

			prevQ := t.queryLimit.Load()
			prevUp := t.upstreamLimit.Load()
			var newQ, newUp int32

			qCeil := t.initQueryLimit * 4
			upCeil := t.initUpstreamLimit * 4

			switch {
			case score >= criticalMark:
				newQ = max(prevQ/2, minQ)
				newUp = max(prevUp/2, minUp)
			case score >= highWater:
				newQ = max(int32(float32(prevQ)*0.85), minQ)
				newUp = max(int32(float32(prevUp)*0.85), minUp)
			case score <= lowWater:
				newQ = min(prevQ+5, qCeil)
				newUp = min(prevUp+5, upCeil)
			default:
				newQ, newUp = prevQ, prevUp
			}

			t.queryLimit.Store(newQ)
			t.upstreamLimit.Store(newUp)

			if score >= highWater && time.Since(lastLog) >= logCooldown {
				if logSystem {
					log.Printf(
						"[THROTTLE] pressure=%d/100 heap=%s | "+
							"query: limit=%d active=%d dropped=%d | "+
							"upstream: limit=%d active=%d dropped=%d",
						score, fmtBytes(heapInuse),
						newQ, t.activeQueries.Load(), t.droppedQueries.Load(),
						newUp, t.activeUpstream.Load(), t.droppedUpstream.Load(),
					)
				}
				lastLog = time.Now()
			}
		case <-shutdownCh:
			return
		}
	}
}

func (t *throttler) computeMemPressure(heapInuse uint64) float64 {
	if cfg.Server.MemoryLimitMB <= 0 {
		return 0.0
	}

	limitBytes := float64(cfg.Server.MemoryLimitMB) * 1024 * 1024 * 0.80
	p := float64(heapInuse) / limitBytes

	if p > 1.0 {
		return 1.0
	}
	return p
}

func (t *throttler) computePressure(heapInuse uint64, activeQ, activeUp int32) int {
	memP := t.computeMemPressure(heapInuse)

	var fanP float64
	if activeQ > 0 {
		fanP = float64(activeUp) / float64(activeQ) / 2.0
		if fanP > 1.0 {
			fanP = 1.0
		}
	}

	return int((0.85*memP + 0.15*fanP) * 100)
}

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
