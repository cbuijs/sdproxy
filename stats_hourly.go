/*
File:    stats_hourly.go
Version: 1.5.0
Updated: 01-May-2026 16:24 CEST

Description:
  Hourly 24h Ring buffer tracking for sdproxy.
  Extracted from stats.go to improve modularity and reduce token burn.

Changes:
  1.5.0 - [SECURITY] Natively integrated `statExfilBlocks` into the hourly aggregate 
          blocked tracking buffers to correctly represent DNS tunneling drops inside 
          the Web UI historical charts.
  1.4.0 - [SECURITY] Natively appended `statDGABlocks` to the aggregate 
          blocked telemetry buffers to ensure absolute alignment within 
          the historical charting data.
*/

package main

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Hourly ring buffer
// ---------------------------------------------------------------------------

// HourlyPoint is one bar in the activity graph returned by /api/stats.
type HourlyPoint struct {
	Label   string `json:"label"`   // "14:00" or "14:00…" for the current hour
	Total   int64  `json:"total"`   // queries during this hour
	Blocked int64  `json:"blocked"` // blocks during this hour
	Fwd     int64  `json:"fwd"`     // forwarded queries during this hour
}

// hourSlot is one completed-hour snapshot stored in the ring. Exported for JSON.
type hourSlot struct {
	EpochHour int64 `json:"epoch_hour"`
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
	Fwd       int64 `json:"fwd"`
}

var (
	// hourlyRing dynamically scales its entries to HistoryRetentionHours.
	hourlyRing = make(map[int64]hourSlot)

	hourlyMu sync.Mutex

	// Cumulative counter snapshots at the last hourly tick.
	// Protected by hourlyMu; read in getHourlyStats to compute the live delta.
	prevTotal   int64
	prevBlocked int64
	prevFwd     int64
)

// runHourlyTicker waits until the next clock-hour boundary, then ticks every
// hour to record the hourly delta into the ring.
func runHourlyTicker() {
	now := time.Now()
	next := now.Truncate(time.Hour).Add(time.Hour)
	time.Sleep(next.Sub(now))
	recordHourSlot()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		recordHourSlot()
	}
}

// recordHourSlot reads the current cumulative counters, computes deltas since
// the last tick, and writes them to the ring.
func recordHourSlot() {
	total := thr.queriesTotal.Load()
	// Include all blocking mechanisms to guarantee graph alignment with total scalar counters
	blocked := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load()
	fwd := thr.upstreamCalls.Load()

	hourlyMu.Lock()
	// Subtract one minute so we reliably land in the hour that just ended.
	ep := time.Now().Add(-time.Minute).Unix() / 3600
	hourlyRing[ep] = hourSlot{
		EpochHour: ep,
		Total:     total - prevTotal,
		Blocked:   blocked - prevBlocked,
		Fwd:       fwd - prevFwd,
	}
	prevTotal = total
	prevBlocked = blocked
	prevFwd = fwd

	// Prune old hours from the ring
	minHour := ep - int64(retentionHours()) + 1
	for k := range hourlyRing {
		if k < minHour {
			delete(hourlyRing, k)
		}
	}
	hourlyMu.Unlock()

	// Cascade prune to all Top-N trackers
	rh := retentionHours()
	statTopDomains.Prune(rh)
	statTopBlocked.Prune(rh)
	statTopTalkers.Prune(rh)
	statTopFilteredIPs.Prune(rh)
	statTopCategories.Prune(rh)
	statTopTLDs.Prune(rh)
	statTopVendors.Prune(rh)
	statTopGroups.Prune(rh)
	statTopBlockReasons.Prune(rh)
	statTopUpstreams.Prune(rh)
	statTopUpstreamHosts.Prune(rh)
	statTopReturnCodes.Prune(rh)
	statTopNXDomain.Prune(rh)
}

// getHourlyStats assembles the series returned by /api/stats.
func getHourlyStats() []HourlyPoint {
	now := time.Now()
	curEpoch := now.Unix() / 3600
	retHours := retentionHours()

	hourlyMu.Lock()
	ringCopy := make(map[int64]hourSlot, len(hourlyRing))
	for k, v := range hourlyRing {
		ringCopy[k] = v
	}
	pTot := prevTotal
	pBlk := prevBlocked
	pFwd := prevFwd
	hourlyMu.Unlock()

	pts := make([]HourlyPoint, retHours)

	// Points 0 to retHours-2: completed hours
	for i := 0; i < retHours-1; i++ {
		ep := curEpoch - int64(retHours-1-i)
		t := time.Unix(ep*3600, 0).Local()
		pt := HourlyPoint{Label: t.Format("15:04")}
		if s, ok := ringCopy[ep]; ok {
			pt.Total = s.Total
			pt.Blocked = s.Blocked
			pt.Fwd = s.Fwd
		}
		pts[i] = pt
	}

	// Point retHours-1: live delta for the current (partial) hour.
	curTot := thr.queriesTotal.Load() - pTot
	curBlk := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load() - pBlk
	curFwd := thr.upstreamCalls.Load() - pFwd
	if curTot < 0 {
		curTot = 0
	}
	if curBlk < 0 {
		curBlk = 0
	}
	if curFwd < 0 {
		curFwd = 0
	}
	pts[retHours-1] = HourlyPoint{
		Label:   now.Format("15:04") + "…", // trailing … marks it as still accumulating
		Total:   curTot,
		Blocked: curBlk,
		Fwd:     curFwd,
	}
	return pts
}

