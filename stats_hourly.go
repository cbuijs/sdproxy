/*
File:    stats_hourly.go
Version: 1.8.0
Last Updated: 29-Sep-2026 09:49 CEST

Description:
  Hourly 24h Ring buffer tracking for sdproxy.
  Extracted from stats.go to improve modularity and reduce token burn.

Changes:
  1.8.0 - [SECURITY] Natively integrated `statSubdomainBlocks` into the hourly aggregate 
          blocked tracking buffers to correctly represent DNS tunneling drops inside 
          the Web UI historical charts.
*/

package main

import (
	"sync"
	"time"
)

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
	hourlyRing = make(map[int64]hourSlot)
	hourlyMu sync.Mutex

	prevTotal   int64
	prevBlocked int64
	prevFwd     int64
)

// runHourlyTicker waits until the next clock-hour boundary, then ticks every
// hour to record the hourly delta into the ring.
func runHourlyTicker() {
	now := time.Now()
	next := now.Truncate(time.Hour).Add(time.Hour)
	sleepDur := next.Sub(now)
	if sleepDur <= 0 {
		sleepDur = time.Second // Prevent instant spin-loop
	}
	
	timer := time.NewTimer(sleepDur)
	select {
	case <-timer.C:
	case <-shutdownCh:
		timer.Stop()
		return
	}

	recordHourSlot()
	
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			recordHourSlot()
		case <-shutdownCh:
			return
		}
	}
}

// recordHourSlot reads the current cumulative counters, computes deltas since
// the last tick, and writes them to the ring.
func recordHourSlot() {
	total := thr.queriesTotal.Load()
	// Include all blocking mechanisms to guarantee graph alignment with total scalar counters
	blocked := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load() + statSubdomainBlocks.Load()
	fwd := thr.upstreamCalls.Load()

	hourlyMu.Lock()
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

	minHour := ep - int64(retentionHours()) + 1
	for k := range hourlyRing {
		if k < minHour {
			delete(hourlyRing, k)
		}
	}
	hourlyMu.Unlock()

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

	statClientSeen.Prune(clientSeenMaxAge)
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

	curTot := thr.queriesTotal.Load() - pTot
	curBlk := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load() + statSubdomainBlocks.Load() - pBlk
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
		Label:   now.Format("15:04") + "…",
		Total:   curTot,
		Blocked: curBlk,
		Fwd:     curFwd,
	}
	return pts
}

