/*
File:    stats_hourly.go
Version: 1.10.0
Last Updated: 24-Nov-2026 13:11 CET

Description:
  Hourly 24h Ring buffer tracking for sdproxy.

Changes:
  1.10.0 - [FIX] Clamped hourly ring deltas (`dTot`, `dBlk`, `dFwd`) at `>= 0`
           inside `recordHourSlot` so counter rebases or partial history restores
           never persist negative bar heights into `hourlyRing`.
  1.9.0  - [FEAT] Included `statIDNHomographBlocks` in hourly aggregate blocked
           counters (`recordHourSlot` and `getHourlyStats`).
  1.8.0  - [SECURITY] Integrated `statSubdomainBlocks` into hourly aggregate
           blocked tracking buffers.
*/

package main

import (
	"sync"
	"time"
)

type HourlyPoint struct {
	Label   string `json:"label"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Fwd     int64  `json:"fwd"`
}

type hourSlot struct {
	EpochHour int64 `json:"epoch_hour"`
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
	Fwd       int64 `json:"fwd"`
}

var (
	hourlyRing = make(map[int64]hourSlot)
	hourlyMu   sync.Mutex

	prevTotal   int64
	prevBlocked int64
	prevFwd     int64
)

func runHourlyTicker() {
	now := time.Now()
	next := now.Truncate(time.Hour).Add(time.Hour)
	sleepDur := next.Sub(now)
	if sleepDur <= 0 {
		sleepDur = time.Second
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

func recordHourSlot() {
	total := thr.queriesTotal.Load()
	blocked := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load() + statSubdomainBlocks.Load() + statIDNHomographBlocks.Load()
	fwd := thr.upstreamCalls.Load()

	hourlyMu.Lock()
	ep := time.Now().Add(-time.Minute).Unix() / 3600
	dTot := total - prevTotal
	dBlk := blocked - prevBlocked
	dFwd := fwd - prevFwd
	if dTot < 0 {
		dTot = 0
	}
	if dBlk < 0 {
		dBlk = 0
	}
	if dFwd < 0 {
		dFwd = 0
	}
	hourlyRing[ep] = hourSlot{
		EpochHour: ep,
		Total:     dTot,
		Blocked:   dBlk,
		Fwd:       dFwd,
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
	curBlk := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load() + statSubdomainBlocks.Load() + statIDNHomographBlocks.Load() - pBlk
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
