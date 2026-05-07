/*
File:    stats.go
Version: 2.16.0
Updated: 03-May-2026 04:00 EDT

Description:
  Lightweight DNS query statistics for sdproxy.
  Tracks totals since startup: total queries, cache hits, parental blocks,
  policy blocks, DGA interceptions, and Exfiltration mitigations. 
  Feeds the /api/stats endpoint in webui.go.

  Logic has been modularized into:
    - stats.go        (Core atomic scalar counters, Load/Save/Reset state)
    - stats_topn.go   (Top-N tracker engine)
    - stats_hourly.go (Hourly 24h Ring buffer tracking)

Changes:
  2.16.0 - [SECURITY/FIX] Resolved a concurrency data race on the `startTime` variable. 
           Migrated the timestamp tracking to an `atomic.Int64` Unix Nanosecond 
           implementation to guarantee thread-safe reads during live JSON polling 
           and `ResetStats` triggers.
  2.15.0 - [FIX] Resolved a telemetry tracking flaw where internal LAN queries 
           missing a remote IP address injected empty keys into the Top Talkers 
           tracker, wasting capacity.
  2.14.0 - [SECURITY] Appended `statExfilBlocks` to record and expose query drops 
           resulting from the Exfiltration/DNS Tunneling anomaly engine.
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// startTimeUnixNano securely tracks the process uptime boundary atomically.
var startTimeUnixNano atomic.Int64

var (
	qpsMu       sync.Mutex
	qpsCurrent  float64
	qpsLow      float64 = -1.0
	qpsHigh     float64
	qpsLastTot  int64
	qpsLastTime time.Time
)

// ---------------------------------------------------------------------------
// Scalar atomic counters
// ---------------------------------------------------------------------------

var (
	// statCacheHits counts cache hits (fresh + stale) served to clients.
	statCacheHits atomic.Int64

	// statParentalBlocks counts queries blocked by the parental control path.
	statParentalBlocks atomic.Int64

	// statPolicyBlocks counts queries blocked by rtype/domain/AAAA/strict-PTR
	// policy exits in writePolicyResp (policy.go).
	statPolicyBlocks atomic.Int64

	// statRateLimited counts queries silently dropped by the Token Bucket rate limiter.
	statRateLimited atomic.Int64

	// statRebindingBlocks counts queries blocked due to DNS Rebinding Protection.
	statRebindingBlocks atomic.Int64
	
	// statDGABlocks counts queries severed natively by the local ML DGA inference engine.
	statDGABlocks atomic.Int64
	
	// statExfilBlocks counts queries suppressed natively by the DNS tunneling anomaly engine.
	statExfilBlocks atomic.Int64
)

// IncrCacheHit records one cache hit. Called from the cache-serve path only.
func IncrCacheHit() { statCacheHits.Add(1) }

// IncrParentalBlock records one parental-control block.
func IncrParentalBlock() { statParentalBlocks.Add(1) }

// IncrPolicyBlock records one policy block.
func IncrPolicyBlock() { statPolicyBlocks.Add(1) }

// IncrDroppedRateLimit records a query dropped due to per-IP Token Bucket exhaustion.
func IncrDroppedRateLimit() { statRateLimited.Add(1) }

// IncrRebindingBlock records a query blocked because it contained private/bogon IPs.
func IncrRebindingBlock() { statRebindingBlocks.Add(1) }

// IncrDGABlock records a query severed because it was classified algorithmically generated.
func IncrDGABlock() { statDGABlocks.Add(1) }

// IncrExfilBlock records a query blocked by the volumetric exfiltration baseline monitor.
func IncrExfilBlock() { statExfilBlocks.Add(1) }

// ---------------------------------------------------------------------------
// QPS Ticker
// ---------------------------------------------------------------------------

// runQPSTicker calculates Current, Low, Average, and High Queries Per Second.
func runQPSTicker() {
	interval := 30 * time.Second
	if cfg.WebUI.StatsRefreshSec >= 5 {
		interval = time.Duration(cfg.WebUI.StatsRefreshSec) * time.Second
	}
	
	qpsMu.Lock()
	qpsLastTime = time.Now()
	qpsLastTot = thr.queriesTotal.Load()
	qpsMu.Unlock()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		now := <-t.C
		tot := thr.queriesTotal.Load()
		
		qpsMu.Lock()
		deltaTot := tot - qpsLastTot
		// Check for Reset stats operation, adjusting bounds organically 
		if deltaTot < 0 {
			deltaTot = tot
		}
		deltaSec := now.Sub(qpsLastTime).Seconds()
		
		var qps float64
		if deltaSec > 0 {
			qps = float64(deltaTot) / deltaSec
		}
		
		qpsCurrent = qps
		if qpsLow < 0 || qps < qpsLow {
			qpsLow = qps
		}
		if qps > qpsHigh {
			qpsHigh = qps
		}
		
		qpsLastTot = tot
		qpsLastTime = now
		qpsMu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Snapshot & Persistence
// ---------------------------------------------------------------------------

type GroupOverrideStat struct {
	Mode       string `json:"mode"`
	ExpiresAt  int64  `json:"expires_at"` // Unix timestamp, 0 if permanent
	RevertMode string `json:"revert_mode"`
}

// StatsSnapshot is the JSON-serialisable structure returned by /api/stats.
type StatsSnapshot struct {
	Uptime           string  `json:"uptime"`            // human-readable process uptime
	Since            string  `json:"since"`             // start date+time "02-Jan-2006 15:04:05" (server TZ, kept for compat)
	SinceUnix        int64   `json:"since_unix"`        // start as Unix timestamp — JS formats in browser local TZ
	TotalQueries     int64   `json:"total_queries"`     // queries past the admission gate
	CacheHits        int64   `json:"cache_hits"`        // hits served directly from cache
	CacheHitRate     string  `json:"cache_hit_rate"`    // "64.3%" — formatted for display
	Forwarded        int64   `json:"forwarded"`         // queries sent to an upstream
	Blocked          int64   `json:"blocked"`           // parental + policy + rebinding + DGA + Exfil blocks
	Dropped          int64   `json:"dropped"`           // shed under admission-control pressure + rate limits
	DroppedUpstream  int64   `json:"dropped_upstream"`  // shed exclusively under upstream connection exhaustion
	CoalescedQueries int64   `json:"coalesced_queries"` // queries suppressed/coalesced natively by singleflight
	CacheEntries     int     `json:"cache_entries"`     // current live entries in cache
	CacheCapacity    int     `json:"cache_capacity"`    // configured max cache size
	ActiveQueries    int32   `json:"active_queries"`    // queries currently in-flight

	CacheHitsPct       string `json:"cache_hits_pct"`
	ForwardedPct       string `json:"forwarded_pct"`
	BlockedPct         string `json:"blocked_pct"`
	DroppedPct         string `json:"dropped_pct"`
	DroppedUpstreamPct string `json:"dropped_upstream_pct"`

	QPSCurrent float64 `json:"qps_current"`
	QPSLow     float64 `json:"qps_low"`
	QPSHigh    float64 `json:"qps_high"`
	QPSAverage float64 `json:"qps_average"`

	GroupOverrides map[string]GroupOverrideStat `json:"group_overrides"`

	TopDomains       []TopEntry `json:"top_domains"`
	TopBlocked       []TopEntry `json:"top_blocked"`
	TopTalkers       []TopEntry `json:"top_talkers"`
	TopFilteredIPs   []TopEntry `json:"top_filtered_ips"`
	TopCategories    []TopEntry `json:"top_categories"`
	TopTLDs          []TopEntry `json:"top_tlds"`
	TopVendors       []TopEntry `json:"top_vendors"`
	TopGroups        []TopEntry `json:"top_groups"`
	TopBlockReasons  []TopEntry `json:"top_block_reasons"`
	TopUpstreams     []TopEntry `json:"top_upstreams"`
	TopUpstreamHosts []TopEntry `json:"top_upstream_hosts"`
	TopReturnCodes   []TopEntry `json:"top_return_codes"`
	TopNXDomain      []TopEntry `json:"top_nxdomain"`

	HourlyStats []HourlyPoint `json:"hourly_stats"`
}

// SavedStats is the rigid structure used when reading/writing to the JSON disk file.
type SavedStats struct {
	StartTime        time.Time                   `json:"start_time"`
	QueriesTotal     int64                       `json:"queries_total"`
	UpstreamCalls    int64                       `json:"upstream_calls"`
	DroppedQueries   int64                       `json:"dropped_queries"`
	DroppedUpstream  int64                       `json:"dropped_upstream"`
	CacheHits        int64                       `json:"cache_hits"`
	ParentalBlocks   int64                       `json:"parental_blocks"`
	PolicyBlocks     int64                       `json:"policy_blocks"`
	RateLimited      int64                       `json:"rate_limited"`
	RebindingBlocks  int64                       `json:"rebinding_blocks"`
	DGABlocks        int64                       `json:"dga_blocks"`
	ExfilBlocks      int64                       `json:"exfil_blocks"`
	CoalescedQueries int64                       `json:"coalesced_queries"`
	PrevTotal        int64                       `json:"prev_total"`
	PrevBlocked      int64                       `json:"prev_blocked"`
	PrevFwd          int64                       `json:"prev_fwd"`
	QPSLow           float64                     `json:"qps_low"`
	QPSHigh          float64                     `json:"qps_high"`
	HourlyRing       map[string]hourSlot         `json:"hourly_ring"`
	TopDomains       map[string]map[string]int64 `json:"top_domains"`
	TopBlocked       map[string]map[string]int64 `json:"top_blocked"`
	TopTalkers       map[string]map[string]int64 `json:"top_talkers"`
	TopFilteredIPs   map[string]map[string]int64 `json:"top_filtered_ips"`
	TopCategories    map[string]map[string]int64 `json:"top_categories"`
	TopTLDs          map[string]map[string]int64 `json:"top_tlds"`
	TopVendors       map[string]map[string]int64 `json:"top_vendors"`
	TopGroups        map[string]map[string]int64 `json:"top_groups"`
	TopBlockReasons  map[string]map[string]int64 `json:"top_block_reasons"`
	TopUpstreams     map[string]map[string]int64 `json:"top_upstreams"`
	TopUpstreamHosts map[string]map[string]int64 `json:"top_upstream_hosts"`
	TopReturnCodes   map[string]map[string]int64 `json:"top_return_codes"`
	TopNXDomain      map[string]map[string]int64 `json:"top_nxdomain"`
}

// GetStats assembles a StatsSnapshot from live atomic counters, the top-N 
// trackers, and the hourly ring buffer. Cheap enough for a 30-second
// polling interval.
func GetStats() StatsSnapshot {
	total := thr.queriesTotal.Load()
	hits := statCacheHits.Load()
	fwd := thr.upstreamCalls.Load()
	blocked := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load()
	dropped := thr.droppedQueries.Load() + statRateLimited.Load()
	droppedUp := thr.droppedUpstream.Load()
	active := thr.activeQueries.Load()
	coalesced := coalescedTotal.Load()

	// Hit-rate denominator: queries that reached the cache lookup phase.
	denom := total - blocked
	var hitRate string
	if denom > 0 {
		hitRate = fmt.Sprintf("%.1f%%", float64(hits)/float64(denom)*100)
	} else {
		hitRate = "—"
	}

	st := time.Unix(0, startTimeUnixNano.Load())
	upSec := int64(time.Since(st).Seconds())
	
	var qpsAvg float64
	if upSec > 0 {
		qpsAvg = float64(total) / float64(upSec)
	}

	qpsMu.Lock()
	curQPS := qpsCurrent
	lowQPS := qpsLow
	highQPS := qpsHigh
	qpsMu.Unlock()
	if lowQPS < 0 {
		lowQPS = 0
	}

	n := cfg.WebUI.StatsTopN
	if n < 5 {
		n = 10
	}
	if n > 100 {
		n = 100
	}

	// Capture active overrides and their expiry for the Web UI live timers.
	groupOverrideMu.RLock()
	goMap := make(map[string]GroupOverrideStat, len(groupOverride))
	for k, v := range groupOverride {
		exp := int64(0)
		if !v.ExpiresAt.IsZero() {
			exp = v.ExpiresAt.Unix()
		}
		goMap[k] = GroupOverrideStat{
			Mode:       v.Mode,
			ExpiresAt:  exp,
			RevertMode: v.RevertMode,
		}
	}
	groupOverrideMu.RUnlock()

	pct := func(v int64) string {
		if total == 0 {
			return "0.0% of total"
		}
		return fmt.Sprintf("%.1f%% of total", float64(v)/float64(total)*100)
	}

	return StatsSnapshot{
		Uptime:             fmtSeconds(upSec),
		Since:              st.Format("02-Jan-2006 15:04:05"),
		SinceUnix:          st.Unix(),
		TotalQueries:       total,
		CacheHits:          hits,
		CacheHitRate:       hitRate,
		Forwarded:          fwd,
		Blocked:            blocked,
		Dropped:            dropped,
		DroppedUpstream:    droppedUp,
		CoalescedQueries:   coalesced,
		CacheEntries:       CacheEntryCount(),
		CacheCapacity:      cfg.Cache.Size,
		ActiveQueries:      active,
		CacheHitsPct:       pct(hits),
		ForwardedPct:       pct(fwd),
		BlockedPct:         pct(blocked),
		DroppedPct:         pct(dropped),
		DroppedUpstreamPct: pct(droppedUp),
		QPSCurrent:         curQPS,
		QPSLow:             lowQPS,
		QPSHigh:            highQPS,
		QPSAverage:         qpsAvg,
		GroupOverrides:     goMap,
		TopDomains:         statTopDomains.TopN(n),
		TopBlocked:         statTopBlocked.TopN(n),
		TopTalkers:         statTopTalkers.TopN(n),
		TopFilteredIPs:     statTopFilteredIPs.TopN(n),
		TopCategories:      statTopCategories.TopN(n),
		TopTLDs:            statTopTLDs.TopN(n),
		TopVendors:         statTopVendors.TopN(n),
		TopGroups:          statTopGroups.TopN(n),
		TopBlockReasons:    statTopBlockReasons.TopN(n),
		TopUpstreams:       statTopUpstreams.TopN(n),
		TopUpstreamHosts:   statTopUpstreamHosts.TopN(n),
		TopReturnCodes:     statTopReturnCodes.TopN(n),
		TopNXDomain:        statTopNXDomain.TopN(n),
		HourlyStats:        getHourlyStats(),
	}
}

// ResetStats securely clears all live counters, history buffers, and top-lists.
func ResetStats() {
	if !cfg.WebUI.Enabled {
		return
	}

	startTimeUnixNano.Store(time.Now().UnixNano())

	thr.queriesTotal.Store(0)
	thr.upstreamCalls.Store(0)
	thr.droppedQueries.Store(0)
	thr.droppedUpstream.Store(0)
	statCacheHits.Store(0)
	statParentalBlocks.Store(0)
	statPolicyBlocks.Store(0)
	statRateLimited.Store(0)
	statRebindingBlocks.Store(0)
	statDGABlocks.Store(0)
	statExfilBlocks.Store(0)
	coalescedTotal.Store(0)

	hourlyMu.Lock()
	hourlyRing = make(map[int64]hourSlot)
	prevTotal = 0
	prevBlocked = 0
	prevFwd = 0
	hourlyMu.Unlock()

	qpsMu.Lock()
	qpsCurrent = 0
	qpsLow = -1.0
	qpsHigh = 0
	qpsLastTot = 0
	qpsLastTime = time.Now()
	qpsMu.Unlock()

	statTopDomains.Clear()
	statTopBlocked.Clear()
	statTopTalkers.Clear()
	statTopFilteredIPs.Clear()
	statTopCategories.Clear()
	statTopTLDs.Clear()
	statTopVendors.Clear()
	statTopGroups.Clear()
	statTopBlockReasons.Clear()
	statTopUpstreams.Clear()
	statTopUpstreamHosts.Clear()
	statTopReturnCodes.Clear()
	statTopNXDomain.Clear()

	SaveStats()
}

// SaveStats natively flushes the historical persistence state securely across process lifecycles.
func SaveStats() {
	if !cfg.WebUI.Enabled {
		return
	}
	dir := historyDir()
	if dir == "" {
		return
	}

	hourlyMu.Lock()
	ringStr := make(map[string]hourSlot, len(hourlyRing))
	for k, v := range hourlyRing {
		ringStr[strconv.FormatInt(k, 10)] = v
	}
	pTot := prevTotal
	pBlk := prevBlocked
	pFwd := prevFwd
	hourlyMu.Unlock()

	qpsMu.Lock()
	lowQPS := qpsLow
	if lowQPS < 0 {
		lowQPS = 0
	}
	highQPS := qpsHigh
	qpsMu.Unlock()

	data := SavedStats{
		StartTime:        time.Unix(0, startTimeUnixNano.Load()),
		QueriesTotal:     thr.queriesTotal.Load(),
		UpstreamCalls:    thr.upstreamCalls.Load(),
		DroppedQueries:   thr.droppedQueries.Load(),
		DroppedUpstream:  thr.droppedUpstream.Load(),
		CacheHits:        statCacheHits.Load(),
		ParentalBlocks:   statParentalBlocks.Load(),
		PolicyBlocks:     statPolicyBlocks.Load(),
		RateLimited:      statRateLimited.Load(),
		RebindingBlocks:  statRebindingBlocks.Load(),
		DGABlocks:        statDGABlocks.Load(),
		ExfilBlocks:      statExfilBlocks.Load(),
		CoalescedQueries: coalescedTotal.Load(),
		PrevTotal:        pTot,
		PrevBlocked:      pBlk,
		PrevFwd:          pFwd,
		QPSLow:           lowQPS,
		QPSHigh:          highQPS,
		HourlyRing:       ringStr,
		TopDomains:       statTopDomains.Export(),
		TopBlocked:       statTopBlocked.Export(),
		TopTalkers:       statTopTalkers.Export(),
		TopFilteredIPs:   statTopFilteredIPs.Export(),
		TopCategories:    statTopCategories.Export(),
		TopTLDs:          statTopTLDs.Export(),
		TopVendors:       statTopVendors.Export(),
		TopGroups:        statTopGroups.Export(),
		TopBlockReasons:  statTopBlockReasons.Export(),
		TopUpstreams:     statTopUpstreams.Export(),
		TopUpstreamHosts: statTopUpstreamHosts.Export(),
		TopReturnCodes:   statTopReturnCodes.Export(),
		TopNXDomain:      statTopNXDomain.Export(),
	}

	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "webui_stats.json")
	b, err := json.MarshalIndent(data, "", "  ") // Indent cleanly
	if err == nil {
		_ = os.WriteFile(path+".tmp", b, 0644)
		_ = os.Rename(path+".tmp", path)
	}
}

// LoadStats retrieves the historical persistence state created by SaveStats during prior lifecycles.
func LoadStats() {
	if !cfg.WebUI.Enabled {
		return
	}
	dir := historyDir()
	if dir == "" {
		return
	}

	path := filepath.Join(dir, "webui_stats.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var data SavedStats
	if err := json.Unmarshal(b, &data); err != nil {
		log.Printf("[STATS] Failed to load history: %v", err)
		return
	}

	startTimeUnixNano.Store(data.StartTime.UnixNano())
	
	thr.queriesTotal.Store(data.QueriesTotal)
	thr.upstreamCalls.Store(data.UpstreamCalls)
	thr.droppedQueries.Store(data.DroppedQueries)
	thr.droppedUpstream.Store(data.DroppedUpstream)
	statCacheHits.Store(data.CacheHits)
	statParentalBlocks.Store(data.ParentalBlocks)
	statPolicyBlocks.Store(data.PolicyBlocks)
	statRateLimited.Store(data.RateLimited)
	statRebindingBlocks.Store(data.RebindingBlocks)
	statDGABlocks.Store(data.DGABlocks)
	statExfilBlocks.Store(data.ExfilBlocks)
	coalescedTotal.Store(data.CoalescedQueries)

	hourlyMu.Lock()
	if data.HourlyRing != nil {
		for kStr, v := range data.HourlyRing {
			if ep, err := strconv.ParseInt(kStr, 10, 64); err == nil {
				hourlyRing[ep] = v
			}
		}
	}
	prevTotal = data.PrevTotal
	prevBlocked = data.PrevBlocked
	prevFwd = data.PrevFwd
	hourlyMu.Unlock()

	qpsMu.Lock()
	if data.QPSLow > 0 || data.QPSHigh > 0 {
		qpsLow = data.QPSLow
		qpsHigh = data.QPSHigh
	} else if data.QPSLow == 0 && data.QPSHigh == 0 {
		// Possibly missing from an old JSON format, keep defaults.
	}
	qpsMu.Unlock()

	if data.TopDomains != nil {
		statTopDomains.Import(data.TopDomains)
	}
	if data.TopBlocked != nil {
		statTopBlocked.Import(data.TopBlocked)
	}
	if data.TopTalkers != nil {
		statTopTalkers.Import(data.TopTalkers)
	}
	if data.TopFilteredIPs != nil {
		statTopFilteredIPs.Import(data.TopFilteredIPs)
	}
	if data.TopCategories != nil {
		statTopCategories.Import(data.TopCategories)
	}
	if data.TopTLDs != nil {
		statTopTLDs.Import(data.TopTLDs)
	}
	if data.TopVendors != nil {
		statTopVendors.Import(data.TopVendors)
	}
	if data.TopGroups != nil {
		statTopGroups.Import(data.TopGroups)
	}
	if data.TopBlockReasons != nil {
		statTopBlockReasons.Import(data.TopBlockReasons)
	}
	if data.TopUpstreams != nil {
		statTopUpstreams.Import(data.TopUpstreams)
	}
	if data.TopUpstreamHosts != nil {
		statTopUpstreamHosts.Import(data.TopUpstreamHosts)
	}
	if data.TopReturnCodes != nil {
		statTopReturnCodes.Import(data.TopReturnCodes)
	}
	if data.TopNXDomain != nil {
		statTopNXDomain.Import(data.TopNXDomain)
	}

	log.Printf("[STATS] Loaded historical stats from %s", path)
}

// runHistorySaveTicker periodically flushes stats and logs to disk based on config.
func runHistorySaveTicker() {
	if !cfg.WebUI.Enabled || historyDir() == "" {
		return
	}
	
	interval := 5 * time.Minute
	if cfg.WebUI.HistorySaveInterval != "" {
		if d, err := time.ParseDuration(cfg.WebUI.HistorySaveInterval); err == nil && d > 0 {
			interval = d
		}
	}
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		SaveStats()
		SaveLogs()
	}
}

// InitStats records the process start time (if not restored) and launches the hourly ring-buffer ticker.
func InitStats() {
	if startTimeUnixNano.Load() == 0 {
		startTimeUnixNano.Store(time.Now().UnixNano())
	}
	
	// Completely disable the resource-heavy tracking loops if the user opted out of the UI
	if cfg.WebUI.Enabled {
		go runHourlyTicker()
		go runHistorySaveTicker()
		go runQPSTicker()
	}
}

