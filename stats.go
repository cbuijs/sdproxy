/*
File:    stats.go
Version: 3.5.0
Last Updated: 24-Nov-2026 13:11 CET

Description:
  Lightweight DNS query statistics for sdproxy. Tracks totals since startup:
  queries, cache lookups/hits, parental blocks, policy blocks, DGA interceptions,
  exfiltration mitigations, subdomain limits, and IDN homograph blocks.
  Feeds /api/stats in webui.go.

Changes:
  3.5.0 - [FIX] Added `statCacheLookups` (`IncrCacheLookup`) and persisted
          `CacheLookups` in `SavedStats` so `GetStats()` computes `CacheHitRate`
          against actual cache lookups (`hits / lookups`, bounded to `100.0%`)
          instead of `total - blocked`, preventing `>100%` or missing hit rates
          when cached synthetic blocks or `LOG`-mode rules increment both
          `statCacheHits` and block counters.
  3.4.0 - [FEAT] Added `statIDNHomographBlocks` and `IncrIDNHomographBlock()`.
  3.3.0 - [FEAT] Integrated `statSubdomainBlocks` for Subdomain Limit defense.
*/

package main

import (
	"bufio"
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

var startTimeUnixNano atomic.Int64

var (
	qpsMu       sync.Mutex
	qpsCurrent  float64
	qpsLow      float64 = -1.0
	qpsHigh     float64
	qpsLastTot  int64
	qpsLastTime time.Time
)

var (
	statCacheLookups       atomic.Int64
	statCacheHits          atomic.Int64
	statParentalBlocks     atomic.Int64
	statPolicyBlocks       atomic.Int64
	statRateLimited        atomic.Int64
	statRebindingBlocks    atomic.Int64
	statDGABlocks          atomic.Int64
	statExfilBlocks        atomic.Int64
	statSubdomainBlocks    atomic.Int64
	statIDNHomographBlocks atomic.Int64
)

func IncrCacheLookup()       { statCacheLookups.Add(1) }
func IncrCacheHit()          { statCacheHits.Add(1) }
func IncrParentalBlock()     { statParentalBlocks.Add(1) }
func IncrPolicyBlock()       { statPolicyBlocks.Add(1) }
func IncrDroppedRateLimit()  { statRateLimited.Add(1) }
func IncrRebindingBlock()    { statRebindingBlocks.Add(1) }
func IncrDGABlock()          { statDGABlocks.Add(1) }
func IncrExfilBlock()        { statExfilBlocks.Add(1) }
func IncrSubdomainBlock()    { statSubdomainBlocks.Add(1) }
func IncrIDNHomographBlock() { statIDNHomographBlocks.Add(1) }

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
		select {
		case now := <-t.C:
			tot := thr.queriesTotal.Load()

			qpsMu.Lock()
			deltaTot := tot - qpsLastTot
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
		case <-shutdownCh:
			return
		}
	}
}

type GroupOverrideStat struct {
	Mode       string `json:"mode"`
	ExpiresAt  int64  `json:"expires_at"`
	RevertMode string `json:"revert_mode"`
}

type StatsSnapshot struct {
	Uptime           string `json:"uptime"`
	Since            string `json:"since"`
	SinceUnix        int64  `json:"since_unix"`
	TotalQueries     int64  `json:"total_queries"`
	CacheHits        int64  `json:"cache_hits"`
	CacheHitRate     string `json:"cache_hit_rate"`
	Forwarded        int64  `json:"forwarded"`
	Blocked          int64  `json:"blocked"`
	CoalescedQueries int64  `json:"coalesced_queries"`
	CacheEntries     int    `json:"cache_entries"`
	CacheCapacity    int    `json:"cache_capacity"`
	ActiveQueries    int32  `json:"active_queries"`

	CacheHitsPct string `json:"cache_hits_pct"`
	ForwardedPct string `json:"forwarded_pct"`
	BlockedPct   string `json:"blocked_pct"`

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

type SavedStats struct {
	StartTime          time.Time                   `json:"start_time"`
	QueriesTotal       int64                       `json:"queries_total"`
	UpstreamCalls      int64                       `json:"upstream_calls"`
	DroppedQueries     int64                       `json:"dropped_queries"`
	DroppedUpstream    int64                       `json:"dropped_upstream"`
	CacheLookups       int64                       `json:"cache_lookups,omitempty"`
	CacheHits          int64                       `json:"cache_hits"`
	ParentalBlocks     int64                       `json:"parental_blocks"`
	PolicyBlocks       int64                       `json:"policy_blocks"`
	RateLimited        int64                       `json:"rate_limited"`
	RebindingBlocks    int64                       `json:"rebinding_blocks"`
	DGABlocks          int64                       `json:"dga_blocks"`
	ExfilBlocks        int64                       `json:"exfil_blocks"`
	SubdomainBlocks    int64                       `json:"subdomain_blocks"`
	IDNHomographBlocks int64                       `json:"idn_homograph_blocks"`
	CoalescedQueries   int64                       `json:"coalesced_queries"`
	PrevTotal          int64                       `json:"prev_total"`
	PrevBlocked        int64                       `json:"prev_blocked"`
	PrevFwd            int64                       `json:"prev_fwd"`
	QPSLow             float64                     `json:"qps_low"`
	QPSHigh            float64                     `json:"qps_high"`
	HourlyRing         map[string]hourSlot         `json:"hourly_ring"`
	TopDomains         map[string]map[string]int64 `json:"top_domains"`
	TopBlocked         map[string]map[string]int64 `json:"top_blocked"`
	TopTalkers         map[string]map[string]int64 `json:"top_talkers"`
	TopFilteredIPs     map[string]map[string]int64 `json:"top_filtered_ips"`
	TopCategories      map[string]map[string]int64 `json:"top_categories"`
	TopTLDs            map[string]map[string]int64 `json:"top_tlds"`
	TopVendors         map[string]map[string]int64 `json:"top_vendors"`
	TopGroups          map[string]map[string]int64 `json:"top_groups"`
	TopBlockReasons    map[string]map[string]int64 `json:"top_block_reasons"`
	TopUpstreams       map[string]map[string]int64 `json:"top_upstreams"`
	TopUpstreamHosts   map[string]map[string]int64 `json:"top_upstream_hosts"`
	TopReturnCodes     map[string]map[string]int64 `json:"top_return_codes"`
	TopNXDomain        map[string]map[string]int64 `json:"top_nxdomain"`
	ClientLastSeen     map[string]int64            `json:"client_last_seen"`
}

func statsPath() string {
	dir := historyDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "webui_stats.json")
}

func GetStats() StatsSnapshot {
	total := thr.queriesTotal.Load()
	lookups := statCacheLookups.Load()
	hits := statCacheHits.Load()
	fwd := thr.upstreamCalls.Load()
	blocked := statParentalBlocks.Load() + statPolicyBlocks.Load() + statRebindingBlocks.Load() + statDGABlocks.Load() + statExfilBlocks.Load() + statSubdomainBlocks.Load() + statIDNHomographBlocks.Load()
	active := thr.activeQueries.Load()
	coalesced := coalescedTotal.Load()

	var hitRate string
	if lookups > 0 {
		rate := float64(hits) / float64(lookups) * 100
		if rate > 100.0 {
			rate = 100.0
		}
		hitRate = fmt.Sprintf("%.1f%%", rate)
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
		if total <= 0 {
			return "0.0% of total"
		}
		p := float64(v) / float64(total) * 100
		if p > 100.0 {
			p = 100.0
		}
		return fmt.Sprintf("%.1f%% of total", p)
	}

	return StatsSnapshot{
		Uptime:           fmtSeconds(upSec),
		Since:            st.Format("02-Jan-2006 15:04:05"),
		SinceUnix:        st.Unix(),
		TotalQueries:     total,
		CacheHits:        hits,
		CacheHitRate:     hitRate,
		Forwarded:        fwd,
		Blocked:          blocked,
		CoalescedQueries: coalesced,
		CacheEntries:     CacheEntryCount(),
		CacheCapacity:    cfg.Cache.Size,
		ActiveQueries:    active,
		CacheHitsPct:     pct(hits),
		ForwardedPct:     pct(fwd),
		BlockedPct:       pct(blocked),
		QPSCurrent:       curQPS,
		QPSLow:           lowQPS,
		QPSHigh:          highQPS,
		QPSAverage:       qpsAvg,
		GroupOverrides:   goMap,
		TopDomains:       statTopDomains.TopN(n),
		TopBlocked:       statTopBlocked.TopN(n),
		TopTalkers:       statTopTalkers.TopN(n),
		TopFilteredIPs:   statTopFilteredIPs.TopN(n),
		TopCategories:    statTopCategories.TopN(n),
		TopTLDs:          statTopTLDs.TopN(n),
		TopVendors:       statTopVendors.TopN(n),
		TopGroups:        statTopGroups.TopN(n),
		TopBlockReasons:  statTopBlockReasons.TopN(n),
		TopUpstreams:     statTopUpstreams.TopN(n),
		TopUpstreamHosts: statTopUpstreamHosts.TopN(n),
		TopReturnCodes:   statTopReturnCodes.TopN(n),
		TopNXDomain:      statTopNXDomain.TopN(n),
		HourlyStats:      getHourlyStats(),
	}
}

func ResetStats() {
	if !cfg.WebUI.Enabled {
		return
	}

	startTimeUnixNano.Store(time.Now().UnixNano())

	thr.queriesTotal.Store(0)
	thr.upstreamCalls.Store(0)
	thr.droppedQueries.Store(0)
	thr.droppedUpstream.Store(0)
	statCacheLookups.Store(0)
	statCacheHits.Store(0)
	statParentalBlocks.Store(0)
	statPolicyBlocks.Store(0)
	statRateLimited.Store(0)
	statRebindingBlocks.Store(0)
	statDGABlocks.Store(0)
	statExfilBlocks.Store(0)
	statSubdomainBlocks.Store(0)
	statIDNHomographBlocks.Store(0)
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

	statClientSeen.Clear()

	SaveStats()
}

func SaveStats() {
	if !cfg.WebUI.Enabled {
		return
	}
	path := statsPath()
	if path == "" {
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
		StartTime:          time.Unix(0, startTimeUnixNano.Load()),
		QueriesTotal:       thr.queriesTotal.Load(),
		UpstreamCalls:      thr.upstreamCalls.Load(),
		DroppedQueries:     thr.droppedQueries.Load(),
		DroppedUpstream:    thr.droppedUpstream.Load(),
		CacheLookups:       statCacheLookups.Load(),
		CacheHits:          statCacheHits.Load(),
		ParentalBlocks:     statParentalBlocks.Load(),
		PolicyBlocks:       statPolicyBlocks.Load(),
		RateLimited:        statRateLimited.Load(),
		RebindingBlocks:    statRebindingBlocks.Load(),
		DGABlocks:          statDGABlocks.Load(),
		ExfilBlocks:        statExfilBlocks.Load(),
		SubdomainBlocks:    statSubdomainBlocks.Load(),
		IDNHomographBlocks: statIDNHomographBlocks.Load(),
		CoalescedQueries:   coalescedTotal.Load(),
		PrevTotal:          pTot,
		PrevBlocked:        pBlk,
		PrevFwd:            pFwd,
		QPSLow:             lowQPS,
		QPSHigh:            highQPS,
		HourlyRing:         ringStr,
		TopDomains:         statTopDomains.Export(),
		TopBlocked:         statTopBlocked.Export(),
		TopTalkers:         statTopTalkers.Export(),
		TopFilteredIPs:     statTopFilteredIPs.Export(),
		TopCategories:      statTopCategories.Export(),
		TopTLDs:            statTopTLDs.Export(),
		TopVendors:         statTopVendors.Export(),
		TopGroups:          statTopGroups.Export(),
		TopBlockReasons:    statTopBlockReasons.Export(),
		TopUpstreams:       statTopUpstreams.Export(),
		TopUpstreamHosts:   statTopUpstreamHosts.Export(),
		TopReturnCodes:     statTopReturnCodes.Export(),
		TopNXDomain:        statTopNXDomain.Export(),
		ClientLastSeen:     statClientSeen.Export(),
	}

	err := atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		return json.NewEncoder(bw).Encode(data)
	})

	if err != nil && (logWebUI || logSystem) {
		log.Printf("[STATS] WARNING: Failed to write stats payload to disk: %v", err)
	}
}

func LoadStats() {
	if !cfg.WebUI.Enabled {
		return
	}
	path := statsPath()
	if path == "" {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var data SavedStats
	if err := json.NewDecoder(bufio.NewReaderSize(f, 64*1024)).Decode(&data); err != nil {
		if logWebUI || logSystem {
			log.Printf("[STATS] Failed to load history: %v", err)
		}
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
	statSubdomainBlocks.Store(data.SubdomainBlocks)
	statIDNHomographBlocks.Store(data.IDNHomographBlocks)
	coalescedTotal.Store(data.CoalescedQueries)

	if data.CacheLookups > 0 {
		statCacheLookups.Store(data.CacheLookups)
	} else if data.CacheHits > 0 {
		allBlk := data.ParentalBlocks + data.PolicyBlocks + data.RebindingBlocks +
			data.DGABlocks + data.ExfilBlocks + data.SubdomainBlocks + data.IDNHomographBlocks
		estLookups := data.QueriesTotal - allBlk
		if estLookups < data.CacheHits {
			estLookups = data.CacheHits
		}
		statCacheLookups.Store(estLookups)
	}

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
	if data.ClientLastSeen != nil {
		statClientSeen.Import(data.ClientLastSeen)
	}

	if logWebUI || logSystem {
		log.Printf("[STATS] Loaded historical stats from %s", path)
	}
}

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
	for {
		select {
		case <-ticker.C:
			SaveStats()
			SaveLogs()
		case <-shutdownCh:
			return
		}
	}
}

func InitStats() {
	if startTimeUnixNano.Load() == 0 {
		startTimeUnixNano.Store(time.Now().UnixNano())
	}

	if cfg.WebUI.Enabled {
		go runHourlyTicker()
		go runHistorySaveTicker()
		go runQPSTicker()
	}
}
