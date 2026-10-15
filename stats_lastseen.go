/*
File:    stats_lastseen.go
Version: 1.2.0
Last Updated: 17-Aug-2026 18:00 CEST

Description:
  Per-client "last seen" tracking for sdproxy.

  Records the wall-clock instant at which each known client (keyed by source IP
  AND, when resolvable, by MAC address) last presented a query that survived the
  admission pipeline. Consumed exclusively by the Web UI "Known Clients &
  Blocking" table, which renders it as a relative age ("3m ago", "2d ago").

Changes:
  1.2.0 - [PERF/FIX] Replaced full linear shard scan with a bounded 32-sample
          oldest-first eviction policy. Mitigates severe CPU thrashing during 
          intense spoofed source IP floods natively.
  1.1.0 - [DOC] itoa64 is no longer private to this file. 
*/

package main

import (
	"hash/maphash"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------

// clientSeenShardCount is the number of independently locked shards.
const clientSeenShardCount = 32

// clientSeenMaxEntries is the process-wide ceiling on tracked identities.
const clientSeenMaxEntries = 8192

// clientSeenPerShardMax is the per-shard derivation of the global ceiling.
const clientSeenPerShardMax = clientSeenMaxEntries / clientSeenShardCount

// clientSeenMaxAge is the retention horizon for a last-seen record.
const clientSeenMaxAge = 30 * 24 * time.Hour

// ---------------------------------------------------------------------------
// Tracker structures
// ---------------------------------------------------------------------------

// clientSeenShard is one independently locked partition of the tracker.
type clientSeenShard struct {
	mu   sync.RWMutex
	seen map[string]*atomic.Int64 // identity key (IP or MAC) -> unix seconds
}

// clientSeenTracker is a bounded, sharded map of identity -> last-seen instant.
// Safe for concurrent use by any number of goroutines.
type clientSeenTracker struct {
	seed   maphash.Seed
	shards [clientSeenShardCount]*clientSeenShard
}

// newClientSeenTracker allocates a fresh tracker with all shards initialised.
func newClientSeenTracker() *clientSeenTracker {
	t := &clientSeenTracker{
		seed: maphash.MakeSeed(),
	}
	for i := 0; i < clientSeenShardCount; i++ {
		t.shards[i] = &clientSeenShard{
			seen: make(map[string]*atomic.Int64, clientSeenPerShardMax),
		}
	}
	return t
}

// getShard maps an identity key onto its owning shard.
func (t *clientSeenTracker) getShard(key string) *clientSeenShard {
	h := maphash.String(t.seed, key)
	return t.shards[h&(clientSeenShardCount-1)]
}

// statClientSeen is the single global tracker instance.
var statClientSeen = newClientSeenTracker()

// ---------------------------------------------------------------------------
// Hot path
// ---------------------------------------------------------------------------

// Touch records unixSec as the last-seen instant for key.
func (t *clientSeenTracker) Touch(key string, unixSec int64) {
	if key == "" {
		return
	}
	sh := t.getShard(key)

	sh.mu.RLock()
	cell, ok := sh.seen[key]
	sh.mu.RUnlock()
	if ok {
		cell.Store(unixSec)
		return
	}

	// ── New identity: exclusive section ──────────────────────────────────
	sh.mu.Lock()
	if cell, ok := sh.seen[key]; ok {
		sh.mu.Unlock()
		cell.Store(unixSec)
		return
	}

	// Hard ceiling enforcement. Only reachable on a genuinely new key against a
	// full shard. [PERF/FIX] Replaced full linear scan with a bounded 32-sample
	// oldest-first eviction. Limits CPU thrashing dramatically during severe 
	// spoofed IP floods natively.
	if len(sh.seen) >= clientSeenPerShardMax {
		var oldestKey string
		var oldestTS int64 = math.MaxInt64
		var sampled int
		
		for k, v := range sh.seen {
			if ts := v.Load(); ts < oldestTS {
				oldestTS = ts
				oldestKey = k
			}
			sampled++
			if sampled >= 32 {
				break
			}
		}
		delete(sh.seen, oldestKey)
	}

	fresh := &atomic.Int64{}
	fresh.Store(unixSec)
	sh.seen[key] = fresh
	sh.mu.Unlock()
}

// TouchClientSeen is the pipeline-facing entry point, called once per admitted
// query from enforceSecurityGuards().
func TouchClientSeen(ip, mac string) {
	if !cfg.WebUI.Enabled {
		return
	}
	now := time.Now().Unix()
	if ip != "" {
		statClientSeen.Touch(ip, now)
	}
	if mac != "" {
		statClientSeen.Touch(mac, now)
	}
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

// Get returns the last-seen unix timestamp for key, or 0 when untracked.
func (t *clientSeenTracker) Get(key string) int64 {
	if key == "" {
		return 0
	}
	sh := t.getShard(key)
	sh.mu.RLock()
	cell, ok := sh.seen[key]
	sh.mu.RUnlock()
	if !ok {
		return 0
	}
	return cell.Load()
}

// Snapshot materialises the whole tracker as a plain map in one pass.
func (t *clientSeenTracker) Snapshot() map[string]int64 {
	out := make(map[string]int64, clientSeenMaxEntries/4)
	for i := 0; i < clientSeenShardCount; i++ {
		sh := t.shards[i]
		sh.mu.RLock()
		for k, v := range sh.seen {
			out[k] = v.Load()
		}
		sh.mu.RUnlock()
	}
	return out
}

// Export serialises the tracker for on-disk persistence (stats.go SaveStats).
func (t *clientSeenTracker) Export() map[string]int64 {
	return t.Snapshot()
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

// Import restores a previously exported map.
func (t *clientSeenTracker) Import(data map[string]int64) {
	if len(data) == 0 {
		return
	}
	cutoff := time.Now().Add(-clientSeenMaxAge).Unix()
	for k, ts := range data {
		if k == "" || ts <= 0 || ts < cutoff {
			continue
		}
		t.Touch(k, ts)
	}
}

// Prune drops every entry whose last-seen instant predates maxAge.
func (t *clientSeenTracker) Prune(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge).Unix()
	for i := 0; i < clientSeenShardCount; i++ {
		sh := t.shards[i]
		sh.mu.Lock()
		for k, v := range sh.seen {
			if v.Load() < cutoff {
				delete(sh.seen, k)
			}
		}
		sh.mu.Unlock()
	}
}

// Clear discards every tracked identity.
func (t *clientSeenTracker) Clear() {
	for i := 0; i < clientSeenShardCount; i++ {
		sh := t.shards[i]
		sh.mu.Lock()
		sh.seen = make(map[string]*atomic.Int64, clientSeenPerShardMax)
		sh.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Presentation helper
// ---------------------------------------------------------------------------

// fmtLastSeenAgo renders a last-seen unix timestamp as a compact relative age.
func fmtLastSeenAgo(ts int64) string {
	if ts <= 0 {
		return "never"
	}
	delta := time.Now().Unix() - ts

	if delta < 0 {
		delta = 0
	}

	switch {
	case delta < 60:
		return "just now"
	case delta < 3600:
		return fmtSeconds((delta/60)*60) + " ago" // whole minutes
	case delta < 86400:
		return fmtSeconds((delta/3600)*3600) + " ago" // whole hours
	default:
		days := delta / 86400
		if days == 1 {
			return "1 day ago"
		}
		return itoa64(days) + " days ago"
	}
}

// itoa64 is a tiny allocation-conscious base-10 formatter for non-negative int64.
func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

