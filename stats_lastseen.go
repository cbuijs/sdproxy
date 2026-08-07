/*
File:    stats_lastseen.go
Version: 1.0.0
Last Updated: 07-Aug-2026 14:20 CEST

Description:
  Per-client "last seen" tracking for sdproxy.

  Records the wall-clock instant at which each known client (keyed by source IP
  AND, when resolvable, by MAC address) last presented a query that survived the
  admission pipeline. Consumed exclusively by the Web UI "Known Clients &
  Blocking" table, which renders it as a relative age ("3m ago", "2d ago").

  Why this is a dedicated structure rather than a reuse of the Top-N trackers:

    • topTracker (stats_topn.go) bins hits into HOURLY buckets and stores only
      a counter per bucket. The finest "last seen" it could ever reconstruct is
      therefore "some time during hour X" — an hour of granularity for a field
      whose entire purpose is to answer "is this device on the network right
      now?". Useless for the intended question.

    • arpSnap (arp.go) knows only what the kernel neighbour table knows: it goes
      stale within minutes on a quiet host, expires entries wholesale, and says
      nothing at all about clients reaching sdproxy over DoH/DoT/DoQ from off-
      link. It answers "is there an L2 adjacency", not "did this client resolve
      anything".

    • identSnap (identity.go) is a static mapping harvested from DHCP leases and
      hosts files. It carries no notion of activity whatsoever.

  Design constraints this file is built against:

    HOT PATH — Touch() is called once per admitted query from
    enforceSecurityGuards(). The overwhelmingly common case is "this client is
    already tracked", so that case must cost exactly one RWMutex read-lock, one
    map lookup and one atomic store, with zero heap allocation. The write lock
    is taken only when a genuinely new client appears.

    SHARDING — 32 independent shards keyed by maphash, mirroring topTracker's
    layout. On a multi-core resolver serving tens of thousands of QPS, a single
    global lock on this structure would serialise the entire admission stage;
    sharding drops contention to effectively nothing since a given client hashes
    to exactly one shard.

    BOUNDED MEMORY (PUBLIC-NETWORK HARDENING) — On a publicly reachable
    resolver, the key space is attacker-controlled: every spoofed source address
    would otherwise mint a permanent map entry. The tracker is therefore capped
    at clientSeenMaxEntries in total (clientSeenPerShardMax per shard) with
    oldest-first eviction, so a source-address flood costs a bounded, small,
    fixed amount of memory and preferentially discards the addresses that have
    been quiet the longest — which is exactly the eviction order a "last seen"
    view wants anyway.

    PERSISTENCE — Exported into webui_stats.json alongside the Top-N trackers
    (stats.go) so a daemon restart does not blank the column. Entries older than
    clientSeenMaxAge are dropped on import and on the hourly prune.

Changes:
  1.0.0 - [FEAT] Initial implementation. Sharded, allocation-free-on-hot-path
          last-seen tracker with a hard entry ceiling, oldest-first eviction,
          age-based pruning, JSON export/import and a relative-age formatter
          (fmtLastSeenAgo) shared by the server-side HTML builder.
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
//
// 32 matches topShardCount in stats_topn.go deliberately: the two structures
// are written from the same call site on the same goroutine, so giving them the
// same fan-out keeps their contention profiles identical and avoids one turning
// into the bottleneck the other was sharded to avoid. Must remain a power of
// two — getShard() masks rather than divides.
const clientSeenShardCount = 32

// clientSeenMaxEntries is the process-wide ceiling on tracked identities.
//
// 8192 comfortably covers any realistic LAN (a /24 is 254 hosts; even a large
// campus segment with IPv6 privacy-address churn stays well inside this), while
// bounding worst-case memory to roughly 8192 × (key string + map overhead +
// one atomic.Int64) ≈ 1 MB. That is the amount an attacker can force us to
// spend by flooding spoofed sources — a fixed, trivial cost rather than an
// unbounded growth vector.
const clientSeenMaxEntries = 8192

// clientSeenPerShardMax is the per-shard derivation of the global ceiling.
//
// Enforcing the cap per shard rather than globally is what keeps the eviction
// scan cheap: at 256 entries a full linear scan for the oldest timestamp is a
// few microseconds, and it runs ONLY when a brand-new client arrives at an
// already-full shard. A global cap would have required either a shared counter
// (contention) or a cross-shard scan (32× the work) on that same path.
//
// maphash distributes keys uniformly, so per-shard capping costs a small amount
// of headroom versus a true global cap; that is an acceptable trade for keeping
// the hot path lock-local.
const clientSeenPerShardMax = clientSeenMaxEntries / clientSeenShardCount

// clientSeenMaxAge is the retention horizon for a last-seen record.
//
// Deliberately NOT tied to retentionHours(): that value governs the statistics
// graphs (default 24h), and a device that last spoke 26 hours ago is precisely
// the device an operator most wants to see listed as "1d ago" rather than
// silently vanishing from the table. 30 days is long enough to keep occasional
// visitors (a guest laptop, a seasonal device) meaningful, and the entry
// ceiling above — not this horizon — is the real memory bound.
const clientSeenMaxAge = 30 * 24 * time.Hour

// ---------------------------------------------------------------------------
// Tracker structures
// ---------------------------------------------------------------------------

// clientSeenShard is one independently locked partition of the tracker.
//
// The value type is *atomic.Int64 rather than a plain int64 so that the common
// "client already tracked" update can be performed under a READ lock: the map
// itself is not mutated (no rehash, no bucket write), only the pointed-to
// counter, which is updated atomically. A plain int64 value would have forced
// every single query to take the exclusive write lock.
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
			// Pre-size to the shard ceiling: the map never legitimately grows
			// past it, so this buys us a single allocation up front instead of
			// a rehash cascade as a network populates.
			seen: make(map[string]*atomic.Int64, clientSeenPerShardMax),
		}
	}
	return t
}

// getShard maps an identity key onto its owning shard.
//
// maphash is seeded per-process, so the shard assignment is not predictable
// from outside — an attacker cannot deliberately steer every spoofed source
// onto one shard to concentrate lock contention or eviction pressure there.
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
//
// Fast path (client already known): RLock -> map read -> RUnlock -> atomic
// store. No allocation, no exclusive lock, no map mutation.
//
// Slow path (new client): exclusive lock, double-checked insert, and — only if
// the shard is at its ceiling — a bounded oldest-first eviction scan.
//
// The atomic store is an unconditional Store rather than a
// compare-and-swap-if-newer loop. Two goroutines racing here are both writing
// time.Now() for the same client within nanoseconds of each other, so the
// worst possible outcome of losing the race is a sub-second-stale value in a
// field rendered at minute granularity. A CAS loop would buy nothing and cost
// a retry branch on the hottest path in the admission stage.
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
	// Double-check: another goroutine may have inserted this exact key between
	// our RUnlock and Lock above.
	if cell, ok := sh.seen[key]; ok {
		sh.mu.Unlock()
		cell.Store(unixSec)
		return
	}

	// Hard ceiling enforcement. Only reachable on a genuinely new key against a
	// full shard, so the linear scan below is amortised to near zero on a
	// stable network and bounded to clientSeenPerShardMax comparisons even
	// under a deliberate source-address flood.
	if len(sh.seen) >= clientSeenPerShardMax {
		var oldestKey string
		var oldestTS int64 = math.MaxInt64
		for k, v := range sh.seen {
			if ts := v.Load(); ts < oldestTS {
				oldestTS = ts
				oldestKey = k
			}
		}
		// oldestKey is guaranteed non-empty here: the map is non-empty (its
		// length is >= clientSeenPerShardMax >= 1) and Touch never inserts an
		// empty key.
		delete(sh.seen, oldestKey)
	}

	fresh := &atomic.Int64{}
	fresh.Store(unixSec)
	sh.seen[key] = fresh
	sh.mu.Unlock()
}

// TouchClientSeen is the pipeline-facing entry point, called once per admitted
// query from enforceSecurityGuards().
//
// Both identities are recorded independently because the Web UI table may know
// a client by either one: a DHCP-leased host appears with both IP and MAC, an
// off-link DoH client has only an IP, and a MAC harvested from a lease file
// whose address has since changed appears with only a MAC.
//
// Gated on cfg.WebUI.Enabled — with the dashboard off there is no consumer, and
// a headless resolver should not pay even this small cost, exactly as
// IncrTalker/IncrDomain are gated.
func TouchClientSeen(ip, mac string) {
	if !cfg.WebUI.Enabled {
		return
	}
	// One clock read shared by both keys: time.Now() is a vDSO call, cheap but
	// not free, and calling it twice would additionally let the two identities
	// of the same client disagree by a nanosecond for no benefit.
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
//
// Prefer Snapshot() when resolving more than a handful of keys in one pass —
// see the note there.
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
//
// getKnownClients() needs a lookup for the IP AND the MAC of every row it
// renders. Servicing those through Get() would mean 2N lock/unlock round trips
// scattered across all 32 shards on the Web UI request thread, interleaved with
// the DNS hot path taking those same locks. One sequential pass instead takes
// each shard's read lock exactly once, holds it for a bounded copy, and hands
// the caller a lock-free structure to finish against.
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
// Identical shape to Snapshot; kept as a distinct name so the persistence
// call sites read symmetrically with the Top-N trackers' Export().
func (t *clientSeenTracker) Export() map[string]int64 {
	return t.Snapshot()
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

// Import restores a previously exported map, discarding anything already older
// than clientSeenMaxAge.
//
// Routed through Touch() rather than writing the shard maps directly so that
// the entry ceiling and eviction policy apply to restored data exactly as they
// do to live data — a webui_stats.json that was hand-edited, corrupted, or
// carried over from a much larger deployment cannot be used to blow past the
// memory bound at startup.
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
//
// Called from recordHourSlot() alongside the Top-N cascade prune. Deleting
// under the exclusive lock is safe during range in Go (deletion of the current
// or of not-yet-visited keys is explicitly permitted by the spec), so this
// needs no two-phase collect/delete.
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

// Clear discards every tracked identity. Invoked from ResetStats() so that
// "reset statistics" in the Web UI genuinely resets everything the dashboard
// displays, rather than leaving a stale Last Seen column behind.
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
//
// Used by buildClientsHTML() for the server-rendered first paint. The browser
// re-renders the same values client-side (script.js) so the column keeps
// ticking between the 60-second /api/clients polls; both implementations use
// the identical thresholds and wording so the label never visibly jumps when
// JavaScript takes over.
//
// Returns "never" for the zero value — a client that is present in the ARP or
// DHCP tables but has not (yet) resolved anything through sdproxy.
func fmtLastSeenAgo(ts int64) string {
	if ts <= 0 {
		return "never"
	}
	delta := time.Now().Unix() - ts

	// A negative delta means the record is stamped in the future: a clock step
	// (NTP correction, VM resume, container host skew) landed between the Touch
	// and this render. Treat it as "now" rather than emitting a nonsensical
	// negative age.
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
		// Deliberately not fmtSeconds: that helper caps at hours, so a
		// fortnight-old device would render as "336h" instead of "14 days".
		return itoa64(days) + " days ago"
	}
}

// itoa64 is a tiny allocation-conscious base-10 formatter for the day count.
//
// strconv.FormatInt would do the same job; this exists only so that
// stats_lastseen.go does not pull strconv in for a single call site, keeping
// the file's import surface to what the tracker itself genuinely needs.
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
