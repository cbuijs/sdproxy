/*
File:    stats_topn.go
Version: 1.5.0
Updated: 02-May-2026 11:14 CEST

Description:
  Top-N tracking structures and global instances for sdproxy.
  Extracted from stats.go to improve modularity and reduce token burn.
  Tracks domains, blocked reasons, talkers, IPs, categories, TLDs,
  vendors, groups, upstreams, upstream hosts, return codes, and NXDOMAINs.

Changes:
  1.5.0 - [PERF/FIX] Increased `topMaxSize` significantly from 2000 to 50000. 
          This ensures high-volume Top-N tracker shards do not prematurely 
          evict legitimate traffic metrics during localized network bursts 
          or heavy ad-tracking storms.
  1.4.0 - [SECURITY/FIX] Resolved a structural key-collision regression in the 
          JSON serialization engine. Replaced the vulnerable pipe (`|`) string 
          delimiter with a null byte (`\x00`) to guarantee that user-defined 
          reasons or policies containing pipes cannot corrupt historical analytics 
          on reboot. Maintains backward compatibility with legacy snapshots natively.
  1.3.0 - [PERF] Eliminated massive global lock contention on the hot-path by sharding 
          the TopTracker implementation. Mutexes are now distributed securely across 32 buckets 
          via cryptographic `hash/maphash` distribution, radically improving throughput 
          on low-power routers under extreme volumetric query floods.
*/

package main

import (
	"fmt"
	"hash/maphash"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Top-N tracker
// ---------------------------------------------------------------------------

// topMaxSize is the maximum number of unique keys per tracker globally.
// Increased safely to 50000 to prevent malicious floods or dense ad-networks 
// from prematurely exhausting capacity and blinding legitimate metrics natively.
const topMaxSize = 50000

// topShardCount specifies the number of independent locks used to shard 
// the tracker map. 32 eliminates virtually all lock contention on 
// heavily threaded multicore routing deployments.
const topShardCount = 32

// TopEntry is one row in a top-N ranked list returned by /api/stats.
type TopEntry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Hint  string `json:"hint,omitempty"` // Used for reasons (blocked) or hostnames (talkers)
}

// trackKey is a struct used as a map key to independently track combinations.
type trackKey struct {
	id   string
	hint string
}

// topTrackerShard manages a locked slice of the active hourly bins.
type topTrackerShard struct {
	mu         sync.Mutex
	hourlyHits map[int64]map[trackKey]int64
}

// topTracker is a bounded frequency map safe for concurrent use.
// It bins hits chronologically into hourly maps to correctly honor retention
// horizons and prevent unbounded lifetime growth. Uses 32 distinct shards to 
// bypass Mutex saturation across highly parallel worker floods.
type topTracker struct {
	seed   maphash.Seed
	shards [topShardCount]*topTrackerShard
}

// newTopTracker allocates a fresh securely-sharded tracker.
func newTopTracker() *topTracker {
	t := &topTracker{
		seed: maphash.MakeSeed(),
	}
	for i := 0; i < topShardCount; i++ {
		t.shards[i] = &topTrackerShard{
			hourlyHits: make(map[int64]map[trackKey]int64),
		}
	}
	return t
}

// getShard safely bounds the tracker key to a specific bucket via maphash.
func (t *topTracker) getShard(id string) *topTrackerShard {
	h := maphash.String(t.seed, id)
	return t.shards[h&(topShardCount-1)]
}

// Add increments the count for the id/hint pair within the current hour bucket.
func (t *topTracker) Add(id, hint string) {
	shard := t.getShard(id)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	ep := time.Now().Unix() / 3600
	bucket, ok := shard.hourlyHits[ep]
	if !ok {
		bucket = make(map[trackKey]int64)
		shard.hourlyHits[ep] = bucket
	}

	k := trackKey{id: id, hint: hint}
	
	// Hard memory cap per shard prevents abusive unique-domain generation vectors (HashDoS)
	if _, exists := bucket[k]; !exists && len(bucket) >= (topMaxSize/topShardCount) {
		return 
	}
	bucket[k]++
}

// TopN returns up to n entries sorted by count descending within the retention window.
func (t *topTracker) TopN(n int) []TopEntry {
	minHour := (time.Now().Unix() / 3600) - int64(retentionHours()) + 1
	totals := make(map[trackKey]int64)

	for i := 0; i < topShardCount; i++ {
		shard := t.shards[i]
		shard.mu.Lock()
		for ep, bucket := range shard.hourlyHits {
			if ep >= minHour {
				for k, v := range bucket {
					totals[k] += v
				}
			}
		}
		shard.mu.Unlock()
	}

	out := make([]TopEntry, 0, len(totals))
	for k, v := range totals {
		out = append(out, TopEntry{Name: k.id, Count: v, Hint: k.hint})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > len(out) {
		n = len(out)
	}
	return out[:n]
}

// Prune cleanly discards map buckets older than the designated retention horizon.
func (t *topTracker) Prune(rh int) {
	minHour := (time.Now().Unix() / 3600) - int64(rh) + 1
	for i := 0; i < topShardCount; i++ {
		shard := t.shards[i]
		shard.mu.Lock()
		for ep := range shard.hourlyHits {
			if ep < minHour {
				delete(shard.hourlyHits, ep)
			}
		}
		shard.mu.Unlock()
	}
}

// Clear deletes all buckets, completely resetting the tracker instance.
func (t *topTracker) Clear() {
	for i := 0; i < topShardCount; i++ {
		shard := t.shards[i]
		shard.mu.Lock()
		shard.hourlyHits = make(map[int64]map[trackKey]int64)
		shard.mu.Unlock()
	}
}

// Export serializes the tracker into a string-keyed map for JSON stability.
func (t *topTracker) Export() map[string]map[string]int64 {
	res := make(map[string]map[string]int64)
	for i := 0; i < topShardCount; i++ {
		shard := t.shards[i]
		shard.mu.Lock()
		for ep, bucket := range shard.hourlyHits {
			strEp := strconv.FormatInt(ep, 10)
			if res[strEp] == nil {
				res[strEp] = make(map[string]int64)
			}
			b := res[strEp]
			for k, v := range bucket {
				// Use \x00 as delimiter to prevent collisions with reason strings natively
				b[k.id+"\x00"+k.hint] = v
			}
		}
		shard.mu.Unlock()
	}
	return res
}

// Import unmarshals a JSON struct back into the tracker safely.
func (t *topTracker) Import(data map[string]map[string]int64) {
	t.Clear()
	for strEp, bucket := range data {
		ep, err := strconv.ParseInt(strEp, 10, 64)
		if err != nil {
			continue
		}
		for strKey, v := range bucket {
			// Support legacy "|" delimiter for backward compatibility with older snapshots
			delim := "\x00"
			if !strings.Contains(strKey, "\x00") && strings.Contains(strKey, "|") {
				delim = "|"
			}
			
			parts := strings.SplitN(strKey, delim, 2)
			var id, hint string
			if len(parts) == 2 {
				id = parts[0]
				hint = parts[1]
			} else {
				id = strKey
			}

			shard := t.getShard(id)
			shard.mu.Lock()
			b, ok := shard.hourlyHits[ep]
			if !ok {
				b = make(map[trackKey]int64)
				shard.hourlyHits[ep] = b
			}
			b[trackKey{id: id, hint: hint}] += v
			shard.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Global top-N tracker instances
// ---------------------------------------------------------------------------

var (
	statTopDomains       = newTopTracker()
	statTopBlocked       = newTopTracker()
	statTopTalkers       = newTopTracker()
	statTopFilteredIPs   = newTopTracker()
	statTopCategories    = newTopTracker()
	statTopTLDs          = newTopTracker()
	statTopVendors       = newTopTracker()
	statTopGroups        = newTopTracker()
	statTopBlockReasons  = newTopTracker()
	statTopUpstreams     = newTopTracker()
	statTopUpstreamHosts = newTopTracker()
	statTopReturnCodes   = newTopTracker()
	statTopNXDomain      = newTopTracker()
)

// IncrDomain records one query for domain in the top-domains tracker.
func IncrDomain(domain string) {
	if !cfg.WebUI.Enabled || domain == "" {
		return
	}
	statTopDomains.Add(domain, "")

	// Extract the eTLD+1 (domain apex) and eTLD itself using the helpers from publicsuffix.go
	eTLDPlusOne, eTLD := extractETLDPlusOne(domain)

	// TLD Tracking
	tld := eTLD
	if idx := strings.LastIndexByte(eTLD, '.'); idx >= 0 {
		tld = eTLD[idx+1:]
	}
	hint := getTLDHint(tld)

	// Prepend with a dot for UI display clarity, unless it already has one.
	displayTLD := eTLD
	if !strings.HasPrefix(displayTLD, ".") {
		displayTLD = "." + displayTLD
	}
	statTopTLDs.Add(displayTLD, hint)

	// Vendor Tracking
	if vendor := getVendor(eTLDPlusOne); vendor != "" {
		statTopVendors.Add(vendor, "")
	}
}

// IncrBlockedDomain records one block event for domain alongside its reason.
// It simultaneously increments the Top Block Reasons tracker for that specific reason.
func IncrBlockedDomain(domain, reason string) {
	if !cfg.WebUI.Enabled {
		return
	}
	statTopBlocked.Add(domain, reason)
	if reason != "" {
		statTopBlockReasons.Add(reason, "")
	}
}

// IncrTalker records one query from client ip.
// When name is non-empty the UI shows "hostname (ip)" in the top-talkers list.
func IncrTalker(ip, name string) { 
	if !cfg.WebUI.Enabled { return }
	if ip == "" { return } // [FIX] Prevent tracking internal/empty IPs
	statTopTalkers.Add(ip, name) 
}

// IncrFilteredIP records an IP address removed from upstream responses.
func IncrFilteredIP(ip, reason string) { 
	if !cfg.WebUI.Enabled { return }
	statTopFilteredIPs.Add(ip, reason) 
}

// IncrCategory records one query that matched a known parental category.
// If cat is empty (uncategorised domain), it is tracked as "unknown".
func IncrCategory(cat string) {
	if !cfg.WebUI.Enabled { return }
	if cat == "" {
		cat = "unknown"
	}
	statTopCategories.Add(cat, "")
}

// IncrGroup records one query that was assigned to a configured client group.
func IncrGroup(group string) {
	if !cfg.WebUI.Enabled || group == "" { return }
	statTopGroups.Add(group, "")
}

// IncrUpstream records the designated upstream routing group for a query.
func IncrUpstream(upstream string) {
	if !cfg.WebUI.Enabled || upstream == "" { return }
	statTopUpstreams.Add(upstream, "")
}

// IncrUpstreamHost records the specific upstream host and IP address that handled the query.
func IncrUpstreamHost(host string) {
	if !cfg.WebUI.Enabled || host == "" { return }
	statTopUpstreamHosts.Add(host, "")
}

// IncrReturnCode records an RCODE from the upstream response. 
func IncrReturnCode(rcode int, isNullIP bool) {
	if !cfg.WebUI.Enabled { return }
	var rcodeStr string
	if isNullIP {
		rcodeStr = "NULL-IP"
	} else {
		if str, ok := dns.RcodeToString[rcode]; ok {
			rcodeStr = str
		} else {
			rcodeStr = fmt.Sprintf("RCODE:%d", rcode)
		}
	}
	statTopReturnCodes.Add(rcodeStr, "")
}

// IncrNXDomain records a domain that resulted in an NXDOMAIN response during resolution.
func IncrNXDomain(domain string) {
	if !cfg.WebUI.Enabled || domain == "" { return }
	statTopNXDomain.Add(domain, "")
}

