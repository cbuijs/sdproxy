/*
File:    process_leak.go
Version: 1.4.0
Last Updated: 05-Aug-2026 17:05 CEST

Description:
  Search Domain Leak Prevention (Recent Blocks Tracker) for sdproxy.
  Extracts the highly specific tracking matrix away from the general
  query processing logic to improve modularity.
  Tracks recently blocked domains to detect and intercept underlying operating 
  systems attempting to erroneously append local search domains (e.g., 
  "blocked.com.local.lan") to blocked queries.

Changes:
  1.4.0 - [SECURITY/FIX] Closed an unbounded-growth path. The only reclaimer for
          rbShards[*].clients — pruneRecentBlocks — was launched from InitCache,
          which returns immediately when `cache.enabled: false`. Any deployment
          running with the cache off and search-domain leak prevention on (the
          default) therefore accumulated one clientRecentBlocks record per
          distinct source address for the entire process lifetime, with nothing
          ever removing them.
          Ownership moved here: InitRecentBlocks() now starts the pruner, gated
          on `searchDomainLeakPrevention`, and is invoked from main.go 1.242.0
          after that flag is resolved from config. The tracker no longer depends
          on an unrelated subsystem's initialisation for its own housekeeping.
        - [SECURITY/FIX] Added a hard per-shard capacity ceiling with
          pseudo-random eviction, mirroring the protection ratelimit.go has
          carried since 1.0. Pruning alone was insufficient even when running:
          it fires on a 10-minute tick, so a spoofed-source flood or ordinary
          IPv6 privacy-address churn could allocate unboundedly BETWEEN ticks.
          The map is now bounded at all times, not merely eventually.
        - [NOTE] recordRecentBlock still re-parses its ipStr argument on every
          block event even though ProcessDNS already holds the unmapped
          netip.Addr. Threading the parsed value through would change
          RecordBlockEvent's signature across ~15 call sites in 6 files, so it
          is deliberately deferred to its own change rather than smuggled into
          a security fix.
  1.3.0 - [PERF] Eradicated massive string-allocation overheads natively on the 
          hot-path. Switched the map hashes, tracking tables, and bounding functions 
          to strictly operate on zero-allocation `netip.Addr` structures.
  1.2.0 - [FEAT] Operation bounds are now dynamically toggleable utilizing the global 
          `search_domain_leak_prevention` configuration switch to conserve memory natively.
  1.1.0 - [SECURITY] Upgraded `getRBShard` hashing mechanism from insecure `FNV-1a` 
          to Go's cryptographically randomized `hash/maphash`. This neutralizes HashDoS 
          vectors, guaranteeing that malicious attackers scanning source IPs cannot 
          deterministically starve the Recent Blocks tracker's Mutex locks.
*/

package main

import (
	"hash/maphash"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Search Domain Leak Prevention (Recent Blocks Tracker)
// ---------------------------------------------------------------------------

const rbShardCount = 32

// rbMaxPerShard bounds each shard's client map.
//
// [SECURITY 1.4.0] Without this, the tracker was bounded only by how often the
// 10-minute pruner happened to run — which on a public resolver is not a bound
// at all. A spoofed-source flood, a CGNAT range, or a LAN full of IPv6 privacy
// addresses rotating every few minutes can mint arbitrarily many distinct keys
// inside a single tick.
//
// 512 × 32 shards ≈ 16.384 tracked clients. Each clientRecentBlocks holds a
// 4-slot ring of {domain, reason, ts}, so the worst case sits in the low
// single-digit megabytes — comfortable even on the embedded routers this
// project targets, while being far beyond any plausible legitimate client
// count for a search-domain heuristic whose useful correlation window is 2
// seconds wide.
const rbMaxPerShard = 512

var (
	rbShards [rbShardCount]*rbShard
	rbHashSeed maphash.Seed
)

func init() {
	rbHashSeed = maphash.MakeSeed()
	for i := 0; i < rbShardCount; i++ {
		rbShards[i] = &rbShard{clients: make(map[netip.Addr]*clientRecentBlocks)}
	}
}

// InitRecentBlocks starts the background reclaimer for the recent-blocks
// tracker. Called once from main() AFTER searchDomainLeakPrevention has been
// resolved from configuration.
//
// [SECURITY/FIX 1.4.0] This launch previously lived inside InitCache, which
// returns early when the cache is disabled — silently leaving the tracker with
// no reclaimer at all in that configuration. Housekeeping for this subsystem
// now belongs to this subsystem.
//
// When leak prevention is disabled nothing is started: recordRecentBlock is
// never called in that mode (see RecordBlockEvent), so the maps stay empty and
// a pruner goroutine would be pure overhead.
func InitRecentBlocks() {
	if !searchDomainLeakPrevention {
		if logSystem {
			log.Println("[LEAK] Search-domain leak prevention disabled — recent-blocks tracker inactive.")
		}
		return
	}
	if logSystem {
		log.Printf("[LEAK] Search-domain leak prevention active (tracker bound: %d shards × %d clients).",
			rbShardCount, rbMaxPerShard)
	}
	go pruneRecentBlocks(shutdownCh)
}

// rbShard independently locks a segment of recent-block trackers, preventing 
// global lock contention across parallel DNS query resolutions.
type rbShard struct {
	sync.RWMutex
	clients map[netip.Addr]*clientRecentBlocks
}

// recentBlock tracks a localized block event chronologically to evaluate 
// subsequent queries for leakage.
type recentBlock struct {
	domain string
	reason string
	ts     int64
}

// clientRecentBlocks maintains a 4-slot ring buffer per client IP.
type clientRecentBlocks struct {
	sync.Mutex
	blocks [4]recentBlock
	idx    int
}

// getRBShard securely computes the target shard array index using a rapid 
// and cryptographically seeded maphash distribution against the binary IP mapping natively.
func getRBShard(key netip.Addr) *rbShard {
	b := key.As16()
	h := maphash.Bytes(rbHashSeed, b[:])
	return rbShards[h&(rbShardCount-1)]
}

// recordRecentBlock registers a domain block event in the client's localized 
// ring buffer to facilitate search-domain leak protections on immediate subsequent queries.
func recordRecentBlock(ipStr, domain, reason string) {
	if ipStr == "" || domain == "" {
		return
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}
	addr = addr.Unmap()

	shard := getRBShard(addr)
	shard.RLock()
	c, exists := shard.clients[addr]
	shard.RUnlock()

	if !exists {
		shard.Lock()
		c, exists = shard.clients[addr]
		if !exists {
			// [SECURITY 1.4.0] Hard capacity ceiling with pseudo-random
			// eviction, identical in shape to the guard in AllowClient.
			//
			// Go randomises map iteration order, so the first key yielded is a
			// statistically uniform victim across the shard — no scan, no
			// bookkeeping, O(1). Evicting a live client at worst costs one
			// missed search-domain correlation on its next query, which is a
			// heuristic optimisation, not a security control. Growing without
			// limit, by contrast, is an OOM.
			if len(shard.clients) >= rbMaxPerShard {
				for k := range shard.clients {
					delete(shard.clients, k)
					break
				}
			}
			c = &clientRecentBlocks{}
			shard.clients[addr] = c
		}
		shard.Unlock()
	}

	c.Lock()
	c.blocks[c.idx] = recentBlock{domain: domain, reason: reason, ts: time.Now().UnixNano()}
	c.idx = (c.idx + 1) % 4
	c.Unlock()
}

// checkRecentBlockAppend interrogates the client's recently blocked queries buffer.
// If the OS stub resolver is attempting to resolve a blocked domain appended with a local
// search suffix (e.g., "blockeddomain.com.home.arpa"), it detects the prefix correlation
// and signals a preemptive drop to save execution cycles.
func checkRecentBlockAppend(addr netip.Addr, qname string) (string, string) {
	if !addr.IsValid() || qname == "" {
		return "", ""
	}
	shard := getRBShard(addr)
	shard.RLock()
	c, exists := shard.clients[addr]
	shard.RUnlock()

	if !exists {
		return "", ""
	}

	now := time.Now().UnixNano()
	c.Lock()
	defer c.Unlock()

	// Evaluate against the 4 most recent localized blocks strictly within a 2-second horizon.
	for i := 0; i < 4; i++ {
		b := c.blocks[i]
		if b.ts == 0 || now-b.ts > 2e9 { 
			continue
		}
		if len(qname) > len(b.domain)+1 && strings.HasPrefix(qname, b.domain+".") {
			return b.domain, b.reason
		}
	}
	return "", ""
}

// pruneRecentBlocks periodically removes client entries whose most recent
// block event has aged out of relevance, complementing the hard rbMaxPerShard
// ceiling enforced in recordRecentBlock: the ceiling stops the map exploding,
// the pruner stops it staying full of clients that have long gone quiet.
//
// Runs independently per shard so the hot path (recordRecentBlock /
// checkRecentBlockAppend) never blocks for longer than a single shard's lock.
//
// [1.4.0] Started by InitRecentBlocks(), not by InitCache().
func pruneRecentBlocks(shutdownCh <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	const staleAfter = int64(10 * 60 * 1e9) // 10 minutes in ns

	for {
		select {
		case <-shutdownCh:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			for _, shard := range rbShards {
				shard.Lock()
				for ip, c := range shard.clients {
					c.Lock()
					newest := int64(0)
					for _, b := range c.blocks {
						if b.ts > newest {
							newest = b.ts
						}
					}
					c.Unlock()
					if newest == 0 || now-newest > staleAfter {
						delete(shard.clients, ip)
					}
				}
				shard.Unlock()
			}
		}
	}
}
