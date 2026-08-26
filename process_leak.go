/*
File:    process_leak.go
Version: 1.5.0
Last Updated: 17-Aug-2026 18:00 CEST

Description:
  Search Domain Leak Prevention (Recent Blocks Tracker) for sdproxy.
  Extracts the highly specific tracking matrix away from the general
  query processing logic to improve modularity.
  Tracks recently blocked domains to detect and intercept underlying operating 
  systems attempting to erroneously append local search domains (e.g., 
  "blocked.com.local.lan") to blocked queries.

Changes:
  1.5.0 - [SECURITY/FIX] Replaced blind map eviction during IPv6 privacy rotation
          floods with Power-of-N-Choices sampled eviction natively. Protects 
          legitimate block telemetry from being indiscriminately scrubbed when 
          tracker capacities saturate organically.
  1.4.0 - [SECURITY/FIX] Closed an unbounded-growth path. Ownership moved here: 
          InitRecentBlocks() now starts the pruner, gated on `searchDomainLeakPrevention`, 
          and is invoked from main.go 1.242.0.
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
			// [SECURITY/FIX] Hard capacity ceiling with sampled eviction.
			// Protects legitimate local search-domain block telemetry from being 
			// randomly discarded during intensive IPv6 privacy rotation floods natively.
			if len(shard.clients) >= rbMaxPerShard {
				var oldestKey netip.Addr
				var oldestTS int64 = 1<<63 - 1
				var sampled int
				
				for k, cRef := range shard.clients {
					cRef.Lock()
					newest := int64(0)
					for _, b := range cRef.blocks {
						if b.ts > newest {
							newest = b.ts
						}
					}
					cRef.Unlock()
					
					if newest < oldestTS {
						oldestTS = newest
						oldestKey = k
					}
					sampled++
					if sampled >= 32 {
						break
					}
				}
				delete(shard.clients, oldestKey)
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
// ceiling enforced in recordRecentBlock.
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

