/*
File:    process_leak.go
Version: 1.3.0
Updated: 23-Jul-2026 12:55 CEST

Description:
  Search Domain Leak Prevention (Recent Blocks Tracker) for sdproxy.
  Extracts the highly specific tracking matrix away from the general
  query processing logic to improve modularity.
  Tracks recently blocked domains to detect and intercept underlying operating 
  systems attempting to erroneously append local search domains (e.g., 
  "blocked.com.local.lan") to blocked queries.

Changes:
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
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Search Domain Leak Prevention (Recent Blocks Tracker)
// ---------------------------------------------------------------------------

const rbShardCount = 32

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
// block event has aged out of relevance, preventing unbounded growth of the
// rbShard.clients map on networks with high client-IP churn (DHCP/CGNAT/
// IPv6 privacy addresses). Runs independently per shard to avoid blocking
// the hot path (recordRecentBlock/checkRecentBlockAppend) for more than the
// duration of a single shard's lock.
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

