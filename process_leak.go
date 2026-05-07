/*
File:    process_leak.go
Version: 1.1.0
Updated: 20-Apr-2026 17:15 CEST

Description:
  Search Domain Leak Prevention (Recent Blocks Tracker) for sdproxy.
  Extracts the highly specific tracking matrix away from the general
  query processing logic to improve modularity.
  Tracks recently blocked domains to detect and intercept underlying operating 
  systems attempting to erroneously append local search domains (e.g., 
  "blocked.com.local.lan") to blocked queries.

Changes:
  1.1.0 - [SECURITY] Upgraded `getRBShard` hashing mechanism from insecure `FNV-1a` 
          to Go's cryptographically randomized `hash/maphash`. This neutralizes HashDoS 
          vectors, guaranteeing that malicious attackers scanning source IPs cannot 
          deterministically starve the Recent Blocks tracker's Mutex locks.
  1.0.0 - Initial split from process.go v3.19.0.
*/

package main

import (
	"hash/maphash"
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
		rbShards[i] = &rbShard{clients: make(map[string]*clientRecentBlocks)}
	}
}

// rbShard independently locks a segment of recent-block trackers, preventing 
// global lock contention across parallel DNS query resolutions.
type rbShard struct {
	sync.RWMutex
	clients map[string]*clientRecentBlocks
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
// and cryptographically seeded maphash distribution.
func getRBShard(ip string) *rbShard {
	h := maphash.String(rbHashSeed, ip)
	return rbShards[h&(rbShardCount-1)]
}

// recordRecentBlock registers a domain block event in the client's localized 
// ring buffer to facilitate search-domain leak protections on immediate subsequent queries.
func recordRecentBlock(ip, domain, reason string) {
	if ip == "" || domain == "" {
		return
	}
	shard := getRBShard(ip)
	shard.RLock()
	c, exists := shard.clients[ip]
	shard.RUnlock()

	if !exists {
		shard.Lock()
		c, exists = shard.clients[ip]
		if !exists {
			c = &clientRecentBlocks{}
			shard.clients[ip] = c
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
func checkRecentBlockAppend(ip, qname string) (string, string) {
	if ip == "" || qname == "" {
		return "", ""
	}
	shard := getRBShard(ip)
	shard.RLock()
	c, exists := shard.clients[ip]
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

