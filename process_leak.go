/*
File:    process_leak.go
Version: 1.9.0
Last Updated: 24-Nov-2026 12:56 CET

Description:
  Search Domain Leak Prevention (Recent Blocks Tracker) for sdproxy.
  Tracks recently blocked domains to detect and intercept local OS stub
  resolvers appending search domains (e.g., "blocked.com.local.lan") to
  recently blocked queries.

Changes:
  1.9.0 - [SECURITY/FIX] Guarded `checkRecentBlockAppend` and `pruneRecentBlocks`
          against backward wall-clock NTP jumps (`now < b.ts`), preventing stale
          block entries from falsely matching until the clock catches up, and
          guaranteed strict `rbMaxPerShard` enforcement even if all `TryLock`
          samples are contended.
  1.8.0 - [SECURITY/FIX] Replaced `math.MaxInt64` with `time.Now().UnixNano()`
          horizon in `recordRecentBlock`.
  1.7.2 - [SECURITY/FIX] Power-of-N-Choices temporal sampling in `recordRecentBlock`.
  1.7.1 - [FIX] Adjusted `TryLock` evaluation loops.
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

const rbShardCount = 32
const rbMaxPerShard = 512

var (
	rbShards   [rbShardCount]*rbShard
	rbHashSeed maphash.Seed
)

func init() {
	rbHashSeed = maphash.MakeSeed()
	for i := 0; i < rbShardCount; i++ {
		rbShards[i] = &rbShard{clients: make(map[netip.Addr]*clientRecentBlocks)}
	}
}

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

type rbShard struct {
	sync.RWMutex
	clients map[netip.Addr]*clientRecentBlocks
}

type recentBlock struct {
	domain string
	reason string
	ts     int64
}

type clientRecentBlocks struct {
	sync.Mutex
	blocks [4]recentBlock
	idx    int
}

func getRBShard(key netip.Addr) *rbShard {
	b := key.As16()
	h := maphash.Bytes(rbHashSeed, b[:])
	return rbShards[h&(rbShardCount-1)]
}

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
			if len(shard.clients) >= rbMaxPerShard {
				var oldestKey, fallbackKey netip.Addr
				var hasFallback bool
				oldestTS := time.Now().UnixNano() + int64(time.Hour*24*365)
				var sampled int
				var hasOldest bool

				for k, cRef := range shard.clients {
					if !hasFallback {
						fallbackKey = k
						hasFallback = true
					}
					if cRef.TryLock() {
						newest := int64(0)
						for _, b := range cRef.blocks {
							if b.ts > newest {
								newest = b.ts
							}
						}
						cRef.Unlock()

						if !hasOldest || newest < oldestTS {
							oldestTS = newest
							oldestKey = k
							hasOldest = true
						}
						sampled++
					}
					if sampled >= 32 {
						break
					}
				}
				if hasOldest && oldestKey.IsValid() {
					delete(shard.clients, oldestKey)
				} else if hasFallback {
					delete(shard.clients, fallbackKey)
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

	for i := 0; i < 4; i++ {
		b := c.blocks[i]
		if b.ts == 0 || now < b.ts || now-b.ts > 2e9 {
			continue
		}
		if len(qname) > len(b.domain)+1 && strings.HasPrefix(qname, b.domain+".") {
			return b.domain, b.reason
		}
	}
	return "", ""
}

func pruneRecentBlocks(shutdownCh <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	const staleAfter = int64(10 * 60 * 1e9)

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
					if newest == 0 || now < newest || now-newest > staleAfter {
						delete(shard.clients, ip)
					}
				}
				shard.Unlock()
			}
		}
	}
}
