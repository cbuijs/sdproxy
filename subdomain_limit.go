/*
File:    subdomain_limit.go
Version: 1.6.0
Last Updated: 24-Nov-2026 12:56 CET

Description:
  Subdomain Rate Limiting engine for sdproxy.
  Tracks unique subdomains queried per (client/subnet, apex domain) to mitigate
  DNS tunneling and info-stealer exfiltration without cross-client DoS.

Changes:
  1.6.0 - [FIX/PERF] Precomputed `sdlMaxPerShard` with ceiling division once in
          `InitSubdomainLimit`, and guarded `windowStart` comparisons against
          backward NTP wall-clock jumps (`now < bucket.windowStart`).
  1.5.0 - [SECURITY/FIX] Partitioned subdomain limiter tracking by `(client subnet, apex)`
          via `sdlKey` and `/64` IPv6 grouping.
  1.4.0 - [SECURITY/FIX] Fixed `exempt:` domain matching via `isSDLExempt` suffix walk.
  1.3.0 - [FEAT] Added `cfg.Server.SubdomainLimit.ExemptSharedHosting`.
  1.2.0 - [SECURITY/FIX] Protected blocked buckets from premature eviction.
  1.1.0 - [SECURITY/FIX] Replaced sliding `lastUpdate` window with fixed `windowStart`.
  1.0.0 - Initial implementation.
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

const sdlShardCount = 64

type sdlKey struct {
	client netip.Addr
	apex   string
}

type sdlBucket struct {
	subs        map[uint64]struct{}
	windowStart int64
	lastUpdate  int64
	blocked     bool
}

type sdlShard struct {
	sync.Mutex
	buckets map[sdlKey]*sdlBucket
}

var (
	sdlShards      [sdlShardCount]*sdlShard
	sdlHashSeed    maphash.Seed
	sdlExempt      map[string]bool
	sdlMaxPerShard int
)

func addSDLExempt(raw string) {
	for _, part := range strings.Split(raw, ",") {
		clean := strings.ToLower(strings.Trim(strings.TrimSpace(part), "."))
		clean = strings.TrimPrefix(clean, "*.")
		if clean == "" {
			continue
		}
		sdlExempt[clean] = true
	}
}

func isSDLExempt(qname, apex string) bool {
	if len(sdlExempt) == 0 {
		return false
	}
	if apex != "" && sdlExempt[apex] {
		return true
	}
	search := qname
	for {
		if sdlExempt[search] {
			return true
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}
	return false
}

func groupSDLIP(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.Masked().Addr()
		}
	}
	return addr
}

func InitSubdomainLimit() {
	if !cfg.Server.SubdomainLimit.Enabled {
		return
	}
	hasSubdomainLimit = true
	sdlHashSeed = maphash.MakeSeed()

	maxKeys := cfg.Server.SubdomainLimit.MaxTrackedApexes
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	sdlMaxPerShard = max((maxKeys+sdlShardCount-1)/sdlShardCount, 1)

	for i := 0; i < sdlShardCount; i++ {
		sdlShards[i] = &sdlShard{
			buckets: make(map[sdlKey]*sdlBucket),
		}
	}

	sdlExempt = make(map[string]bool)

	for _, d := range cfg.Server.SubdomainLimit.Exempt {
		addSDLExempt(d)
	}

	for _, d := range dgaSafeDomains {
		addSDLExempt(d)
	}

	if cfg.Server.SubdomainLimit.ExemptSharedHosting {
		for d := range sharedHostingDomains {
			addSDLExempt(d)
		}
	}

	if logSystem {
		log.Printf("[SUBDOMAIN-LIMIT] Active: Threshold %d unique subdomains per %d mins | Max Tracked Keys: %d | Exempt Rules: %d (User: %d) | Exempt Shared Hosting: %v | Action: %s",
			cfg.Server.SubdomainLimit.Threshold, cfg.Server.SubdomainLimit.WindowMinutes, maxKeys, len(sdlExempt), len(cfg.Server.SubdomainLimit.Exempt), cfg.Server.SubdomainLimit.ExemptSharedHosting, cfg.Server.SubdomainLimit.Action)
	}

	go runSubdomainLimitSweeper()
}

func getSDLShard(key sdlKey) *sdlShard {
	h := maphash.String(sdlHashSeed, key.apex)
	if key.client.IsValid() {
		b := key.client.As16()
		h ^= maphash.Bytes(sdlHashSeed, b[:]) * 0x9e3779b97f4a7c15
	}
	return sdlShards[h&(sdlShardCount-1)]
}

func AnalyzeSubdomainLimit(clientAddr netip.Addr, qname string) (bool, string) {
	apex, _ := extractETLDPlusOne(qname)
	if apex == "" || apex == qname {
		return true, ""
	}

	if isSDLExempt(qname, apex) {
		return true, ""
	}

	if cfg.Server.SubdomainLimit.ExemptSharedHosting && isSharedHostingDomain(qname) {
		return true, ""
	}

	if isVerifiedAWSDNS(qname) {
		return true, ""
	}

	subdomain := qname
	if len(qname) > len(apex)+1 {
		subdomain = qname[:len(qname)-len(apex)-1]
	}

	key := sdlKey{
		client: groupSDLIP(clientAddr),
		apex:   apex,
	}

	shard := getSDLShard(key)
	now := time.Now().UnixNano()
	windowNanos := int64(cfg.Server.SubdomainLimit.WindowMinutes) * 60 * 1e9

	shard.Lock()
	defer shard.Unlock()

	bucket, exists := shard.buckets[key]
	if !exists {
		if len(shard.buckets) >= sdlMaxPerShard {
			var (
				bestKey       sdlKey
				bestTS        int64
				bestFound     bool
				bestUnblocked bool
				sampled       int
			)
			for k, b := range shard.buckets {
				unblocked := !b.blocked || now < b.windowStart || (now-b.windowStart > windowNanos)
				better := !bestFound ||
					(unblocked && !bestUnblocked) ||
					(unblocked == bestUnblocked && b.lastUpdate < bestTS)
				if better {
					bestKey, bestTS, bestUnblocked, bestFound = k, b.lastUpdate, unblocked, true
				}
				sampled++
				if sampled >= 32 {
					break
				}
			}
			if bestFound {
				delete(shard.buckets, bestKey)
			}
		}

		bucket = &sdlBucket{
			subs:        make(map[uint64]struct{}),
			windowStart: now,
			lastUpdate:  now,
		}
		shard.buckets[key] = bucket
	}

	if now < bucket.windowStart || now-bucket.windowStart > windowNanos {
		clear(bucket.subs)
		bucket.blocked = false
		bucket.windowStart = now
	}

	bucket.lastUpdate = now

	if bucket.blocked {
		return false, cfg.Server.SubdomainLimit.Action
	}

	subHash := maphash.String(sdlHashSeed, subdomain)
	bucket.subs[subHash] = struct{}{}

	if len(bucket.subs) > cfg.Server.SubdomainLimit.Threshold {
		bucket.blocked = true
		return false, cfg.Server.SubdomainLimit.Action
	}

	return true, ""
}

func runSubdomainLimitSweeper() {
	windowNanos := int64(cfg.Server.SubdomainLimit.WindowMinutes) * 60 * 1e9
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			horizon := now - windowNanos

			for i := 0; i < sdlShardCount; i++ {
				shard := sdlShards[i]
				shard.Lock()
				for k, b := range shard.buckets {
					if (now < b.lastUpdate || b.lastUpdate < horizon) && (!b.blocked || now < b.windowStart || now-b.windowStart > windowNanos) {
						delete(shard.buckets, k)
					}
				}
				shard.Unlock()
			}
		case <-shutdownCh:
			return
		}
	}
}
