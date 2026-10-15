/*
File:    subdomain_limit.go
Version: 1.1.0
Last Updated: 15-Oct-2026 17:26 CEST

Description:
  Subdomain Rate Limiting engine for sdproxy.
  Tracks unique subdomains queried per apex domain (eTLD+1) natively.
  Mitigates DNS tunneling and info-stealer exfiltration where sensitive 
  data is smuggled via dynamically generated label prefixes.

Changes:
  1.1.0 - [SECURITY/FIX] Replaced sliding `lastUpdate` window checks with a fixed 
          `windowStart` anchor. Previously, sustained queries below the threshold 
          reset `lastUpdate` on every packet, preventing the window from ever 
          expiring and permanently banning active domains.
  1.0.0 - Initial implementation. Features sharded mutex locks for O(1) 
          hot-path throughput, cryptographic map hashing to prevent DoS, 
          and autonomous sampled eviction sweeps.
*/

package main

import (
	"hash/maphash"
	"log"
	"math"
	"strings"
	"sync"
	"time"
)

const sdlShardCount = 64

type sdlBucket struct {
	subs        map[uint64]struct{}
	windowStart int64
	lastUpdate  int64
	blocked     bool
}

type sdlShard struct {
	sync.Mutex
	buckets map[string]*sdlBucket
}

var (
	sdlShards   [sdlShardCount]*sdlShard
	sdlHashSeed maphash.Seed
	sdlExempt   map[string]bool
)

// InitSubdomainLimit initializes the trackers and bounds needed to defend against
// DNS tunneling across dynamic subdomains organically.
func InitSubdomainLimit() {
	if !cfg.Server.SubdomainLimit.Enabled {
		return
	}
	hasSubdomainLimit = true
	sdlHashSeed = maphash.MakeSeed()

	for i := 0; i < sdlShardCount; i++ {
		sdlShards[i] = &sdlShard{
			buckets: make(map[string]*sdlBucket),
		}
	}

	sdlExempt = make(map[string]bool)

	// Ingest operator-defined overrides cleanly
	for _, d := range cfg.Server.SubdomainLimit.Exempt {
		sdlExempt[strings.ToLower(strings.TrimSuffix(d, "."))] = true
	}

	// [SECURITY/PERF] Auto-trust infrastructure platforms explicitly.
	// Massive CDNs and tech platforms organically cycle subdomains natively, 
	// evaluating them through the rate limiter blindly invites severe false positives.
	for _, d := range dgaSafeDomains {
		sdlExempt[strings.ToLower(strings.TrimSuffix(d, "."))] = true
	}

	if logSystem {
		log.Printf("[SUBDOMAIN-LIMIT] Active: Threshold %d unique subdomains per %d mins | Max Apexes: %d | Action: %s",
			cfg.Server.SubdomainLimit.Threshold, cfg.Server.SubdomainLimit.WindowMinutes, cfg.Server.SubdomainLimit.MaxTrackedApexes, cfg.Server.SubdomainLimit.Action)
	}

	go runSubdomainLimitSweeper()
}

// getSDLShard calculates the O(1) lock boundary for the provided apex domain natively.
func getSDLShard(apex string) *sdlShard {
	h := maphash.String(sdlHashSeed, apex)
	return sdlShards[h&(sdlShardCount-1)]
}

// AnalyzeSubdomainLimit evaluates if a specific query name has exceeded 
// its allotted unique subdomains threshold for its apex organically.
// Returns boolean `allowed` and the configured `actionStr` string constraint.
func AnalyzeSubdomainLimit(qname string) (bool, string) {
	apex, _ := extractETLDPlusOne(qname)
	if apex == "" || apex == qname {
		// Bare TLDs or identical apex queries inherently carry no unique subdomains
		return true, ""
	}

	if sdlExempt[apex] {
		return true, ""
	}

	// Subdomain payload is isolated entirely by stripping the suffix boundaries natively
	subdomain := qname
	if len(qname) > len(apex)+1 {
		subdomain = qname[:len(qname)-len(apex)-1]
	}

	shard := getSDLShard(apex)
	now := time.Now().UnixNano()
	windowNanos := int64(cfg.Server.SubdomainLimit.WindowMinutes) * 60 * 1e9

	shard.Lock()
	defer shard.Unlock()

	bucket, exists := shard.buckets[apex]
	if !exists {
		// [SECURITY/FIX] Enforce strict OOM tracking utilizing sampled eviction.
		// Protects legitimate analytics from being permanently overridden 
		// during aggressive cache-miss randomization floods organically.
		if len(shard.buckets) >= cfg.Server.SubdomainLimit.MaxTrackedApexes/sdlShardCount {
			var oldestKey string
			var oldestTS int64 = math.MaxInt64
			var sampled int
			for k, b := range shard.buckets {
				if b.lastUpdate < oldestTS {
					oldestTS = b.lastUpdate
					oldestKey = k
				}
				sampled++
				if sampled >= 32 {
					break
				}
			}
			if oldestKey != "" {
				delete(shard.buckets, oldestKey)
			}
		}

		bucket = &sdlBucket{
			subs:        make(map[uint64]struct{}),
			windowStart: now,
			lastUpdate:  now,
		}
		shard.buckets[apex] = bucket
	}

	// [SECURITY/FIX 1.1.0] Evaluate against windowStart so sustained traffic 
	// cannot infinitely extend the window or lock a blocked domain forever.
	if now-bucket.windowStart > windowNanos {
		clear(bucket.subs)
		bucket.blocked = false
		bucket.windowStart = now
	}

	bucket.lastUpdate = now

	if bucket.blocked {
		return false, cfg.Server.SubdomainLimit.Action
	}

	// Execute mathematical hash compression on the subdomain string to conserve RAM globally
	subHash := maphash.String(sdlHashSeed, subdomain)
	bucket.subs[subHash] = struct{}{}

	// Instant block trigger upon reaching limits
	if len(bucket.subs) > cfg.Server.SubdomainLimit.Threshold {
		bucket.blocked = true
		return false, cfg.Server.SubdomainLimit.Action
	}

	return true, ""
}

// runSubdomainLimitSweeper ensures inactive apex tracking objects are garbage collected
// natively without waiting for arbitrary access operations.
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
					if b.lastUpdate < horizon {
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

