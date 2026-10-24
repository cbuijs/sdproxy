/*
File:    subdomain_limit.go
Version: 1.4.0
Last Updated: 24-Oct-2026 11:42 CEST

Description:
  Subdomain Rate Limiting engine for sdproxy.
  Tracks unique subdomains queried per apex domain (eTLD+1) natively.
  Mitigates DNS tunneling and info-stealer exfiltration where sensitive 
  data is smuggled via dynamically generated label prefixes.

Changes:
  1.4.0 - [SECURITY/FIX] Fixed `exempt:` domain matching in `AnalyzeSubdomainLimit`
          and `addSDLExempt`:
          1. Added a label-by-label suffix walk (`isSDLExempt`) so single-label/TLD
             exemptions (e.g. `arpa`, `local`), multi-label subdomain exemptions
             (e.g. `in-addr.arpa`, `ip6.arpa`, `dns.quad9.net`), and comma-separated
             entries in `exempt:` match the queried domain and all of its subdomains
             instead of only checking `sdlExempt[apex]`.
          2. Stopped `addSDLExempt` from promoting multi-label exemptions (such as
             `in-addr.arpa`, `ip6.arpa`, or `dns.quad9.net`) to their parent eTLD+1
             only, while avoiding poisoning entire TLDs unless explicitly configured.
  1.3.0 - [FEAT] Added support for `cfg.Server.SubdomainLimit.ExemptSharedHosting`
          to optionally exempt all domains (and their eTLD+1 apexes) in
          `sharedHostingDomains` (`sharedhosting.go`) from subdomain limit tracking.
        - [FIX] Normalized multi-label entries in `exempt:` and `dgaSafeDomains`
          (e.g. `dns.quad9.net`) via `extractETLDPlusOne` and checked both `apex`
          and `isSharedHostingDomain(qname)` when `exempt_shared_hosting` is enabled.
  1.2.0 - [SECURITY/FIX] Prevented newly created `sdlBucket` entries from evicting
          active or blocked buckets before `bucket.blocked` expires.
  1.1.0 - [SECURITY/FIX] Replaced sliding `lastUpdate` window checks with a fixed 
          `windowStart` anchor.
  1.0.0 - Initial implementation.
*/

package main

import (
	"hash/maphash"
	"log"
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

// addSDLExempt registers one or more comma-separated domain suffixes in sdlExempt.
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

// isSDLExempt performs a zero-allocation label-by-label suffix walk over qname
// and also checks the extracted apex, ensuring bare TLDs ("arpa", "local"),
// zone delegations ("in-addr.arpa", "ip6.arpa"), apexes ("example.com"), and
// specific sub-trees ("sub.example.com") in sdlExempt all match any subdomain.
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
		addSDLExempt(d)
	}

	// Auto-trust infrastructure platforms explicitly.
	for _, d := range dgaSafeDomains {
		addSDLExempt(d)
	}

	// Optionally include sharedHostingDomains from sharedhosting.go
	if cfg.Server.SubdomainLimit.ExemptSharedHosting {
		for d := range sharedHostingDomains {
			addSDLExempt(d)
		}
	}

	if logSystem {
		log.Printf("[SUBDOMAIN-LIMIT] Active: Threshold %d unique subdomains per %d mins | Max Apexes: %d | Exempt Rules: %d (User: %d) | Exempt Shared Hosting: %v | Action: %s",
			cfg.Server.SubdomainLimit.Threshold, cfg.Server.SubdomainLimit.WindowMinutes, cfg.Server.SubdomainLimit.MaxTrackedApexes, len(sdlExempt), len(cfg.Server.SubdomainLimit.Exempt), cfg.Server.SubdomainLimit.ExemptSharedHosting, cfg.Server.SubdomainLimit.Action)
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

	if isSDLExempt(qname, apex) {
		return true, ""
	}

	if cfg.Server.SubdomainLimit.ExemptSharedHosting && isSharedHostingDomain(qname) {
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
		maxPerShard := cfg.Server.SubdomainLimit.MaxTrackedApexes / sdlShardCount
		if maxPerShard < 1 {
			maxPerShard = 1
		}
		if len(shard.buckets) >= maxPerShard {
			var (
				bestKey       string
				bestTS        int64
				bestFound     bool
				bestUnblocked bool
				sampled       int
			)
			for k, b := range shard.buckets {
				unblocked := !b.blocked || (now-b.windowStart > windowNanos)
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
			if bestFound && bestKey != "" {
				delete(shard.buckets, bestKey)
			}
		}

		bucket = &sdlBucket{
			subs:        make(map[uint64]struct{}),
			windowStart: now,
			lastUpdate:  now,
		}
		shard.buckets[apex] = bucket
	}

	if now-bucket.windowStart > windowNanos {
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
					if b.lastUpdate < horizon && (!b.blocked || now-b.windowStart > windowNanos) {
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

