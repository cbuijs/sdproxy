/*
File:    parental_loader.go
Version: 2.0.0 (Split)
Updated: 22-Jul-2026 22:10 CEST

Description:
  Data orchestration, HTTP loading and caching for parental categories.

Changes:
  2.0.0  - [TIER 2] Meta and URL cache writes moved onto the shared atomic
           helpers; the manual tmp/flush/sync/close/rename ladders are gone.
  1.25.0 - [SECURITY/RELIABILITY] Directory fsync on cache renames.
  1.24.0 - [PERF] 3-hour freshness TTL across all remote extraction paths,
           removing boot latency and CDN rate-limiting.
*/

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	catCacheFile = "parental-catcache.json"
	catMetaFile  = "parental-catmeta.json"

	// catMaxListBytes caps a single remote blocklist. [SECURITY] CWE-400.
	catMaxListBytes = 50 * 1024 * 1024
	// catFreshnessTTL skips the network when the list was validated recently.
	catFreshnessTTL = 3 * 3600
)

type catListHeaders struct {
	LastModified string `json:"last_modified"`
	ETag         string `json:"etag"`
	LastFetch    int64  `json:"last_fetch"`
}

type catMetaState struct {
	ConfigHash string                    `json:"config_hash"`
	HTTPMeta   map[string]catListHeaders `json:"http_meta"`
	FileMeta   map[string]int64          `json:"file_meta"`
}

func loadCategoryMeta() catMetaState {
	var meta catMetaState
	if b, err := os.ReadFile(filepath.Join(snapshotDir(), catMetaFile)); err == nil {
		json.Unmarshal(b, &meta)
	}
	if meta.HTTPMeta == nil {
		meta.HTTPMeta = make(map[string]catListHeaders)
	}
	if meta.FileMeta == nil {
		meta.FileMeta = make(map[string]int64)
	}
	return meta
}

func saveCategoryMeta(meta catMetaState) {
	b, err := json.Marshal(meta)
	if err != nil {
		return
	}
	path := filepath.Join(snapshotDir(), catMetaFile)
	if err := atomicWrite(path, b, 0644); err != nil && logParental {
		log.Printf("[PARENTAL] WARNING: failed to persist category meta: %v", err)
	}
}

// computeConfigHash fingerprints every setting that affects the compiled
// category set, so a config edit forces a rebuild even with unchanged sources.
func computeConfigHash() string {
	type hashData struct {
		Categories   map[string]CategoryConfig
		Consol       *bool
		SynthParents *bool
		RemoveSub    *bool
		StripLabels  *bool
		ParentThresh int
		HomogPct     int
		IPVersion    string
	}
	hd := hashData{
		Categories:   cfg.Parental.Categories,
		Consol:       cfg.Parental.Consolidation,
		SynthParents: cfg.Parental.SynthesiseParents,
		RemoveSub:    cfg.Parental.RemoveRedundantSubdomains,
		StripLabels:  cfg.Parental.StripServiceLabels,
		ParentThresh: cfg.Parental.ParentConsolidationThreshold,
		HomogPct:     cfg.Parental.ConsolidationHomogeneityPct,
		IPVersion:    ipVersionSupport,
	}
	b, _ := json.Marshal(hd)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func getURLCachePath(url string) string {
	h := sha256.Sum256([]byte(url))
	return filepath.Join(snapshotDir(), "src-"+hex.EncodeToString(h[:8])+".txt")
}

func loadURLCache(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)

	buf := make([]byte, 64*1024)
	sc.Buffer(buf, 2*1024*1024)

	for sc.Scan() {
		if txt := strings.TrimSpace(sc.Text()); txt != "" {
			lines = append(lines, txt)
		}
	}
	return lines
}

func saveURLCache(path string, lines []string) {
	err := atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		for _, l := range lines {
			if _, err := bw.WriteString(l); err != nil {
				return err
			}
			if err := bw.WriteByte('\n'); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil && logParental {
		log.Printf("[PARENTAL] WARNING: failed to write list cache %s: %v", filepath.Base(path), err)
	}
}

// catHTTPClient fetches public blocklists. Timeouts are explicit at every stage
// to mitigate Slowloris and connection-pool exhaustion from a hostile host.
var catHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       getHardenedTLSConfig(),
	},
}

func loadAllCategoryLists(force bool) {
	needed := make(map[string]bool)
	for _, grp := range cfg.Groups {
		for key := range grp.Budget {
			if key != "total" {
				needed[key] = true
			}
		}
	}

	// [SECURITY] Deterministic ordering. When two categories claim the same
	// domain, the alphabetically first one must win consistently across reboots,
	// otherwise a random map walk flips the assignment between restarts.
	var catNames []string
	for cat := range cfg.Parental.Categories {
		if needed[cat] {
			catNames = append(catNames, cat)
		}
	}
	sort.Strings(catNames)

	meta := loadCategoryMeta()
	needsRebuild := false

	if force {
		if logParental {
			log.Printf("[PARENTAL] Force-refresh enabled. Bypassing metadata caches.")
		}
		needsRebuild = true
		meta.HTTPMeta = make(map[string]catListHeaders)
		meta.FileMeta = make(map[string]int64)
	}

	currentHash := computeConfigHash()
	if meta.ConfigHash != currentHash {
		needsRebuild = true
		meta.ConfigHash = currentHash
		if !force && logParental {
			log.Printf("[PARENTAL] Category configuration changed, full rebuild triggered")
		}
	}

	data := catMap.Load()
	if data == nil || len(data.apex) == 0 {
		needsRebuild = true
		if !force && logParental {
			log.Printf("[PARENTAL] In-memory category cache missing, full rebuild triggered")
		}
	}

	activeURLs := make(map[string]bool)
	urlData := make(map[string][]string)
	currentFileMeta := make(map[string]int64)

	for _, cat := range catNames {
		cc := cfg.Parental.Categories[cat]
		for _, src := range cc.ListURLs {
			if !isSourceURL(src) {
				info, err := os.Stat(src)
				if err == nil {
					mtime := info.ModTime().UnixNano()
					currentFileMeta[src] = mtime
					if meta.FileMeta[src] != mtime {
						needsRebuild = true
					}
				} else if _, ok := meta.FileMeta[src]; ok {
					needsRebuild = true
				}
			}
		}
	}

	// Sources whose cache is valid but which we haven't read yet. If nothing
	// forces a rebuild we never touch them; if something does, they're loaded.
	var delayedCacheLoad []string
	nowUnix := time.Now().Unix()

	for _, cat := range catNames {
		cc := cfg.Parental.Categories[cat]
		for _, src := range cc.ListURLs {
			if !isSourceURL(src) {
				continue
			}
			// [PERF] Two categories sharing a URL must not fetch it twice.
			if activeURLs[src] {
				continue
			}
			activeURLs[src] = true

			cachePath := getURLCachePath(src)
			hasCacheFile := false
			if _, err := os.Stat(cachePath); err == nil {
				hasCacheFile = true
			}

			var m catListHeaders
			var hasMeta bool
			if !force {
				m, hasMeta = meta.HTTPMeta[src]
			}

			// [PERF] Freshness gate — no HTTP round-trip inside the TTL window.
			if !force && hasCacheFile && hasMeta && (nowUnix-m.LastFetch) < catFreshnessTTL {
				cacheFile := filepath.Base(cachePath)
				if needsRebuild {
					urlData[src] = loadURLCache(cachePath)
					if logParental {
						log.Printf("[PARENTAL] Category %q: fresh in cache (<3h) — loaded %d entries from local cache (%s) for %s", cat, len(urlData[src]), cacheFile, src)
					}
				} else {
					delayedCacheLoad = append(delayedCacheLoad, src)
					if logParental {
						log.Printf("[PARENTAL] Category %q: fresh in cache (<3h) — queued local cache (%s) for %s", cat, cacheFile, src)
					}
				}
				continue
			}

			if logParental {
				log.Printf("[PARENTAL] Category %q: Checking/Fetching remote source: %s", cat, src)
			}

			req, err := http.NewRequest(http.MethodGet, src, nil)
			if err != nil {
				if logParental {
					log.Printf("[PARENTAL] Category %q: request build error %s: %v", cat, src, err)
				}
				continue
			}
			req.Header.Set("User-Agent", cfg.Server.UserAgent)

			if !hasCacheFile {
				needsRebuild = true
			} else if !force && hasMeta {
				if m.LastModified != "" {
					req.Header.Set("If-Modified-Since", m.LastModified)
				}
				if m.ETag != "" {
					req.Header.Set("If-None-Match", m.ETag)
				}
			}

			resp, err := catHTTPClient.Do(req)
			if err != nil {
				cacheFile := filepath.Base(cachePath)
				if needsRebuild && hasCacheFile {
					urlData[src] = loadURLCache(cachePath)
					if logParental {
						log.Printf("[PARENTAL] Category %q: list fetch error %s: %v — loaded from local cache (%s)", cat, src, err, cacheFile)
					}
				} else if !needsRebuild && hasCacheFile {
					delayedCacheLoad = append(delayedCacheLoad, src)
					if logParental {
						log.Printf("[PARENTAL] Category %q: list fetch error %s: %v — queued local cache (%s)", cat, src, err, cacheFile)
					}
				} else if logParental {
					log.Printf("[PARENTAL] Category %q: list fetch error %s: %v", cat, src, err)
				}
				continue
			}

			switch {
			case resp.StatusCode == http.StatusNotModified:
				resp.Body.Close()
				m.LastFetch = nowUnix
				meta.HTTPMeta[src] = m

				cacheFile := filepath.Base(cachePath)
				if needsRebuild && hasCacheFile {
					lines := loadURLCache(cachePath)
					urlData[src] = lines
					if logParental {
						log.Printf("[PARENTAL] Category %q: not modified (304) — loaded %d entries from local cache (%s) for %s", cat, len(lines), cacheFile, src)
					}
				} else if !needsRebuild {
					delayedCacheLoad = append(delayedCacheLoad, src)
					if logParental {
						log.Printf("[PARENTAL] Category %q: not modified (304) for %s — queued local cache (%s)", cat, src, cacheFile)
					}
				}

			case resp.StatusCode == http.StatusOK:
				// A changed list forces a rebuild, which means every previously
				// deferred cache must now actually be read.
				if !needsRebuild {
					needsRebuild = true
					for _, delayedSrc := range delayedCacheLoad {
						cPath := getURLCachePath(delayedSrc)
						urlData[delayedSrc] = loadURLCache(cPath)
						if logParental {
							log.Printf("[PARENTAL] Delayed load: fetched %d entries from local cache (%s) for %s", len(urlData[delayedSrc]), filepath.Base(cPath), delayedSrc)
						}
					}
					delayedCacheLoad = nil
				}

				// [SECURITY] Read one byte past the cap to detect truncation.
				limitReader := io.LimitReader(resp.Body, catMaxListBytes+1)
				lines, eTLDs, scanErr := parseSourceBody(limitReader)

				if scanErr == nil && limitReader.(*io.LimitedReader).N == 0 {
					scanErr = fmt.Errorf("payload exceeded %dMB safety limit", catMaxListBytes/(1024*1024))
				}

				if scanErr != nil && logParental {
					log.Printf("[PARENTAL] Category %q: WARNING — scanner error during payload parsing from %s: %v", cat, src, scanErr)
				}
				resp.Body.Close()

				saveURLCache(cachePath, lines)
				urlData[src] = lines
				meta.HTTPMeta[src] = catListHeaders{
					LastModified: resp.Header.Get("Last-Modified"),
					ETag:         resp.Header.Get("ETag"),
					LastFetch:    nowUnix,
				}
				if eTLDs > 0 && logParental {
					log.Printf("[PARENTAL] Category %q: WARNING — loaded %d eTLD/bare-TLD entries from %s", cat, eTLDs, src)
				}
				if logParental {
					log.Printf("[PARENTAL] Category %q: fetched %d entries from %s — saved to cache (%s)", cat, len(lines), src, filepath.Base(cachePath))
				}

			default:
				status := resp.StatusCode
				resp.Body.Close()
				cacheFile := filepath.Base(cachePath)
				if needsRebuild && hasCacheFile {
					urlData[src] = loadURLCache(cachePath)
					if logParental {
						log.Printf("[PARENTAL] Category %q: HTTP %d for %s — loaded from local cache (%s)", cat, status, src, cacheFile)
					}
				} else if !needsRebuild && hasCacheFile {
					delayedCacheLoad = append(delayedCacheLoad, src)
					if logParental {
						log.Printf("[PARENTAL] Category %q: HTTP %d for %s — queued local cache (%s)", cat, status, src, cacheFile)
					}
				} else if logParental {
					log.Printf("[PARENTAL] Category %q: HTTP %d for %s", cat, status, src)
				}
			}
		}
	}

	for url := range meta.HTTPMeta {
		if !activeURLs[url] {
			delete(meta.HTTPMeta, url)
			os.Remove(getURLCachePath(url))
			needsRebuild = true
			if logParental {
				log.Printf("[PARENTAL] Garbage collected stale cache for removed URL: %s", url)
			}
		}
	}
	for file := range meta.FileMeta {
		if _, exists := currentFileMeta[file]; !exists {
			delete(meta.FileMeta, file)
			needsRebuild = true
		}
	}

	if needsRebuild && len(delayedCacheLoad) > 0 {
		for _, delayedSrc := range delayedCacheLoad {
			cPath := getURLCachePath(delayedSrc)
			urlData[delayedSrc] = loadURLCache(cPath)
			if logParental {
				log.Printf("[PARENTAL] Delayed load: fetched %d entries from local cache (%s) for %s", len(urlData[delayedSrc]), filepath.Base(cPath), delayedSrc)
			}
		}
		delayedCacheLoad = nil
	}

	if !needsRebuild {
		if logParental {
			log.Printf("[PARENTAL] All lists and configs up to date. Processing skipped.")
		}
		catMapInitialized.Store(true)
		return
	}

	meta.FileMeta = currentFileMeta
	saveCategoryMeta(meta)

	newApex := make(map[string]string, 4096)
	var newPatterns []wildcardCatEntry
	newIPs := make(map[netip.Addr]string)
	var newCIDRs []cidrCatEntry

	doStrip := false
	if cfg.Parental.StripServiceLabels != nil {
		doStrip = *cfg.Parental.StripServiceLabels
	}

	localFileData := make(map[string][]string)

	for _, cat := range catNames {
		cc := cfg.Parental.Categories[cat]

		discardedIPs := 0
		yieldCounter := 0

		for _, d := range cc.Add {
			yieldCounter++
			if yieldCounter%5000 == 0 {
				time.Sleep(time.Millisecond)
			}

			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if ip, err := netip.ParseAddr(d); err == nil {
				if !cfg.Server.FilterIPs {
					discardedIPs++
					continue
				}
				unmapped := ip.Unmap()
				if ipVersionSupport != "both" {
					if ipVersionSupport == "ipv4" && !unmapped.Is4() {
						continue
					}
					if ipVersionSupport == "ipv6" && !unmapped.Is6() {
						continue
					}
				}
				newIPs[unmapped] = cat
				continue
			}
			if prefix, err := ParsePrefixUnmapped(d); err == nil {
				if !cfg.Server.FilterIPs {
					discardedIPs++
					continue
				}
				if ipVersionSupport != "both" {
					if ipVersionSupport == "ipv4" && !prefix.Addr().Is4() {
						continue
					}
					if ipVersionSupport == "ipv6" && !prefix.Addr().Is6() {
						continue
					}
				}
				newCIDRs = append(newCIDRs, cidrCatEntry{prefix: prefix, cat: cat})
				continue
			}
			if isWildcard(d) {
				newPatterns = append(newPatterns, wildcardCatEntry{Pattern: d, Cat: cat})
			} else if d != "" {
				if !isIPOrCIDR(d) && isPublicSuffix(d) {
					if logParental {
						log.Printf("[PARENTAL] Category %q: WARNING — manual 'add:' entry includes eTLD/bare-TLD %q", cat, d)
					}
				}
				if doStrip {
					if stripped, ok := stripServiceLabel(d); ok {
						if logParental {
							log.Printf("[PARENTAL] Category %q: stripped service label %q → %q (add: entry)", cat, d, stripped)
						}
						d = stripped
					}
				}
				newApex[d] = cat
			}
		}

		for _, src := range cc.ListURLs {
			var lines []string
			if isSourceURL(src) {
				lines = urlData[src]
			} else if cachedLines, ok := localFileData[src]; ok {
				// [PERF] A local file shared by several categories is read once.
				lines = cachedLines
			} else {
				if logParental {
					log.Printf("[PARENTAL] Category %q: Loading local file source: %s", cat, src)
				}
				fLines, eTLDs, err := parseLocalFile(src)
				if err != nil && len(fLines) == 0 {
					if logParental {
						log.Printf("[PARENTAL] Category %q: Failed to parse local file %s: %v", cat, src, err)
					}
					continue
				}
				if err != nil && logParental {
					log.Printf("[PARENTAL] Category %q: WARNING — partial scanner error reading local file %s: %v", cat, src, err)
				}
				if eTLDs > 0 && logParental {
					log.Printf("[PARENTAL] Category %q: WARNING — loaded %d eTLD/bare-TLD entries from %s (override with 'remove:' if unintended)", cat, eTLDs, src)
				}
				lines = fLines
				localFileData[src] = lines
				if logParental {
					log.Printf("[PARENTAL] Category %q: Fetched %d entries from local file: %s", cat, len(lines), src)
				}
			}

			yieldCounter = 0
			for _, d := range lines {
				yieldCounter++
				if yieldCounter%5000 == 0 {
					time.Sleep(time.Millisecond)
				}

				if ip, err := netip.ParseAddr(d); err == nil {
					if !cfg.Server.FilterIPs {
						discardedIPs++
						continue
					}
					unmapped := ip.Unmap()
					if ipVersionSupport != "both" {
						if ipVersionSupport == "ipv4" && !unmapped.Is4() {
							continue
						}
						if ipVersionSupport == "ipv6" && !unmapped.Is6() {
							continue
						}
					}
					// First category to claim an entry keeps it.
					if _, exists := newIPs[unmapped]; !exists {
						newIPs[unmapped] = cat
					}
					continue
				}
				if prefix, err := ParsePrefixUnmapped(d); err == nil {
					if !cfg.Server.FilterIPs {
						discardedIPs++
						continue
					}
					if ipVersionSupport != "both" {
						if ipVersionSupport == "ipv4" && !prefix.Addr().Is4() {
							continue
						}
						if ipVersionSupport == "ipv6" && !prefix.Addr().Is6() {
							continue
						}
					}
					newCIDRs = append(newCIDRs, cidrCatEntry{prefix: prefix, cat: cat})
					continue
				}

				if doStrip {
					if stripped, ok := stripServiceLabel(d); ok {
						if logParental {
							log.Printf("[PARENTAL] Category %q: stripped service label %q → %q", cat, d, stripped)
						}
						d = stripped
					}
				}
				if _, exists := newApex[d]; !exists {
					newApex[d] = cat
				}
			}
		}

		yieldCounter = 0
		for _, d := range cc.Remove {
			yieldCounter++
			if yieldCounter%5000 == 0 {
				time.Sleep(time.Millisecond)
			}

			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if ip, err := netip.ParseAddr(d); err == nil {
				unmapped := ip.Unmap()
				if newIPs[unmapped] == cat {
					delete(newIPs, unmapped)
				}
				continue
			}
			if prefix, err := ParsePrefixUnmapped(d); err == nil {
				var kept []cidrCatEntry
				for _, c := range newCIDRs {
					if c.cat == cat && c.prefix == prefix {
						continue
					}
					kept = append(kept, c)
				}
				newCIDRs = kept
				continue
			}
			if isWildcard(d) {
				for k, c := range newApex {
					if c == cat && matchGlob(d, k) {
						delete(newApex, k)
					}
				}
				var kept []wildcardCatEntry
				for _, p := range newPatterns {
					if p.Cat == cat && p.Pattern == d {
						continue
					}
					kept = append(kept, p)
				}
				newPatterns = kept
			} else if d != "" {
				if newApex[d] == cat {
					delete(newApex, d)
				}
			}
		}

		if discardedIPs > 0 && logParental {
			log.Printf("[PARENTAL] Category %q: Discarded %d IP/CIDR entries (server.filter_ips is false)", cat, discardedIPs)
		}
	}

	doConsolidation := true
	if cfg.Parental.Consolidation != nil {
		doConsolidation = *cfg.Parental.Consolidation
	}

	if doConsolidation {
		doSynth := false
		if cfg.Parental.SynthesiseParents != nil {
			doSynth = *cfg.Parental.SynthesiseParents
		}

		if doSynth {
			threshold := cfg.Parental.ParentConsolidationThreshold
			if threshold <= 0 {
				threshold = 10
			}
			homogPct := cfg.Parental.ConsolidationHomogeneityPct
			if homogPct <= 0 || homogPct > 100 {
				homogPct = 90
			}
			if n := consolidateParentDomains(newApex, threshold, homogPct); n > 0 && logParental {
				log.Printf("[PARENTAL] Synthesised %d parent domain(s) via consolidation", n)
			}
		}

		doRemove := true
		if cfg.Parental.RemoveRedundantSubdomains != nil {
			doRemove = *cfg.Parental.RemoveRedundantSubdomains
		}

		if doRemove {
			catCountsBefore := make(map[string]int)
			for _, cat := range newApex {
				catCountsBefore[cat]++
			}

			if n := dedupeApex(newApex); n > 0 && logParental {
				catCountsAfter := make(map[string]int)
				for _, cat := range newApex {
					catCountsAfter[cat]++
				}
				for cat, before := range catCountsBefore {
					after := catCountsAfter[cat]
					if removed := before - after; removed > 0 {
						log.Printf("[PARENTAL] Category %q: dedupped from %d to %d (removed %d redundant sub-domain apex entries)", cat, before, after, removed)
					}
				}
			}
		}
	}

	if len(newCIDRs) > 0 {
		sort.SliceStable(newCIDRs, func(i, j int) bool {
			return newCIDRs[i].prefix.Bits() > newCIDRs[j].prefix.Bits()
		})
	}

	catMap.Store(&categoryData{
		apex:             newApex,
		compiledPatterns: CompileWildcards(newPatterns),
		ips:              newIPs,
		cidrs:            newCIDRs,
	})
	catMapInitialized.Store(true)
	computeCatLabelBounds(newApex)
	saveCatCache(newApex, newPatterns, newIPs, newCIDRs)

	if logParental {
		log.Printf("[PARENTAL] Category maps ready: %d apex entries, %d wildcard pattern(s), %d IPs, %d CIDRs", len(newApex), len(newPatterns), len(newIPs), len(newCIDRs))
	}
}

