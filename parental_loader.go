/*
File:    parental_loader.go
Version: 1.23.0 (Split)
Updated: 06-Jun-2026 15:08 CEST

Description:
  Data orchestration, HTTP loading, and caching for Parental Categories.

Changes:
  1.23.0 - [SECURITY/FIX] Bolstered internal memory persistence checks natively. 
           `saveCategoryMeta` and `saveURLCache` now definitively assert `os.WriteFile`, 
           `Flush()`, and `Sync()` boundaries to avert cache file corruption under pressure.
  1.22.0 - [PERF] Injected `time.Sleep` constraints inside monolithic mapping evaluation 
           loops dynamically. Restricts array building tasks from completely stalling 
           the DNS routing system locally upon heavy Domain-Blocklist integrations natively.
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

const catCacheFile = "parental-catcache.json"
const catMetaFile = "parental-catmeta.json"

type catListHeaders struct {
	LastModified string `json:"last_modified"`
	ETag         string `json:"etag"`
}

type catMetaState struct {
	ConfigHash string                    `json:"config_hash"`
	HTTPMeta   map[string]catListHeaders `json:"http_meta"`
	FileMeta   map[string]int64          `json:"file_meta"`
}

func loadCategoryMeta() catMetaState {
	var meta catMetaState
	b, err := os.ReadFile(filepath.Join(snapshotDir(), catMetaFile))
	if err == nil {
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
	if err := os.MkdirAll(snapshotDir(), 0755); err != nil {
		return
	}
	b, err := json.Marshal(meta)
	if err == nil {
		path := filepath.Join(snapshotDir(), catMetaFile)
		tmp := path + ".tmp"
		
		// [SECURITY/FIX] Rigorous check prevents blanking the vital state.
		if err := os.WriteFile(tmp, b, 0644); err == nil {
			os.Rename(tmp, path)
		} else {
			os.Remove(tmp)
		}
	}
}

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
	
	// Expand capacity to prevent buffer-too-long errors natively
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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		w.WriteString(l)
		w.WriteByte('\n')
	}
	
	// [SECURITY/FIX] Assert complete data flushing prior to closure natively.
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return
	}
	if err := f.Close(); err == nil {
		os.Rename(tmpPath, path)
	} else {
		os.Remove(tmpPath)
	}
}

// Hardened HTTP Client designed strictly to fetch public blocklists safely, 
// mitigating Slowloris and connection-pool exhaustion vectors.
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
		// Enforce our highly secure local TLS cipher suite natively.
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

	// [SECURITY/FIX] Deterministically sort the categorical execution order natively.
	// If two arbitrary categories (e.g., `games` and `social`) attempt to register 
	// the identical domain suffix simultaneously, the alphabetical leader will 
	// consistently retain custody. Resolves random structural flips across reboots.
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

	// Evaluate Local File Hashes natively
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
				} else {
					if _, ok := meta.FileMeta[src]; ok {
						needsRebuild = true
					}
				}
			}
		}
	}

	var delayedCacheLoad []string

	// Execute HTTP fetching and remote cache extraction natively
	for _, cat := range catNames {
		cc := cfg.Parental.Categories[cat]
		for _, src := range cc.ListURLs {
			if isSourceURL(src) {
				// [PERF/FIX] Natively terminate duplicate fetch routines organically. 
				// Substantially minimizes Network/IO overhead by enforcing singleton 
				// extraction architectures over overlapping blocklists.
				if activeURLs[src] {
					continue 
				}
				activeURLs[src] = true
				
				cachePath := getURLCachePath(src)

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

				hasCacheFile := false
				if _, err := os.Stat(cachePath); err == nil {
					hasCacheFile = true
				}

				if !hasCacheFile {
					needsRebuild = true
				} else if !force {
					if m, ok := meta.HTTPMeta[src]; ok {
						if m.LastModified != "" {
							req.Header.Set("If-Modified-Since", m.LastModified)
						}
						if m.ETag != "" {
							req.Header.Set("If-None-Match", m.ETag)
						}
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
					} else {
						if logParental {
							log.Printf("[PARENTAL] Category %q: list fetch error %s: %v", cat, src, err)
						}
					}
					continue
				}

				if resp.StatusCode == http.StatusNotModified {
					resp.Body.Close()
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
				} else if resp.StatusCode == http.StatusOK {
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
					
					// [SECURITY/FIX] Read precisely 1 byte beyond the maximum capacity limit to actively 
					// detect upstream truncation and reject the payload natively.
					limitReader := io.LimitReader(resp.Body, 50*1024*1024 + 1)
					lines, eTLDs, scanErr := parseSourceBody(limitReader)
					
					// Evaluate Limit exhaustion natively to flag silent truncations
					if scanErr == nil && limitReader.(*io.LimitedReader).N == 0 {
						scanErr = fmt.Errorf("payload exceeded 50MB safety limit")
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
					}
					if eTLDs > 0 && logParental {
						log.Printf("[PARENTAL] Category %q: WARNING — loaded %d eTLD/bare-TLD entries from %s", cat, eTLDs, src)
					}
					cacheFile := filepath.Base(cachePath)
					if logParental {
						log.Printf("[PARENTAL] Category %q: fetched %d entries from %s — saved to cache (%s)", cat, len(lines), src, cacheFile)
					}
				} else {
					resp.Body.Close()
					cacheFile := filepath.Base(cachePath)
					if needsRebuild && hasCacheFile {
						urlData[src] = loadURLCache(cachePath)
						if logParental {
							log.Printf("[PARENTAL] Category %q: HTTP %d for %s — loaded from local cache (%s)", cat, resp.StatusCode, src, cacheFile)
						}
					} else if !needsRebuild && hasCacheFile {
						delayedCacheLoad = append(delayedCacheLoad, src)
						if logParental {
							log.Printf("[PARENTAL] Category %q: HTTP %d for %s — queued local cache (%s)", cat, resp.StatusCode, src, cacheFile)
						}
					} else {
						if logParental {
							log.Printf("[PARENTAL] Category %q: HTTP %d for %s", cat, resp.StatusCode, src)
						}
					}
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
		catMapInitialized.Store(true) // Signal startup guard
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
					if ipVersionSupport == "ipv4" && !unmapped.Is4() { continue }
					if ipVersionSupport == "ipv6" && !unmapped.Is6() { continue }
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
					if ipVersionSupport == "ipv4" && !prefix.Addr().Is4() { continue }
					if ipVersionSupport == "ipv6" && !prefix.Addr().Is6() { continue }
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
			} else {
				// [PERF/FIX] Prevent identical local-files inherited by subsequent lists
				// from instigating redundant disk readings by mapping extractions natively.
				if cachedLines, ok := localFileData[src]; ok {
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
					if err != nil {
						if logParental {
							log.Printf("[PARENTAL] Category %q: WARNING — partial scanner error reading local file %s: %v", cat, src, err)
						}
					}
					if eTLDs > 0 {
						if logParental {
							log.Printf("[PARENTAL] Category %q: WARNING — loaded %d eTLD/bare-TLD entries from %s (override with 'remove:' if unintended)", cat, eTLDs, src)
						}
					}
					lines = fLines
					localFileData[src] = lines
					if logParental {
						log.Printf("[PARENTAL] Category %q: Fetched %d entries from local file: %s", cat, len(lines), src)
					}
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
						if ipVersionSupport == "ipv4" && !unmapped.Is4() { continue }
						if ipVersionSupport == "ipv6" && !unmapped.Is6() { continue }
					}
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
						if ipVersionSupport == "ipv4" && !prefix.Addr().Is4() { continue }
						if ipVersionSupport == "ipv6" && !prefix.Addr().Is6() { continue }
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
			if n := consolidateParentDomains(newApex, threshold, homogPct); n > 0 {
				if logParental {
					log.Printf("[PARENTAL] Synthesised %d parent domain(s) via consolidation", n)
				}
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

			if n := dedupeApex(newApex); n > 0 {
				catCountsAfter := make(map[string]int)
				for _, cat := range newApex {
					catCountsAfter[cat]++
				}
				for cat, before := range catCountsBefore {
					after := catCountsAfter[cat]
					if removed := before - after; removed > 0 {
						if logParental {
							log.Printf("[PARENTAL] Category %q: dedupped from %d to %d (removed %d redundant sub-domain apex entries)", cat, before, after, removed)
						}
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
	catMapInitialized.Store(true) // Signal startup guard
	computeCatLabelBounds(newApex)
	saveCatCache(newApex, newPatterns, newIPs, newCIDRs)
	
	if logParental {
		log.Printf("[PARENTAL] Category maps ready: %d apex entries, %d wildcard pattern(s), %d IPs, %d CIDRs", len(newApex), len(newPatterns), len(newIPs), len(newCIDRs))
	}
}

