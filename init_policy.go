/*
File:    init_policy.go
Version: 1.11.0
Updated: 30-Jun-2026 09:29 CEST

Description:
  Parses and maps RType and Domain policies for sdproxy.
  Handles remote list fetching, local file parsing, and label boundary
  calculations for optimized suffix walking.

Changes:
  1.11.0 - [BUG/FIX] Resolved a build compilation error (`declared and not used: actionName`) 
           natively within the URL extraction loop by properly omitting the unused variable.
  1.10.0 - [PERF] Introduced a rigid 3-hour Local Freshness TTL (`LastFetch`) natively. 
           Bypasses HTTP polling entirely if the policy payload was successfully validated 
           within the 3-hour horizon, dramatically conserving network bandwidth dynamically.
  1.9.0 - [SECURITY/FIX] Eradicated a persistent zombie goroutine organically. 
          The periodic Domain Policy polling loop now explicitly listens for the 
          global `shutdownCh` multiplexer, ensuring clean teardowns natively.
  1.8.1 - [SECURITY/FIX] Eradicated a severe Map Assignment Panic natively. 
          When `policy_cache_dir` was configured as empty, the metadata loader 
          returned uninitialized map structures (`FileMeta` and `HTTPMeta`), 
          causing catastrophic SIGSEGVs during Domain Policy re-evaluations. 
          Maps are now strictly instantiated prior to returning organically.
*/

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	policyMu sync.Mutex
)

// Structural representations utilized natively for Binary Serialization caches
type CompiledPolicy struct {
	Map   map[string]int
	CIDRs []DpCidrEntryGob
}

type DpCidrEntryGob struct {
	Prefix string // [FIX] Stored as a raw string to guarantee bulletproof gob encoding/decoding natively
	Action int
}

type policyMetaState struct {
	ConfigHash string                    `json:"config_hash"`
	HTTPMeta   map[string]catListHeaders `json:"http_meta"`
	FileMeta   map[string]int64          `json:"file_meta"`
}

// loadPolicyMeta retrieves the metadata for domain policies from the cache directory.
func loadPolicyMeta() policyMetaState {
	var meta policyMetaState
	if cfg.Server.PolicyCacheDir != "" {
		b, err := os.ReadFile(filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json"))
		if err == nil {
			json.Unmarshal(b, &meta)
		}
	}
	
	// [SECURITY/FIX] Enforce strict map instantiation to definitively avert 
	// `nil map` assignment panics natively when caches are absent.
	if meta.HTTPMeta == nil {
		meta.HTTPMeta = make(map[string]catListHeaders)
	}
	if meta.FileMeta == nil {
		meta.FileMeta = make(map[string]int64)
	}
	return meta
}

// savePolicyMeta persists the metadata for domain policies to the cache directory.
func savePolicyMeta(meta policyMetaState) {
	if cfg.Server.PolicyCacheDir == "" {
		return
	}
	os.MkdirAll(cfg.Server.PolicyCacheDir, 0755)
	b, err := json.Marshal(meta)
	if err == nil {
		path := filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json")
		tmp := path + ".tmp"
		
		if err := os.WriteFile(tmp, b, 0644); err == nil {
			os.Remove(path) // [FIX] Protects against OS-level file lock rejections natively (Windows)
			if renameErr := os.Rename(tmp, path); renameErr != nil {
				if logRouting {
					log.Printf("[POLICY] WARNING: Failed to atomically rename meta file: %v", renameErr)
				}
				os.Remove(tmp)
			}
		} else {
			if logRouting {
				log.Printf("[POLICY] WARNING: Failed to write meta file to disk natively: %v", err)
			}
			os.Remove(tmp)
		}
	}
}

// computePolicyConfigHash evaluates inline configuration bounds to dynamically trigger rebuilds
func computePolicyConfigHash() string {
	type hashData struct {
		Policy    map[string]string
		Files     map[string]string
		URLs      map[string]string
		FilterIPs bool
	}
	hd := hashData{
		Policy:    cfg.DomainPolicy,
		Files:     cfg.DomainPolicyFiles,
		URLs:      cfg.DomainPolicyURLs,
		FilterIPs: cfg.Server.FilterIPs,
	}
	b, _ := json.Marshal(hd)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// pollDomainPolicies rebuilds the domain policy map from all configured sources.
func pollDomainPolicies(force bool) {
	policyMu.Lock()
	defer policyMu.Unlock()

	isStartup := domainPolicySnap.Load() == nil

	changed := false
	activeFiles := make(map[string]bool)
	activeURLs := make(map[string]bool)

	meta := loadPolicyMeta()
	
	if force {
		changed = true
		meta.HTTPMeta = make(map[string]catListHeaders)
		meta.FileMeta = make(map[string]int64)
	}

	currentHash := computePolicyConfigHash()
	if meta.ConfigHash != currentHash {
		changed = true
		meta.ConfigHash = currentHash
		if logRouting && !force {
			log.Printf("[POLICY] Inline configuration changed, triggering rebuild.")
		}
	}

	for filePath := range cfg.DomainPolicyFiles {
		activeFiles[filePath] = true
		info, err := os.Stat(filePath)
		if err != nil {
			if _, exists := meta.FileMeta[filePath]; exists {
				delete(meta.FileMeta, filePath)
				changed = true
				if logRouting {
					log.Printf("[POLICY] File %s was removed. Flagging policy maps for rebuild.", filePath)
				}
			}
			continue
		}
		mtime := info.ModTime().UnixNano()
		if lastMtime, ok := meta.FileMeta[filePath]; !ok || lastMtime != mtime {
			meta.FileMeta[filePath] = mtime
			changed = true
		}
	}

	// [PERF/FIX] Attempt instant binary load at startup to bypass network latency.
	// If the configuration and local files are completely unchanged, load the binary cache
	// organically and return instantly. This radically decreases time-to-first-query 
	// by eliminating synchronous HTTP polling on cold boots.
	if isStartup && !changed && !force && cfg.Server.PolicyCacheDir != "" {
		binPath := filepath.Join(cfg.Server.PolicyCacheDir, "policy-compiled.bin")
		if bf, err := os.Open(binPath); err == nil {
			var comp CompiledPolicy
			br := bufio.NewReaderSize(bf, 64*1024)
			if err := gob.NewDecoder(br).Decode(&comp); err == nil {
				var newCIDRs []dpCidrEntry
				for _, c := range comp.CIDRs {
					// [FIX] Safely unmarshal the immutable string bounds natively back into `netip.Prefix`
					if p, err := netip.ParsePrefix(c.Prefix); err == nil {
						newCIDRs = append(newCIDRs, dpCidrEntry{prefix: p, action: c.Action})
					}
				}
				domainPolicySnap.Store(&comp.Map)
				domainPolicyCIDRSnap.Store(&newCIDRs)
				hasDomainPolicy.Store(len(comp.Map) > 0 || len(newCIDRs) > 0)
				computeDomainLabelBounds(&comp.Map)
				bf.Close()
				if logRouting {
					log.Printf("[POLICY] Loaded compiled BINARY policy map instantly. Bound %d rule(s) globally.", len(comp.Map)+len(newCIDRs))
				}
				return // Execution successfully bypassed raw extraction logic and network
			} else {
				if logRouting {
					log.Printf("[POLICY] WARNING: Binary cache decode error: %v. Falling back to source extraction natively.", err)
				}
			}
			bf.Close()
		}
	}

	urlData := make(map[string][]string)
	fetchFailed := make(map[string]bool)
	nowUnix := time.Now().Unix()

	for urlStr := range cfg.DomainPolicyURLs {
		activeURLs[urlStr] = true
		
		var cachePath string
		hasCacheFile := false
		if cfg.Server.PolicyCacheDir != "" {
			os.MkdirAll(cfg.Server.PolicyCacheDir, 0755)
			h := sha256.Sum256([]byte(urlStr))
			cachePath = filepath.Join(cfg.Server.PolicyCacheDir, "policy-"+hex.EncodeToString(h[:8])+".raw")
			if _, errStat := os.Stat(cachePath); errStat == nil {
				hasCacheFile = true
			}
		}

		var m catListHeaders
		var hasMeta bool
		if !force {
			m, hasMeta = meta.HTTPMeta[urlStr]
		}

		// [PERF/SECURITY] 3-Hour Freshness TTL Gate
		// Organically skips the HTTP Request execution completely if the list was successfully
		// verified or downloaded within the last 3 hours. Drastically lowers boot latency and CDN rate-limits.
		if !force && hasCacheFile && hasMeta && (nowUnix-m.LastFetch) < 3*3600 {
			if logRouting {
				log.Printf("[POLICY] Fresh in cache (<3h) — queued local cache for %s", urlStr)
			}
			continue // Bypass network fetch completely natively
		}

		req, err := http.NewRequest(http.MethodGet, urlStr, nil)
		if err != nil {
			fetchFailed[urlStr] = true
			continue
		}
		req.Header.Set("User-Agent", cfg.Server.UserAgent)

		if !force && hasCacheFile && hasMeta {
			if m.LastModified != "" {
				req.Header.Set("If-Modified-Since", m.LastModified)
			}
			if m.ETag != "" {
				req.Header.Set("If-None-Match", m.ETag)
			}
		}

		resp, err := catHTTPClient.Do(req)
		if err != nil {
			fetchFailed[urlStr] = true
			if logRouting {
				if !hasCacheFile {
					log.Printf("[POLICY] Fetch failed for %s: %v", urlStr, err)
				} else {
					log.Printf("[POLICY] Fetch failed for %s: %v — falling back to local cache", urlStr, err)
				}
			}
			continue
		}

		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			
			// Update LastFetch TTL natively to sustain the freshness horizon
			m.LastFetch = nowUnix
			meta.HTTPMeta[urlStr] = m
			
			if hasCacheFile && logRouting {
				log.Printf("[POLICY] Not modified (304) for %s — queued local cache", urlStr)
			}
			continue
		} else if resp.StatusCode == http.StatusOK {
			meta.HTTPMeta[urlStr] = catListHeaders{
				LastModified: resp.Header.Get("Last-Modified"),
				ETag:         resp.Header.Get("ETag"),
				LastFetch:    nowUnix,
			}
			
			var lines []string
			
			// [SECURITY/FIX] CWE-400 Limit Exceedance Protection. 
			// Bound strictly to 10MB + 1 to detect stream overflows reliably natively.
			lr := io.LimitReader(resp.Body, 10*1024*1024+1)
			scanner := bufio.NewScanner(lr)
			buf := make([]byte, 64*1024)
			scanner.Buffer(buf, 2*1024*1024)
			
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if idx := strings.IndexByte(line, '#'); idx >= 0 {
					line = strings.TrimSpace(line[:idx])
				}
				if line != "" {
					lines = append(lines, line)
				}
			}
			
			// Evaluate Limit exhaustion natively to flag silent truncations
			if scanner.Err() == nil && lr.(*io.LimitedReader).N == 0 {
				if logRouting {
					log.Printf("[POLICY] Security constraint: payload exceeded 10MB safety limit for %s", urlStr)
				}
				resp.Body.Close()
				fetchFailed[urlStr] = true
				continue
			}
			
			resp.Body.Close()
			urlData[urlStr] = lines
			
			if cachePath != "" {
				tmp := cachePath + ".tmp"
				f, err := os.Create(tmp)
				if err == nil {
					w := bufio.NewWriter(f)
					for _, l := range lines {
						w.WriteString(l)
						w.WriteByte('\n')
					}
					
					// [SECURITY/FIX] Assert complete data flushing prior to closure natively.
					if flushErr := w.Flush(); flushErr == nil {
						f.Sync()
						if closeErr := f.Close(); closeErr == nil {
							os.Remove(cachePath) // [FIX] Protects against OS-level file lock rejections natively (Windows)
							if renameErr := os.Rename(tmp, cachePath); renameErr != nil {
								if logRouting {
									log.Printf("[POLICY] WARNING: Failed to rename raw cache file natively: %v", renameErr)
								}
								os.Remove(tmp)
							}
						} else {
							f.Close()
							os.Remove(tmp)
						}
					} else {
						f.Close()
						os.Remove(tmp)
					}
				}
				if logRouting {
					log.Printf("[POLICY] Fetched %d entries from %s — saved to cache", len(lines), urlStr)
				}
			}
			changed = true
		} else {
			fetchFailed[urlStr] = true
			resp.Body.Close()
			if hasCacheFile && logRouting {
				log.Printf("[POLICY] HTTP %d for %s — falling back to local cache", resp.StatusCode, urlStr)
			}
		}
	}

	for f := range meta.FileMeta {
		if !activeFiles[f] {
			delete(meta.FileMeta, f)
			changed = true
		}
	}
	for u := range meta.HTTPMeta {
		if !activeURLs[u] {
			delete(meta.HTTPMeta, u)
			changed = true
		}
	}

	if isStartup || changed {
		
		// Attempt instant payload load utilizing completely evaluated structural Binary memory bounds 
		// explicitly if the configurations remained entirely unchanged organically natively.
		if !changed && cfg.Server.PolicyCacheDir != "" && !force {
			binPath := filepath.Join(cfg.Server.PolicyCacheDir, "policy-compiled.bin")
			if bf, err := os.Open(binPath); err == nil {
				var comp CompiledPolicy
				br := bufio.NewReaderSize(bf, 64*1024)
				if err := gob.NewDecoder(br).Decode(&comp); err == nil {
					var newCIDRs []dpCidrEntry
					for _, c := range comp.CIDRs {
						if p, err := netip.ParsePrefix(c.Prefix); err == nil {
							newCIDRs = append(newCIDRs, dpCidrEntry{prefix: p, action: c.Action})
						}
					}
					domainPolicySnap.Store(&comp.Map)
					domainPolicyCIDRSnap.Store(&newCIDRs)
					hasDomainPolicy.Store(len(comp.Map) > 0 || len(newCIDRs) > 0)
					computeDomainLabelBounds(&comp.Map)
					bf.Close()
					if logRouting {
						log.Printf("[POLICY] Loaded compiled BINARY policy map instantly. Bound %d rule(s) globally.", len(comp.Map)+len(newCIDRs))
					}
					return // Execution successfully bypassed raw extraction logic
				}
				bf.Close()
			}
		}

		savePolicyMeta(meta)

		newMap := make(map[string]int)
		var newCIDRs []dpCidrEntry

		processDomainPolicy := func(rawKey string, actionName string) int {
			discarded := 0
			for _, domainStr := range strings.Split(rawKey, ",") {
				domainStr = strings.TrimSpace(domainStr)
				if domainStr == "" {
					continue
				}

				actionStr := strings.ToUpper(actionName)
				var rcode int
				if actionStr == "DROP" { rcode = PolicyActionDrop } else if actionStr == "BLOCK" { rcode = PolicyActionBlock } else {
					rc, ok := dns.StringToRcode[actionStr]
					if !ok { continue }
					rcode = rc
				}

				if !cfg.Server.FilterIPs {
					if _, err := netip.ParseAddr(domainStr); err == nil { discarded++; continue }
					if _, err := netip.ParsePrefix(domainStr); err == nil { discarded++; continue }
				} else {
					if addr, err := netip.ParseAddr(domainStr); err == nil {
						var prefix netip.Prefix
						addr = addr.Unmap()
						if addr.Is4() { prefix = netip.PrefixFrom(addr, 32) } else { prefix = netip.PrefixFrom(addr, 128) }
						newCIDRs = append(newCIDRs, dpCidrEntry{prefix: prefix, action: rcode})
						continue
					}
					if prefix, err := ParsePrefixUnmapped(domainStr); err == nil {
						newCIDRs = append(newCIDRs, dpCidrEntry{prefix: prefix, action: rcode})
						continue
					}
				}

				clean := strings.ToLower(strings.TrimSuffix(domainStr, "."))
				if clean != "" { newMap[clean] = rcode }
			}
			return discarded
		}

		for rawKey, actionName := range cfg.DomainPolicy { 
			processDomainPolicy(rawKey, actionName) 
		}
		
		for filePath, actionName := range cfg.DomainPolicyFiles {
			lines, err := readConfigListFile(filePath)
			if err == nil {
				yieldCounter := 0
				for _, line := range lines { 
					processDomainPolicy(line, actionName) 
					yieldCounter++
					if yieldCounter%5000 == 0 {
						time.Sleep(time.Millisecond)
					}
				}
			}
		}

		for urlStr, actionName := range cfg.DomainPolicyURLs {
			var lines []string
			if data, ok := urlData[urlStr]; ok {
				lines = data
			} else if cfg.Server.PolicyCacheDir != "" {
				h := sha256.Sum256([]byte(urlStr))
				cachePath := filepath.Join(cfg.Server.PolicyCacheDir, "policy-"+hex.EncodeToString(h[:8])+".raw")
				lines, _ = readConfigListFile(cachePath)
			}
			if len(lines) > 0 {
				yieldCounter := 0
				for _, line := range lines { 
					processDomainPolicy(line, actionName) 
					yieldCounter++
					if yieldCounter%5000 == 0 {
						time.Sleep(time.Millisecond)
					}
				}
			}
		}

		if len(newCIDRs) > 0 {
			sort.SliceStable(newCIDRs, func(i, j int) bool {
				return newCIDRs[i].prefix.Bits() > newCIDRs[j].prefix.Bits()
			})
		}

		domainPolicySnap.Store(&newMap)
		domainPolicyCIDRSnap.Store(&newCIDRs)
		hasDomainPolicy.Store(len(newMap) > 0 || len(newCIDRs) > 0)
		computeDomainLabelBounds(&newMap)

		// Transparently serialize the successfully aggregated arrays statically to disk organically
		if cfg.Server.PolicyCacheDir != "" {
			os.MkdirAll(cfg.Server.PolicyCacheDir, 0755) // Ensure target boundaries exist organically
			binPath := filepath.Join(cfg.Server.PolicyCacheDir, "policy-compiled.bin")
			if bf, err := os.Create(binPath + ".tmp"); err == nil {
				var gobCidrs []DpCidrEntryGob
				for _, c := range newCIDRs {
					// [FIX] Convert complex subnets into secure strings for pristine Binary Serialization natively
					gobCidrs = append(gobCidrs, DpCidrEntryGob{Prefix: c.prefix.String(), Action: c.action})
				}
				comp := CompiledPolicy{Map: newMap, CIDRs: gobCidrs}
				bw := bufio.NewWriterSize(bf, 64*1024)
				if err := gob.NewEncoder(bw).Encode(comp); err == nil {
					bw.Flush()
					bf.Sync()
					bf.Close()
					os.Remove(binPath) // [FIX] Protects against OS-level file lock rejections natively (Windows)
					if renameErr := os.Rename(binPath+".tmp", binPath); renameErr != nil {
						if logRouting {
							log.Printf("[POLICY] WARNING: Failed to atomically rename binary cache natively: %v", renameErr)
						}
						os.Remove(binPath+".tmp")
					}
				} else {
					if logRouting {
						log.Printf("[POLICY] WARNING: Failed to encode binary cache natively: %v", err)
					}
					bf.Close()
					os.Remove(binPath+".tmp")
				}
			}
		}

		if logRouting {
			log.Printf("[POLICY] Rebuilt domain policy map. Loaded %d rule(s) globally.", len(newMap)+len(newCIDRs))
		}
	}
}

// initPolicies prepares the fast-path blocking structures for QTypes and Domains.
func initPolicies() {
	rtypePolicy = make(map[uint16]int, len(cfg.RtypePolicy))
	processRtype := func(rawKey string, actionName string) {
		for _, typeName := range strings.Split(rawKey, ",") {
			typeName = strings.TrimSpace(typeName)
			if typeName == "" { continue }
			qtype, ok := dns.StringToType[strings.ToUpper(typeName)]
			if !ok { continue }

			actionStr := strings.ToUpper(actionName)
			if actionStr == "DROP" { rtypePolicy[qtype] = PolicyActionDrop; continue }
			if actionStr == "BLOCK" { rtypePolicy[qtype] = PolicyActionBlock; continue }
			if rcode, ok := dns.StringToRcode[actionStr]; ok { rtypePolicy[qtype] = rcode }
		}
	}

	for rawKey, actionName := range cfg.RtypePolicy { processRtype(rawKey, actionName) }
	for filePath, actionName := range cfg.RtypePolicyFiles {
		lines, err := readConfigListFile(filePath)
		if err == nil {
			for _, line := range lines { processRtype(line, actionName) }
		}
	}

	if cfg.Server.FastStart {
		go pollDomainPolicies(forceRefreshStartup)
	} else {
		pollDomainPolicies(forceRefreshStartup)
	}

	pollStr := cfg.Server.PolicyPollInterval
	if pollStr == "" { pollStr = "6h" }
	if interval, err := time.ParseDuration(pollStr); err == nil && interval > 0 {
		go func() {
			t := time.NewTicker(interval)
            defer t.Stop()
			for {
                select {
                case <-t.C:
                    pollDomainPolicies(false)
                case <-shutdownCh:
                    return
                }
            }
		}()
	}

	if cfg.Server.BlockObsoleteQtypes {
		for qtype := range obsoleteQtypes {
			if _, userSet := rtypePolicy[qtype]; !userSet { rtypePolicy[qtype] = dns.RcodeNotImplemented }
		}
		blockUnknownQtypes = true
	}
	hasRtypePolicy = len(rtypePolicy) > 0
}

func computeDomainLabelBounds(dpMap *map[string]int) {
	countLabels := func(k string) int { return strings.Count(k, ".") + 1 }
	if len(*dpMap) > 0 {
		minP, maxP := 128, 1
		for k := range *dpMap {
			n := countLabels(k)
			if n < minP { minP = n }
			if n > maxP { maxP = n }
		}
		domainPolicyMinLabels.Store(int32(minP))
		domainPolicyMaxLabels.Store(int32(maxP))
	}
	if len(domainRoutes) > 0 {
		minR, maxR := 128, 1
		for k := range domainRoutes {
			n := countLabels(k)
			if n < minR { minR = n }
			if n > maxR { maxR = n }
		}
		domainRoutesMinLabels.Store(int32(minR))
		domainRoutesMaxLabels.Store(int32(maxR))
	}
}

