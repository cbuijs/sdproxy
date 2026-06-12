/*
File:    init_policy.go
Version: 1.3.0
Updated: 06-Jun-2026 15:08 CEST

Description:
  Parses and maps RType and Domain policies for sdproxy.
  Handles remote list fetching, local file parsing, and label boundary
  calculations for optimized suffix walking.

Changes:
  1.3.0 - [SECURITY/FIX] Rigidly integrated `os.WriteFile`, `Flush()`, and `Sync()` 
          guards natively inside `.tmp` file commits across Domain Policy polling tasks.
          Prevents corrupted arrays from blinding filtering maps across reboots.
  1.2.0 - [SECURITY/FIX] Eradicated a Silent Truncation vulnerability natively 
          within `pollDomainPolicies`. `LimitReader` limits are now dynamically verified. 
          If a payload exhausts the boundary unexpectedly, it organically registers as a 
          fetch failure, preventing incomplete security configurations from being deployed.
*/

package main

import (
	"bufio"
	"crypto/sha256"
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
	policyHTTPMeta = make(map[string]catListHeaders)
	policyFileMeta = make(map[string]int64)
	policyMu       sync.Mutex
)

// loadPolicyMeta retrieves the metadata for domain policies from the cache directory.
func loadPolicyMeta() map[string]catListHeaders {
	meta := make(map[string]catListHeaders)
	if cfg.Server.PolicyCacheDir == "" {
		return meta
	}
	b, err := os.ReadFile(filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json"))
	if err == nil {
		json.Unmarshal(b, &meta)
	}
	return meta
}

// savePolicyMeta persists the metadata for domain policies to the cache directory.
func savePolicyMeta(meta map[string]catListHeaders) {
	if cfg.Server.PolicyCacheDir == "" {
		return
	}
	os.MkdirAll(cfg.Server.PolicyCacheDir, 0755)
	b, err := json.Marshal(meta)
	if err == nil {
		path := filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json")
		tmp := path + ".tmp"
		
		// [SECURITY/FIX] Guard against OS-level write failures to prevent state truncation natively.
		if err := os.WriteFile(tmp, b, 0644); err == nil {
			os.Rename(tmp, path)
		} else {
			os.Remove(tmp)
		}
	}
}

// pollDomainPolicies rebuilds the domain policy map from all configured sources.
func pollDomainPolicies(force bool) {
	policyMu.Lock()
	defer policyMu.Unlock()

	changed := false
	activeFiles := make(map[string]bool)
	activeURLs := make(map[string]bool)

	if force {
		policyHTTPMeta = make(map[string]catListHeaders)
	} else if len(policyHTTPMeta) == 0 && cfg.Server.PolicyCacheDir != "" {
		policyHTTPMeta = loadPolicyMeta()
	}

	for filePath := range cfg.DomainPolicyFiles {
		activeFiles[filePath] = true
		info, err := os.Stat(filePath)
		if err != nil {
			if _, exists := policyFileMeta[filePath]; exists {
				delete(policyFileMeta, filePath)
				changed = true
				if logRouting {
					log.Printf("[POLICY] File %s was removed. Flagging policy maps for rebuild.", filePath)
				}
			}
			continue
		}
		mtime := info.ModTime().UnixNano()
		if lastMtime, ok := policyFileMeta[filePath]; !ok || lastMtime != mtime {
			policyFileMeta[filePath] = mtime
			changed = true
		}
	}

	urlData := make(map[string][]string)
	fetchFailed := make(map[string]bool)

	for urlStr := range cfg.DomainPolicyURLs {
		activeURLs[urlStr] = true
		req, err := http.NewRequest(http.MethodGet, urlStr, nil)
		if err != nil {
			fetchFailed[urlStr] = true
			continue
		}
		req.Header.Set("User-Agent", cfg.Server.UserAgent)

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

		if !force {
			if m, ok := policyHTTPMeta[urlStr]; ok && hasCacheFile {
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
			if hasCacheFile && logRouting {
				log.Printf("[POLICY] Not modified (304) for %s — queued local cache", urlStr)
			}
			continue
		} else if resp.StatusCode == http.StatusOK {
			policyHTTPMeta[urlStr] = catListHeaders{
				LastModified: resp.Header.Get("Last-Modified"),
				ETag:         resp.Header.Get("ETag"),
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
							os.Rename(tmp, cachePath)
						} else {
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

	for f := range policyFileMeta {
		if !activeFiles[f] {
			delete(policyFileMeta, f)
			changed = true
		}
	}
	for u := range policyHTTPMeta {
		if !activeURLs[u] {
			delete(policyHTTPMeta, u)
			changed = true
		}
	}

	if domainPolicySnap.Load() == nil || changed {
		savePolicyMeta(policyHTTPMeta)

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
			for range t.C { pollDomainPolicies(false) }
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

