/*
File:    init_policy.go
Version: 2.0.0
Updated: 22-Jul-2026 22:10 CEST

Description:
  Parses and maps RType and Domain policies for sdproxy.
  Handles remote list fetching, local file parsing, and label boundary
  calculations for optimized suffix walking.

  Like the ASN loader, this uses a compiled binary cache so a cold boot can skip
  both the network and the rule-parsing pass entirely.

Changes:
  2.0.0  - [TIER 2] Both gob-load blocks collapsed behind loadCompiledPolicy();
           meta and raw-cache writes moved to the shared atomic helpers.
  1.13.0 - [SECURITY/RELIABILITY] Directory fsync on cache renames.
  1.12.0 - [LOGGING/FIX] Binary cache decode faults distinguished from OS-level
           open failures.
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

// policyFreshnessTTL skips the network when the list was validated recently.
const policyFreshnessTTL = 3 * 3600

var policyMu sync.Mutex

// CompiledPolicy is the binary cache payload: the fully built domain map plus
// the CIDR table, ready to publish without re-parsing any source.
type CompiledPolicy struct {
	Map   map[string]int
	CIDRs []DpCidrEntryGob
}

// DpCidrEntryGob stores the prefix as a string — netip.Prefix is not gob-stable.
type DpCidrEntryGob struct {
	Prefix string
	Action int
}

type policyMetaState struct {
	ConfigHash string                    `json:"config_hash"`
	HTTPMeta   map[string]catListHeaders `json:"http_meta"`
	FileMeta   map[string]int64          `json:"file_meta"`
}

func policyBinPath() string {
	if cfg.Server.PolicyCacheDir == "" {
		return ""
	}
	return filepath.Join(cfg.Server.PolicyCacheDir, "policy-compiled.bin")
}

func policyRawPath(urlStr string) string {
	if cfg.Server.PolicyCacheDir == "" {
		return ""
	}
	h := sha256.Sum256([]byte(urlStr))
	return filepath.Join(cfg.Server.PolicyCacheDir, "policy-"+hex.EncodeToString(h[:8])+".raw")
}

func loadPolicyMeta() policyMetaState {
	var meta policyMetaState
	if cfg.Server.PolicyCacheDir != "" {
		if b, err := os.ReadFile(filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json")); err == nil {
			json.Unmarshal(b, &meta)
		}
	}
	// [SECURITY] Instantiate both maps: an absent or null cache would otherwise
	// produce a nil-map assignment panic on the next write.
	if meta.HTTPMeta == nil {
		meta.HTTPMeta = make(map[string]catListHeaders)
	}
	if meta.FileMeta == nil {
		meta.FileMeta = make(map[string]int64)
	}
	return meta
}

func savePolicyMeta(meta policyMetaState) {
	if cfg.Server.PolicyCacheDir == "" {
		return
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return
	}
	path := filepath.Join(cfg.Server.PolicyCacheDir, "policy-meta.json")
	if err := atomicWrite(path, b, 0644); err != nil && logRouting {
		log.Printf("[POLICY] WARNING: failed to persist meta file: %v", err)
	}
}

// loadCompiledPolicy restores and publishes the policy maps from the binary
// cache. Returns false on a missing or unusable cache, in which case the caller
// falls back to parsing the raw sources.
func loadCompiledPolicy() bool {
	binPath := policyBinPath()
	if binPath == "" {
		return false
	}

	comp, err := loadGob[CompiledPolicy](binPath)
	if err != nil {
		if logRouting && !os.IsNotExist(err) {
			log.Printf("[POLICY] WARNING: binary cache unusable (%s): %v — may be corrupt or from an older version",
				filepath.Base(binPath), err)
		}
		return false
	}

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

	if logRouting {
		log.Printf("[POLICY] Loaded compiled BINARY policy map instantly. Bound %d rule(s) globally.", len(comp.Map)+len(newCIDRs))
	}
	return true
}

// saveCompiledPolicy writes the built maps to the binary cache.
func saveCompiledPolicy(m map[string]int, cidrs []dpCidrEntry) {
	binPath := policyBinPath()
	if binPath == "" {
		return
	}
	gobCidrs := make([]DpCidrEntryGob, 0, len(cidrs))
	for _, c := range cidrs {
		gobCidrs = append(gobCidrs, DpCidrEntryGob{Prefix: c.prefix.String(), Action: c.action})
	}
	if err := saveGob(binPath, CompiledPolicy{Map: m, CIDRs: gobCidrs}); err != nil && logRouting {
		log.Printf("[POLICY] WARNING: failed to write binary cache: %v", err)
	}
}

// computePolicyConfigHash fingerprints the inline config so an edit to
// domain_policy triggers a rebuild even when no source file changed.
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

	// [PERF] Cold-boot fast path: config and local files unchanged means the
	// compiled cache is authoritative. Skip the network and the parse pass.
	if isStartup && !changed && !force && loadCompiledPolicy() {
		return
	}

	urlData := make(map[string][]string)
	nowUnix := time.Now().Unix()

	for urlStr := range cfg.DomainPolicyURLs {
		activeURLs[urlStr] = true

		cachePath := policyRawPath(urlStr)
		hasCacheFile := false
		if cachePath != "" {
			os.MkdirAll(cfg.Server.PolicyCacheDir, 0755)
			if _, errStat := os.Stat(cachePath); errStat == nil {
				hasCacheFile = true
			}
		}

		var m catListHeaders
		var hasMeta bool
		if !force {
			m, hasMeta = meta.HTTPMeta[urlStr]
		}

		// [PERF] Freshness gate — avoids CDN rate limits and boot latency.
		if !force && hasCacheFile && hasMeta && (nowUnix-m.LastFetch) < policyFreshnessTTL {
			if logRouting {
				log.Printf("[POLICY] Fresh in cache (<3h) — queued local cache for %s", urlStr)
			}
			continue
		}

		req, err := http.NewRequest(http.MethodGet, urlStr, nil)
		if err != nil {
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
			if logRouting {
				if !hasCacheFile {
					log.Printf("[POLICY] Fetch failed for %s: %v", urlStr, err)
				} else {
					log.Printf("[POLICY] Fetch failed for %s: %v — falling back to local cache", urlStr, err)
				}
			}
			continue
		}

		switch {
		case resp.StatusCode == http.StatusNotModified:
			resp.Body.Close()
			m.LastFetch = nowUnix
			meta.HTTPMeta[urlStr] = m
			if hasCacheFile && logRouting {
				log.Printf("[POLICY] Not modified (304) for %s — queued local cache", urlStr)
			}

		case resp.StatusCode == http.StatusOK:
			meta.HTTPMeta[urlStr] = catListHeaders{
				LastModified: resp.Header.Get("Last-Modified"),
				ETag:         resp.Header.Get("ETag"),
				LastFetch:    nowUnix,
			}

			var lines []string
			// [SECURITY] Read one byte past the cap so truncation is detected.
			lr := io.LimitReader(resp.Body, maxRemoteListBytes+1)
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

			overflow := scanner.Err() == nil && lr.(*io.LimitedReader).N == 0
			resp.Body.Close()

			if overflow {
				if logRouting {
					log.Printf("[POLICY] Security constraint: payload exceeded %dMB safety limit for %s",
						maxRemoteListBytes/(1024*1024), urlStr)
				}
				continue
			}

			urlData[urlStr] = lines

			if cachePath != "" {
				err := atomicWriteBuf(cachePath, 0644, func(bw *bufio.Writer) error {
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
				if err != nil && logRouting {
					log.Printf("[POLICY] WARNING: failed to write raw cache for %s: %v", urlStr, err)
				} else if logRouting {
					log.Printf("[POLICY] Fetched %d entries from %s — saved to cache", len(lines), urlStr)
				}
			}
			changed = true

		default:
			status := resp.StatusCode
			resp.Body.Close()
			if hasCacheFile && logRouting {
				log.Printf("[POLICY] HTTP %d for %s — falling back to local cache", status, urlStr)
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

	if !isStartup && !changed {
		return
	}

	// Nothing actually changed on this pass — the compiled cache is still valid.
	if !changed && !force && loadCompiledPolicy() {
		return
	}

	savePolicyMeta(meta)

	newMap := make(map[string]int)
	var newCIDRs []dpCidrEntry

	processDomainPolicy := func(rawKey string, actionName string) {
		for _, domainStr := range strings.Split(rawKey, ",") {
			domainStr = strings.TrimSpace(domainStr)
			if domainStr == "" {
				continue
			}

			actionStr := strings.ToUpper(actionName)
			var rcode int
			if actionStr == "DROP" {
				rcode = PolicyActionDrop
			} else if actionStr == "BLOCK" {
				rcode = PolicyActionBlock
			} else {
				rc, ok := dns.StringToRcode[actionStr]
				if !ok {
					continue
				}
				rcode = rc
			}

			if !cfg.Server.FilterIPs {
				// IP/CIDR entries are meaningless without filter_ips — discard
				// rather than storing them as unreachable domain keys.
				if _, err := netip.ParseAddr(domainStr); err == nil {
					continue
				}
				if _, err := netip.ParsePrefix(domainStr); err == nil {
					continue
				}
			} else {
				if addr, err := netip.ParseAddr(domainStr); err == nil {
					addr = addr.Unmap()
					var prefix netip.Prefix
					if addr.Is4() {
						prefix = netip.PrefixFrom(addr, 32)
					} else {
						prefix = netip.PrefixFrom(addr, 128)
					}
					newCIDRs = append(newCIDRs, dpCidrEntry{prefix: prefix, action: rcode})
					continue
				}
				if prefix, err := ParsePrefixUnmapped(domainStr); err == nil {
					newCIDRs = append(newCIDRs, dpCidrEntry{prefix: prefix, action: rcode})
					continue
				}
			}

			clean := strings.ToLower(strings.TrimSuffix(domainStr, "."))
			if clean != "" {
				newMap[clean] = rcode
			}
		}
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
		} else if cachePath := policyRawPath(urlStr); cachePath != "" {
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

	// Most-specific-wins: sort by prefix length descending so the first match
	// during lookup is the tightest one.
	if len(newCIDRs) > 0 {
		sort.SliceStable(newCIDRs, func(i, j int) bool {
			return newCIDRs[i].prefix.Bits() > newCIDRs[j].prefix.Bits()
		})
	}

	domainPolicySnap.Store(&newMap)
	domainPolicyCIDRSnap.Store(&newCIDRs)
	hasDomainPolicy.Store(len(newMap) > 0 || len(newCIDRs) > 0)
	computeDomainLabelBounds(&newMap)
	saveCompiledPolicy(newMap, newCIDRs)

	if logRouting {
		log.Printf("[POLICY] Rebuilt domain policy map. Loaded %d rule(s) globally.", len(newMap)+len(newCIDRs))
	}
}

// initPolicies prepares the fast-path blocking structures for QTypes and Domains.
func initPolicies() {
	rtypePolicy = make(map[uint16]int, len(cfg.RtypePolicy))
	processRtype := func(rawKey string, actionName string) {
		for _, typeName := range strings.Split(rawKey, ",") {
			typeName = strings.TrimSpace(typeName)
			if typeName == "" {
				continue
			}
			qtype, ok := dns.StringToType[strings.ToUpper(typeName)]
			if !ok {
				continue
			}

			actionStr := strings.ToUpper(actionName)
			if actionStr == "DROP" {
				rtypePolicy[qtype] = PolicyActionDrop
				continue
			}
			if actionStr == "BLOCK" {
				rtypePolicy[qtype] = PolicyActionBlock
				continue
			}
			if rcode, ok := dns.StringToRcode[actionStr]; ok {
				rtypePolicy[qtype] = rcode
			}
		}
	}

	for rawKey, actionName := range cfg.RtypePolicy {
		processRtype(rawKey, actionName)
	}
	for filePath, actionName := range cfg.RtypePolicyFiles {
		lines, err := readConfigListFile(filePath)
		if err == nil {
			for _, line := range lines {
				processRtype(line, actionName)
			}
		}
	}

	if cfg.Server.FastStart {
		go pollDomainPolicies(forceRefreshStartup)
	} else {
		pollDomainPolicies(forceRefreshStartup)
	}

	pollStr := cfg.Server.PolicyPollInterval
	if pollStr == "" {
		pollStr = "6h"
	}
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
			// Never override an explicit user rule.
			if _, userSet := rtypePolicy[qtype]; !userSet {
				rtypePolicy[qtype] = dns.RcodeNotImplemented
			}
		}
		blockUnknownQtypes = true
	}
	hasRtypePolicy = len(rtypePolicy) > 0
}

// computeDomainLabelBounds records the shallowest and deepest configured entry
// so walkDomainMaps can skip label levels no rule could ever match.
func computeDomainLabelBounds(dpMap *map[string]int) {
	countLabels := func(k string) int { return strings.Count(k, ".") + 1 }
	if len(*dpMap) > 0 {
		minP, maxP := 128, 1
		for k := range *dpMap {
			n := countLabels(k)
			if n < minP {
				minP = n
			}
			if n > maxP {
				maxP = n
			}
		}
		domainPolicyMinLabels.Store(int32(minP))
		domainPolicyMaxLabels.Store(int32(maxP))
	}
	if len(domainRoutes) > 0 {
		minR, maxR := 128, 1
		for k := range domainRoutes {
			n := countLabels(k)
			if n < minR {
				minR = n
			}
			if n > maxR {
				maxR = n
			}
		}
		domainRoutesMinLabels.Store(int32(minR))
		domainRoutesMaxLabels.Store(int32(maxR))
	}
}

