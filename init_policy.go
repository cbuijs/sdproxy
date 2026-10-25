/*
File:    init_policy.go
Version: 2.3.0
Last Updated: 23-Oct-2026 17:18 CEST

Description:
  Parses and maps RType and Domain policies for sdproxy.
  Handles remote list fetching, local file parsing, regex compilation/validation,
  and label boundary calculations for optimized suffix walking.

  Like the ASN loader, this uses a compiled binary cache so a cold boot can skip
  both the network and the rule-parsing pass entirely.

Changes:
  2.3.0  - [SECURITY/FIX] Saved `policy-meta.json` when remote policy URLs return
           `304 Not Modified` so the refreshed `LastFetch` timestamp is persisted
           to disk instead of expiring repeatedly across restarts.
         - [SECURITY/FIX] Checked `scanner.Err()` when streaming remote policy lists
           in `pollDomainPolicies` so mid-stream network read errors do not overwrite
           valid cached policy lists with truncated data.
         - [FIX] Included `ipVersionSupport` in `computePolicyConfigHash` and enforced
           `ipVersionSupport` filtering when parsing IP/CIDR entries in `domain_policy`
           to match `parental_loader.go` and `identity_asn.go`.
  2.2.0  - [SECURITY/FIX] Cleared `meta.HTTPMeta` when reading `policy_cache_dir`
           and the raw cache file is missing on disk, preventing `pollDomainPolicies`
           from silently skipping a remote download for up to 3 hours (`policyFreshnessTTL`)
           if the `.raw` cache file was deleted while `policy-meta.json` remained.
  2.1.1  - [FIX] Replaced generic bracket call with `loadCompiledPolicyGob(binPath)`
           to prevent bracket-stripping build errors.
  2.1.0  - [FEAT] Added regex domain matching (`/pattern/`) support to `domain_policy`,
           `domain_policy_files`, `domain_policy_urls`, and `CompiledPolicy` binary
           cache persistence, with load-time syntax validation.
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
// the CIDR and Regex tables, ready to publish without re-parsing any source.
type CompiledPolicy struct {
	Map     map[string]int
	CIDRs   []DpCidrEntryGob
	Regexes []DpRegexEntryGob
}

// DpCidrEntryGob stores the prefix as a string — netip.Prefix is not gob-stable.
type DpCidrEntryGob struct {
	Prefix string
	Action int
}

// DpRegexEntryGob stores the raw "/pattern/" string and action for binary cache persistence.
type DpRegexEntryGob struct {
	Raw    string
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

	comp, err := loadCompiledPolicyGob(binPath)
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

	var newRegexes []dpRegexEntry
	for _, r := range comp.Regexes {
		re, err := compileDomainRegex(r.Raw)
		if err != nil {
			if logRouting {
				log.Printf("[POLICY] WARNING: invalid regex %q in binary cache: %v — triggering rebuild", r.Raw, err)
			}
			return false
		}
		newRegexes = append(newRegexes, dpRegexEntry{raw: r.Raw, re: re, action: r.Action})
	}

	domainPolicySnap.Store(&comp.Map)
	domainPolicyCIDRSnap.Store(&newCIDRs)
	domainPolicyRegexSnap.Store(&newRegexes)
	hasDomainPolicy.Store(len(comp.Map) > 0 || len(newCIDRs) > 0 || len(newRegexes) > 0)
	computeDomainLabelBounds(&comp.Map)

	if logRouting {
		log.Printf("[POLICY] Loaded compiled BINARY policy map instantly. Bound %d rule(s) globally (%d regex).",
			len(comp.Map)+len(newCIDRs)+len(newRegexes), len(newRegexes))
	}
	return true
}

// saveCompiledPolicy writes the built maps to the binary cache.
func saveCompiledPolicy(m map[string]int, cidrs []dpCidrEntry, regexes []dpRegexEntry) {
	binPath := policyBinPath()
	if binPath == "" {
		return
	}
	gobCidrs := make([]DpCidrEntryGob, 0, len(cidrs))
	for _, c := range cidrs {
		gobCidrs = append(gobCidrs, DpCidrEntryGob{Prefix: c.prefix.String(), Action: c.action})
	}
	gobRegexes := make([]DpRegexEntryGob, 0, len(regexes))
	for _, r := range regexes {
		gobRegexes = append(gobRegexes, DpRegexEntryGob{Raw: r.raw, Action: r.action})
	}
	if err := saveGob(binPath, CompiledPolicy{Map: m, CIDRs: gobCidrs, Regexes: gobRegexes}); err != nil && logRouting {
		log.Printf("[POLICY] WARNING: failed to write binary cache: %v", err)
	}
}

// computePolicyConfigHash fingerprints the inline config so an edit to
// domain_policy or IP version support triggers a rebuild even when no source file changed.
func computePolicyConfigHash() string {
	type hashData struct {
		Policy    map[string]string
		Files     map[string]string
		URLs      map[string]string
		FilterIPs bool
		IPVersion string
	}
	hd := hashData{
		Policy:    cfg.DomainPolicy,
		Files:     cfg.DomainPolicyFiles,
		URLs:      cfg.DomainPolicyURLs,
		FilterIPs: cfg.Server.FilterIPs,
		IPVersion: ipVersionSupport,
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
	metaDirty := false
	activeFiles := make(map[string]bool)
	activeURLs := make(map[string]bool)

	meta := loadPolicyMeta()

	if force {
		changed = true
		metaDirty = true
		meta.HTTPMeta = make(map[string]catListHeaders)
		meta.FileMeta = make(map[string]int64)
	}

	currentHash := computePolicyConfigHash()
	if meta.ConfigHash != currentHash {
		changed = true
		metaDirty = true
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
				metaDirty = true
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
			metaDirty = true
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
			if hasMeta && !hasCacheFile && cachePath != "" {
				delete(meta.HTTPMeta, urlStr)
				hasMeta = false
				changed = true
				metaDirty = true
			}
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
			metaDirty = true
			if hasCacheFile && logRouting {
				log.Printf("[POLICY] Not modified (304) for %s — queued local cache", urlStr)
			}

		case resp.StatusCode == http.StatusOK:
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

			scanErr := scanner.Err()
			overflow := scanErr == nil && lr.(*io.LimitedReader).N == 0
			resp.Body.Close()

			if scanErr != nil {
				if logRouting {
					log.Printf("[POLICY] Stream read error for %s: %v — aborting update", urlStr, scanErr)
				}
				continue
			}

			if overflow {
				if logRouting {
					log.Printf("[POLICY] Security constraint: payload exceeded %dMB safety limit for %s",
						maxRemoteListBytes/(1024*1024), urlStr)
				}
				continue
			}

			meta.HTTPMeta[urlStr] = catListHeaders{
				LastModified: resp.Header.Get("Last-Modified"),
				ETag:         resp.Header.Get("ETag"),
				LastFetch:    nowUnix,
			}
			metaDirty = true

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
			metaDirty = true
		}
	}
	for u := range meta.HTTPMeta {
		if !activeURLs[u] {
			delete(meta.HTTPMeta, u)
			changed = true
			metaDirty = true
		}
	}

	if !isStartup && !changed {
		if metaDirty {
			savePolicyMeta(meta)
		}
		return
	}

	// Nothing actually changed on this pass — the compiled cache is still valid.
	if !changed && !force && loadCompiledPolicy() {
		if metaDirty {
			savePolicyMeta(meta)
		}
		return
	}

	savePolicyMeta(meta)

	newMap := make(map[string]int)
	var newCIDRs []dpCidrEntry
	var newRegexes []dpRegexEntry
	seenRegex := make(map[string]int)

	processDomainPolicy := func(rawKey string, actionName string, fatalOnBadRegex bool) {
		actionStr := strings.ToUpper(strings.TrimSpace(actionName))
		var rcode int
		if actionStr == "DROP" {
			rcode = PolicyActionDrop
		} else if actionStr == "BLOCK" {
			rcode = PolicyActionBlock
		} else {
			rc, ok := dns.StringToRcode[actionStr]
			if !ok {
				return
			}
			rcode = rc
		}

		for _, domainStr := range splitDomainPolicyKeys(rawKey) {
			if isRegexKey(domainStr) {
				re, err := compileDomainRegex(domainStr)
				if err != nil {
					if fatalOnBadRegex {
						log.Fatalf("[FATAL] domain_policy: %v", err)
					}
					if logRouting || logSystem {
						log.Printf("[POLICY] ERROR: invalid regex %q skipped: %v", domainStr, err)
					}
					continue
				}
				if idx, exists := seenRegex[domainStr]; exists {
					newRegexes[idx].action = rcode
				} else {
					seenRegex[domainStr] = len(newRegexes)
					newRegexes = append(newRegexes, dpRegexEntry{
						raw:    domainStr,
						re:     re,
						action: rcode,
					})
				}
				continue
			}

			if !cfg.Server.FilterIPs {
				if _, err := netip.ParseAddr(domainStr); err == nil {
					continue
				}
				if _, err := netip.ParsePrefix(domainStr); err == nil {
					continue
				}
			} else {
				if addr, err := netip.ParseAddr(domainStr); err == nil {
					addr = addr.Unmap()
					if ipVersionSupport != "both" {
						if ipVersionSupport == "ipv4" && !addr.Is4() {
							continue
						}
						if ipVersionSupport == "ipv6" && !addr.Is6() {
							continue
						}
					}
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
					if ipVersionSupport != "both" {
						if ipVersionSupport == "ipv4" && !prefix.Addr().Is4() {
							continue
						}
						if ipVersionSupport == "ipv6" && !prefix.Addr().Is6() {
							continue
						}
					}
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

	inlineKeys := make([]string, 0, len(cfg.DomainPolicy))
	for k := range cfg.DomainPolicy {
		inlineKeys = append(inlineKeys, k)
	}
	sort.Strings(inlineKeys)
	for _, rawKey := range inlineKeys {
		processDomainPolicy(rawKey, cfg.DomainPolicy[rawKey], isStartup)
	}

	fileKeys := make([]string, 0, len(cfg.DomainPolicyFiles))
	for k := range cfg.DomainPolicyFiles {
		fileKeys = append(fileKeys, k)
	}
	sort.Strings(fileKeys)
	for _, filePath := range fileKeys {
		actionName := cfg.DomainPolicyFiles[filePath]
		lines, err := readConfigListFile(filePath)
		if err == nil {
			yieldCounter := 0
			for _, line := range lines {
				processDomainPolicy(line, actionName, isStartup)
				yieldCounter++
				if yieldCounter%5000 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}
	}

	urlKeys := make([]string, 0, len(cfg.DomainPolicyURLs))
	for k := range cfg.DomainPolicyURLs {
		urlKeys = append(urlKeys, k)
	}
	sort.Strings(urlKeys)
	for _, urlStr := range urlKeys {
		actionName := cfg.DomainPolicyURLs[urlStr]
		var lines []string
		if data, ok := urlData[urlStr]; ok {
			lines = data
		} else if cachePath := policyRawPath(urlStr); cachePath != "" {
			lines, _ = readConfigListFile(cachePath)
		}
		if len(lines) > 0 {
			yieldCounter := 0
			for _, line := range lines {
				processDomainPolicy(line, actionName, isStartup && !cfg.Server.FastStart)
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
	domainPolicyRegexSnap.Store(&newRegexes)
	hasDomainPolicy.Store(len(newMap) > 0 || len(newCIDRs) > 0 || len(newRegexes) > 0)
	computeDomainLabelBounds(&newMap)
	saveCompiledPolicy(newMap, newCIDRs, newRegexes)

	if logRouting {
		log.Printf("[POLICY] Rebuilt domain policy map. Loaded %d rule(s) globally (%d regex).",
			len(newMap)+len(newCIDRs)+len(newRegexes), len(newRegexes))
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
	} else {
		domainPolicyMinLabels.Store(1)
		domainPolicyMaxLabels.Store(128)
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
	} else {
		domainRoutesMinLabels.Store(1)
		domainRoutesMaxLabels.Store(128)
	}
}

