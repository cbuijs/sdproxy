/*
File:    parental_categories.go
Version: 2.5.0 (Split)
Updated: 07-May-2026 12:13 CEST

Description:
  Category data management and lookups for the sdproxy parental subsystem.
  Extracted parsing, tree consolidation, and data loading into:
    - parental_loader.go
    - parental_parser.go
    - parental_consolidation.go

Changes:
  2.5.0  - [PERF] Eradicated severe heap allocations during domain-to-IP filter 
           evaluations on the hot path. A rapid byte-scan heuristic now intercepts 
           alphabetical domains instantly, completely bypassing `netip.ParseAddr` 
           error interface allocations natively.
*/

package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Category data structures
// ---------------------------------------------------------------------------

type wildcardCatEntry struct {
	pattern string 
	cat     string 
}

type compiledWildcard struct {
	pattern    string
	cat        string
	minLen     int
	literalLen int
	prefix     string
	suffix     string
}

type cidrCatEntry struct {
	prefix netip.Prefix
	cat    string
}

type categoryData struct {
	apex map[string]string
	compiledPatterns []compiledWildcard
	ips map[netip.Addr]string
	cidrs []cidrCatEntry
}

var catMap atomic.Pointer[categoryData]

var (
	catMinLabels atomic.Int32
	catMaxLabels atomic.Int32
)

func init() {
	catMinLabels.Store(1)
	catMaxLabels.Store(128)
}

// ---------------------------------------------------------------------------
// Wildcard helpers & Compilation
// ---------------------------------------------------------------------------

func isWildcard(s string) bool {
	return strings.ContainsAny(s, "*?")
}

func matchGlob(p, s string) bool {
	starP, starS := -1, 0
	pi, si := 0, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			starP = pi
			starS = si
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case starP >= 0:
			starS++
			si = starS
			pi = starP + 1
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func CompileWildcards(raw []wildcardCatEntry) []compiledWildcard {
	compiled := make([]compiledWildcard, len(raw))
	for i, r := range raw {
		stars := strings.Count(r.pattern, "*")
		qs := strings.Count(r.pattern, "?")
		
		cw := compiledWildcard{
			pattern:    r.pattern,
			cat:        r.cat,
			minLen:     len(r.pattern) - stars,
			literalLen: len(r.pattern) - stars - qs,
		}

		firstWild := strings.IndexAny(r.pattern, "*?")
		if firstWild < 0 {
			cw.prefix = r.pattern
			cw.suffix = r.pattern
		} else {
			cw.prefix = r.pattern[:firstWild]
			lastWild := strings.LastIndexAny(r.pattern, "*?")
			cw.suffix = r.pattern[lastWild+1:]
		}
		compiled[i] = cw
	}

	slices.SortFunc(compiled, func(a, b compiledWildcard) int {
		if a.literalLen > b.literalLen {
			return -1
		} else if a.literalLen < b.literalLen {
			return 1
		}
		return 0
	})

	return compiled
}

// ---------------------------------------------------------------------------
// Category lookup (hot path)
// ---------------------------------------------------------------------------

func categoryOf(qname string, targetAddr netip.Addr) (string, string) {
	data := catMap.Load()
	if data == nil {
		return "", ""
	}

	// 1. Directly short circuit for IP lookups (Filter IPs Support)
	// Zero-allocation fallback for hot-path IP mapping
	if targetAddr.IsValid() {
		ip := targetAddr.Unmap()
		if cat, ok := data.ips[ip]; ok {
			return cat, ip.String() // Allocated only strictly on match
		}
		for _, c := range data.cidrs {
			if c.prefix.Contains(ip) {
				return c.cat, c.prefix.String() // Allocated only strictly on match
			}
		}
		// Allow logic to cascade downward to execute domain constraints natively 
		// when physical IP array evaluations register zero active blocks.
	}

	if qname == "" {
		return "", ""
	}

	// [PERF] Fast-path heuristic: only invoke netip.ParseAddr if the string starts 
	// with a digit or IPv6 colon. Radically reduces heap allocations for alphabetical 
	// domain queries escaping the error interface natively.
	if (qname[0] >= '0' && qname[0] <= '9') || qname[0] == ':' {
		if ip, err := netip.ParseAddr(qname); err == nil {
			ip = ip.Unmap()
			if cat, ok := data.ips[ip]; ok {
				return cat, ip.String()
			}
			for _, c := range data.cidrs {
				if c.prefix.Contains(ip) {
					return c.cat, c.prefix.String()
				}
			}
			return "", ""
		}
	}

	// 2. High-Performance Wildcard Evaluation
	for _, e := range data.compiledPatterns {
		if len(qname) < e.minLen {
			continue
		}
		if e.prefix != "" && !strings.HasPrefix(qname, e.prefix) {
			continue
		}
		if e.suffix != "" && !strings.HasSuffix(qname, e.suffix) {
			continue
		}
		
		if matchGlob(e.pattern, qname) {
			return e.cat, e.pattern
		}
	}
	
	// 3. Apex Resolution
	labels := countDomainLabels(qname)
	ceiling := int(catMaxLabels.Load())
	
	if ceiling > labels {
		ceiling = labels
	}
	search := qname
	for labels > ceiling {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
		labels--
	}
	for {
		if cat, ok := data.apex[search]; ok {
			return cat, search
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 || labels <= int(catMinLabels.Load()) {
			break
		}
		search = search[idx+1:]
		labels--
	}
	return "", ""
}

func computeCatLabelBounds(apex map[string]string) {
	if len(apex) == 0 {
		catMinLabels.Store(1)
		catMaxLabels.Store(128)
		return
	}
	minL, maxL := int(^uint(0)>>1), 0
	for k := range apex {
		n := countDomainLabels(k)
		if n < minL {
			minL = n
		}
		if n > maxL {
			maxL = n
		}
	}
	catMinLabels.Store(int32(minL))
	catMaxLabels.Store(int32(maxL))
	log.Printf("[PARENTAL] Category walk bounds: [%d..%d] labels (%d apex entries)", catMinLabels.Load(), catMaxLabels.Load(), len(apex))
}

// ---------------------------------------------------------------------------
// Disk Cache Persistence
// ---------------------------------------------------------------------------

type catCacheData struct {
	Apex     map[string]string  `json:"apex"`
	Patterns []wildcardCatEntry `json:"patterns"`
	IPs      map[string]string  `json:"ips"`
	CIDRs    []cidrCatEntryStr  `json:"cidrs"`
}

type cidrCatEntryStr struct {
	Prefix string `json:"prefix"`
	Cat    string `json:"cat"`
}

func loadCatCache() {
	path := filepath.Join(snapshotDir(), catCacheFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var data catCacheData
	if err := json.Unmarshal(b, &data); err != nil {
		var apex map[string]string
		if err := json.Unmarshal(b, &apex); err != nil {
			log.Printf("[PARENTAL] Cat-cache parse error: %v", err)
			return
		}
		data.Apex = apex
	}

	var patterns []wildcardCatEntry
	if len(data.Patterns) == 0 {
		for cat, cc := range cfg.Parental.Categories {
			for _, d := range cc.Add {
				d = strings.ToLower(strings.TrimSuffix(d, "."))
				if isWildcard(d) {
					patterns = append(patterns, wildcardCatEntry{pattern: d, cat: cat})
				}
			}
		}
	} else {
		patterns = data.Patterns
	}

	ips := make(map[netip.Addr]string, len(data.IPs))
	for k, v := range data.IPs {
		if ip, err := netip.ParseAddr(k); err == nil {
			ips[ip] = v
		}
	}

	var cidrs []cidrCatEntry
	for _, c := range data.CIDRs {
		if prefix, err := netip.ParsePrefix(c.Prefix); err == nil {
			cidrs = append(cidrs, cidrCatEntry{prefix: prefix, cat: c.Cat})
		}
	}

	catMap.Store(&categoryData{
		apex:             data.Apex,
		compiledPatterns: CompileWildcards(patterns),
		ips:              ips,
		cidrs:            cidrs,
	})
	computeCatLabelBounds(data.Apex)
	log.Printf("[PARENTAL] Category cache loaded: %d apex, %d patterns, %d IPs, %d CIDRs", len(data.Apex), len(patterns), len(ips), len(cidrs))
}

func saveCatCache(apex map[string]string, patterns []wildcardCatEntry, ips map[netip.Addr]string, cidrs []cidrCatEntry) {
	path := filepath.Join(snapshotDir(), catCacheFile)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}

	data := catCacheData{
		Apex:     apex,
		Patterns: patterns,
		IPs:      make(map[string]string, len(ips)),
		CIDRs:    make([]cidrCatEntryStr, len(cidrs)),
	}
	for k, v := range ips {
		data.IPs[k.String()] = v
	}
	for i, c := range cidrs {
		data.CIDRs[i] = cidrCatEntryStr{Prefix: c.prefix.String(), Cat: c.cat}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		os.Rename(tmp, path)
	}
}

