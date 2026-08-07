/*
File:    parental_categories.go
Version: 3.0.0 (Split)
Updated: 22-Jul-2026 22:10 CEST

Description:
  Category data management and hot-path lookups for the sdproxy parental
  subsystem. Parsing, tree consolidation and data loading live in
  parental_loader.go, parental_parser.go and parental_consolidation.go.

Changes:
  3.0.0  - [TIER 2] Binary cache load/save moved onto the shared gob helpers.
           The legacy JSON path is retained read-only for one-way migration.
  2.12.0 - [LOGGING/FIX] .bin decode errors bound to logParental with clearer
           guidance when the on-disk schema predates the binary.
  2.11.0 - [PERF] Persistent cache migrated from JSON to gob; a cold boot now
           loads structural maps directly instead of decoding raw strings.
*/

package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
)

type wildcardCatEntry struct {
	Pattern string `json:"pattern"`
	Cat     string `json:"cat"`
}

// compiledWildcard precomputes the cheap rejection tests (length floor, literal
// prefix/suffix) so the expensive glob walk runs only on plausible candidates.
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
	apex             map[string]string
	compiledPatterns []compiledWildcard
	ips              map[netip.Addr]string
	cidrs            []cidrCatEntry
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

func isWildcard(s string) bool {
	return strings.ContainsAny(s, "*?")
}

// matchGlob is an iterative `*`/`?` matcher with backtracking. Iterative rather
// than recursive so a pathological pattern cannot blow the stack.
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

// CompileWildcards precomputes rejection metadata and sorts by literal length
// descending, so the most specific pattern wins when several could match.
func CompileWildcards(raw []wildcardCatEntry) []compiledWildcard {
	compiled := make([]compiledWildcard, len(raw))
	for i, r := range raw {
		stars := strings.Count(r.Pattern, "*")
		qs := strings.Count(r.Pattern, "?")

		cw := compiledWildcard{
			pattern:    r.Pattern,
			cat:        r.Cat,
			minLen:     len(r.Pattern) - stars,
			literalLen: len(r.Pattern) - stars - qs,
		}

		firstWild := strings.IndexAny(r.Pattern, "*?")
		if firstWild < 0 {
			cw.prefix = r.Pattern
			cw.suffix = r.Pattern
		} else {
			cw.prefix = r.Pattern[:firstWild]
			lastWild := strings.LastIndexAny(r.Pattern, "*?")
			cw.suffix = r.Pattern[lastWild+1:]
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

// categoryOf resolves a query name or IP to its category and the rule that matched.
func categoryOf(qname string, targetAddr netip.Addr) (string, string) {
	data := catMap.Load()
	if data == nil {
		return "", ""
	}

	// 1. IP lookups (filter_ips support). Strings are allocated only on a match.
	if targetAddr.IsValid() {
		ip := targetAddr.Unmap()
		if cat, ok := data.ips[ip]; ok {
			return cat, ip.String()
		}
		for _, c := range data.cidrs {
			if c.prefix.Contains(ip) {
				return c.cat, c.prefix.String()
			}
		}
		// Fall through to domain rules when no IP rule matched.
	}

	if qname == "" {
		return "", ""
	}

	// [PERF] Only attempt IP parsing when the first byte could plausibly start
	// one. Alphabetic domains skip the error-interface allocation entirely.
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

	// 2. Wildcards, cheapest rejection tests first.
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

	// 3. Apex suffix walk, bounded by the configured label depths.
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

	if logParental {
		log.Printf("[PARENTAL] Category walk bounds: [%d..%d] labels (%d apex entries)", catMinLabels.Load(), catMaxLabels.Load(), len(apex))
	}
}

// ---------------------------------------------------------------------------
// Disk cache
// ---------------------------------------------------------------------------

// catCacheData is the serialized category set. IPs and CIDRs are stored as
// strings because netip types are not gob-stable.
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

func catBinPath() string {
	return filepath.Join(snapshotDir(), "parental-catcache.bin")
}

func loadCatCache() {
	var data catCacheData
	loadedBin := false

	if d, err := loadGob[catCacheData](catBinPath()); err == nil {
		data = d
		loadedBin = true
	} else if logParental && !os.IsNotExist(err) {
		log.Printf("[PARENTAL] WARNING: binary cache unusable: %v — may be corrupt or from an older version", err)
	}

	// Legacy JSON fallback so an in-place upgrade doesn't lose the cache.
	if !loadedBin {
		path := filepath.Join(snapshotDir(), catCacheFile)
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		if err := json.Unmarshal(b, &data); err != nil {
			// Oldest format: a bare apex map with no wrapper.
			var apex map[string]string
			if err := json.Unmarshal(b, &apex); err != nil {
				if logParental {
					log.Printf("[PARENTAL] Cat-cache parse error: %v", err)
				}
				return
			}
			data.Apex = apex
		}
	}

	// Pre-wrapper caches carry no patterns; rebuild them from config.
	var patterns []wildcardCatEntry
	if len(data.Patterns) == 0 {
		for cat, cc := range cfg.Parental.Categories {
			for _, d := range cc.Add {
				d = strings.ToLower(strings.TrimSuffix(d, "."))
				if isWildcard(d) {
					patterns = append(patterns, wildcardCatEntry{Pattern: d, Cat: cat})
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

	if len(cidrs) > 0 {
		sort.SliceStable(cidrs, func(i, j int) bool {
			return cidrs[i].prefix.Bits() > cidrs[j].prefix.Bits()
		})
	}

	catMap.Store(&categoryData{
		apex:             data.Apex,
		compiledPatterns: CompileWildcards(patterns),
		ips:              ips,
		cidrs:            cidrs,
	})
	catMapInitialized.Store(true)
	computeCatLabelBounds(data.Apex)

	if logParental {
		src := "JSON"
		if loadedBin {
			src = "Binary"
		}
		log.Printf("[PARENTAL] %s category cache loaded: %d apex, %d patterns, %d IPs, %d CIDRs",
			src, len(data.Apex), len(patterns), len(ips), len(cidrs))
	}
}

func saveCatCache(apex map[string]string, patterns []wildcardCatEntry, ips map[netip.Addr]string, cidrs []cidrCatEntry) {
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

	if err := saveGob(catBinPath(), data); err != nil {
		if logParental {
			log.Printf("[PARENTAL] WARNING: failed to write category cache: %v", err)
		}
		return
	}
	// Prune the superseded JSON payload.
	os.Remove(filepath.Join(snapshotDir(), catCacheFile))
}

