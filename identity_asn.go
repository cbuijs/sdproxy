/*
File:    identity_asn.go
Version: 2.0.0
Updated: 22-Jul-2026 22:10 CEST

Description:
  Autonomous System Number (ASN) identity resolution and database fetching.
  Retrieves and parses remote/local IPinfo JSON/GZ databases.

  Three cache tiers, fastest first:
    1. Compiled binary cache (.bin, gob)  — instant, skips JSON parsing entirely.
    2. Raw payload cache (.raw, JSON/GZ)  — parsed, then recompiled to .bin.
    3. Network fetch (conditional GET)    — only when 1 and 2 are stale/absent.

  A 3-hour freshness TTL short-circuits the network entirely, which is what keeps
  cold boots fast on routers with slow or unreachable WAN links.

Changes:
  2.0.0  - [TIER 2] The six copy-pasted gob-load blocks collapsed into
           loadASNBinCache (helpers_io.go) behind two local closures. Meta and
           binary cache writes now use the shared atomic helpers.
  1.38.0 - [SECURITY/RELIABILITY] Directory fsync on cache renames.
  1.37.0 - [SECURITY/FIX] Corrected []AsnRange vs []AsnRangeGob assertion that
           made the decoder discard every valid binary cache.
*/

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// asnMaxRawBytes caps a downloaded ASN payload before decompression.
	asnMaxRawBytes = 100 * 1024 * 1024
	// asnMaxDecompressedBytes caps the gzip output. [SECURITY] Gzip-bomb guard.
	asnMaxDecompressedBytes = 500 * 1024 * 1024
	// asnFreshnessTTL skips the network when the cache was validated recently.
	asnFreshnessTTL = 3 * 3600
)

type AsnRange struct {
	Start   netip.Addr
	End     netip.Addr
	ASN     string
	Name    string
	Country string
}

// AsnRangeGob is the on-disk form. Addresses are stored as strings because
// netip.Addr's internal layout is not gob-stable across Go releases.
type AsnRangeGob struct {
	Start   string
	End     string
	ASN     string
	Name    string
	Country string
}

type asnLookupTable struct {
	ranges []AsnRange
}

var asnSnap atomic.Pointer[asnLookupTable]

// LookupASNDetails binary-searches the sorted range table for addr.
func LookupASNDetails(addr netip.Addr) (asn, name, country string) {
	if !addr.IsValid() {
		return "", "", ""
	}

	table := asnSnap.Load()
	if table == nil || len(table.ranges) == 0 {
		return "", "", ""
	}

	ranges := table.ranges
	i, j := 0, len(ranges)

	for i < j {
		h := int(uint(i+j) >> 1)
		if ranges[h].Start.Compare(addr) <= 0 {
			i = h + 1
		} else {
			j = h
		}
	}

	if i > 0 {
		r := ranges[i-1]
		if r.End.Compare(addr) >= 0 {
			return r.ASN, r.Name, r.Country
		}
	}
	return "", "", ""
}

var (
	asnHTTPMeta   = make(map[string]catListHeaders)
	asnFileMeta   = make(map[string]int64)
	asnFileRanges = make(map[string][]AsnRange)
	asnMu         sync.Mutex
)

// asnBinPath returns the compiled cache path for a source. Remote and local
// sources use distinct prefixes so a URL and a file path can never collide.
func asnBinPath(src string) string {
	if cfg.Identity.ASNCacheDir == "" {
		return ""
	}
	h := sha256.Sum256([]byte(src))
	prefix := "local-asn-"
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		prefix = "asn-"
	}
	return filepath.Join(cfg.Identity.ASNCacheDir, prefix+hex.EncodeToString(h[:8])+".bin")
}

// asnRawPath returns the raw payload cache path for a remote source.
func asnRawPath(src string) string {
	if cfg.Identity.ASNCacheDir == "" {
		return ""
	}
	h := sha256.Sum256([]byte(src))
	return filepath.Join(cfg.Identity.ASNCacheDir, "asn-"+hex.EncodeToString(h[:8])+".raw")
}

func loadASNMeta() map[string]catListHeaders {
	meta := make(map[string]catListHeaders)
	if cfg.Identity.ASNCacheDir != "" {
		if b, err := os.ReadFile(filepath.Join(cfg.Identity.ASNCacheDir, "asn-meta.json")); err == nil {
			json.Unmarshal(b, &meta)
		}
	}
	// Guard against a null JSON payload unmarshalling into a nil map.
	if meta == nil {
		meta = make(map[string]catListHeaders)
	}
	return meta
}

func saveASNMeta(meta map[string]catListHeaders) {
	if cfg.Identity.ASNCacheDir == "" {
		return
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return
	}
	path := filepath.Join(cfg.Identity.ASNCacheDir, "asn-meta.json")
	if err := atomicWrite(path, b, 0644); err != nil && logIdentity {
		log.Printf("[IDENTITY-ASN] WARNING: failed to persist meta file: %v", err)
	}
}

func InitASN() {
	if len(cfg.Identity.IPInfoASN) == 0 {
		return
	}
	if logIdentity {
		log.Printf("[IDENTITY-ASN] Initialising ASN databases from %d source(s)", len(cfg.Identity.IPInfoASN))
	}

	if cfg.Server.FastStart || cfg.Identity.ASNFastStart {
		if logIdentity {
			log.Printf("[IDENTITY-ASN] Fast start enabled. ASN databases will load in the background.")
		}
		go pollASN(forceRefreshStartup)
	} else {
		pollASN(forceRefreshStartup)
	}

	pollStr := cfg.Identity.ASNPollInterval
	if pollStr == "" {
		pollStr = "6h"
	}

	if pollStr != "0s" && pollStr != "0" {
		if interval, err := time.ParseDuration(pollStr); err == nil && interval > 0 {
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						pollASN(false)
					case <-shutdownCh:
						return
					}
				}
			}()
		} else if logIdentity {
			log.Printf("[IDENTITY-ASN] Invalid asn_poll_interval %q: %v", pollStr, err)
		}
	}
}

func pollASN(force bool) {
	asnMu.Lock()
	defer asnMu.Unlock()

	changed := false
	activeSources := make(map[string]bool)

	isStartup := asnSnap.Load() == nil || len(asnSnap.Load().ranges) == 0

	if force {
		if logIdentity {
			log.Printf("[IDENTITY-ASN] Force-refresh enabled. Bypassing metadata caches.")
		}
		asnHTTPMeta = make(map[string]catListHeaders)
	} else if len(asnHTTPMeta) == 0 && cfg.Identity.ASNCacheDir != "" {
		asnHTTPMeta = loadASNMeta()
	}

	// loadBin restores a source from its compiled cache. Marks the poll as
	// changed so the merged table is rebuilt at the end.
	loadBin := func(src, reason string) bool {
		binPath := asnBinPath(src)
		if binPath == "" {
			return false
		}
		parsed, ok := loadASNBinCache(binPath)
		if !ok {
			return false
		}
		asnFileRanges[src] = parsed
		changed = true
		if logIdentity {
			log.Printf("[IDENTITY-ASN] %s — loaded BINARY cache (%s) for %s", reason, filepath.Base(binPath), src)
		}
		return true
	}

	// restore tries the binary cache, then the raw cache. Returns handled=true
	// when the binary cache satisfied the request and no parsing is needed.
	restore := func(src, reason string) (reader io.ReadCloser, handled bool) {
		if loadBin(src, reason) {
			return nil, true
		}
		cachePath := asnRawPath(src)
		if cachePath == "" {
			return nil, false
		}
		f, err := os.Open(cachePath)
		if err != nil {
			return nil, false
		}
		changed = true
		if logIdentity {
			log.Printf("[IDENTITY-ASN] %s — falling back to raw local cache (%s) for %s", reason, filepath.Base(cachePath), src)
		}
		return f, false
	}

	// [PERF] Cold-boot fast path: if every source has a valid compiled cache,
	// load them and return without touching the network at all. This removes
	// 10-30s of synchronous HTTP timeouts on routers with a dead WAN.
	if isStartup && !force && cfg.Identity.ASNCacheDir != "" && len(cfg.Identity.IPInfoASN) > 0 {
		allLoaded := true
		for _, src := range cfg.Identity.IPInfoASN {
			binPath := asnBinPath(src)
			parsed, ok := loadASNBinCache(binPath)
			if !ok {
				allLoaded = false
				continue
			}
			asnFileRanges[src] = parsed
			activeSources[src] = true
		}

		if allLoaded {
			rebuildASNTable()
			return
		}
	}

	nowUnix := time.Now().Unix()

	for _, src := range cfg.Identity.IPInfoASN {
		activeSources[src] = true
		var reader io.ReadCloser

		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			cachePath := asnRawPath(src)
			hasCacheFile := false
			if cachePath != "" {
				os.MkdirAll(cfg.Identity.ASNCacheDir, 0755)
				if _, err := os.Stat(cachePath); err == nil {
					hasCacheFile = true
				}
			}

			var m catListHeaders
			var hasMeta bool
			if !force {
				m, hasMeta = asnHTTPMeta[src]
			}

			// [PERF] Freshness gate: skip the HTTP round-trip entirely when the
			// cache was validated inside the TTL window.
			if !force && hasCacheFile && hasMeta && (nowUnix-m.LastFetch) < asnFreshnessTTL {
				if len(asnFileRanges[src]) == 0 {
					r, handled := restore(src, "Fresh in cache (<3h)")
					if handled {
						continue
					}
					reader = r
				} else if logIdentity {
					log.Printf("[IDENTITY-ASN] Fresh in cache (<3h) — %s already loaded in memory", src)
				}

				if reader == nil {
					continue
				}
			} else {
				if logIdentity {
					log.Printf("[IDENTITY-ASN] Checking/Fetching remote ASN database: %s", src)
				}

				req, err := http.NewRequest(http.MethodGet, src, nil)
				if err != nil {
					if logIdentity {
						log.Printf("[IDENTITY-ASN] Bad URL %s: %v", src, err)
					}
					continue
				}

				if !force && hasCacheFile && hasMeta {
					if m.LastModified != "" {
						req.Header.Set("If-Modified-Since", m.LastModified)
					}
					if m.ETag != "" {
						req.Header.Set("If-None-Match", m.ETag)
					}
				}

				resp, err := catHTTPClient.Do(req)
				switch {
				case err != nil:
					if len(asnFileRanges[src]) == 0 && hasCacheFile {
						r, handled := restore(src, fmt.Sprintf("Fetch failed for %s: %v", src, err))
						if handled {
							continue
						}
						reader = r
					} else if logIdentity {
						log.Printf("[IDENTITY-ASN] Fetch failed for %s: %v", src, err)
					}

				case resp.StatusCode == http.StatusNotModified:
					resp.Body.Close()
					// Refresh the TTL so the next poll can short-circuit.
					m.LastFetch = nowUnix
					asnHTTPMeta[src] = m

					if len(asnFileRanges[src]) == 0 && hasCacheFile {
						r, handled := restore(src, "Not modified (304)")
						if handled {
							continue
						}
						reader = r
					} else {
						continue
					}

				case resp.StatusCode == http.StatusOK:
					asnHTTPMeta[src] = catListHeaders{
						LastModified: resp.Header.Get("Last-Modified"),
						ETag:         resp.Header.Get("ETag"),
						LastFetch:    nowUnix,
					}

					if cachePath != "" {
						err := saveASNRawCache(cachePath, resp.Body)
						resp.Body.Close()
						if err != nil {
							if logIdentity {
								log.Printf("[IDENTITY-ASN] Error saving payload for %s: %v", src, err)
							}
							continue
						}
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Saved remote database to local cache (%s) for %s", filepath.Base(cachePath), src)
						}
						if f, openErr := os.Open(cachePath); openErr == nil {
							reader = f
						} else if logIdentity {
							log.Printf("[IDENTITY-ASN] Error reopening cache file %s: %v", cachePath, openErr)
						}
					} else {
						reader = resp.Body
					}

					if reader != nil {
						changed = true
					}

				default:
					status := resp.StatusCode
					resp.Body.Close()
					if len(asnFileRanges[src]) == 0 && hasCacheFile {
						r, handled := restore(src, fmt.Sprintf("Failed to fetch. HTTP %d", status))
						if handled {
							continue
						}
						reader = r
					} else if logIdentity {
						log.Printf("[IDENTITY-ASN] Failed to fetch. HTTP %d for %s", status, src)
					}
				}
			}
		} else {
			if logIdentity {
				log.Printf("[IDENTITY-ASN] Checking local ASN database: %s", src)
			}

			info, err := os.Stat(src)
			if err != nil {
				if _, exists := asnFileMeta[src]; exists {
					delete(asnFileMeta, src)
					delete(asnFileRanges, src)
					changed = true
					if logIdentity {
						log.Printf("[IDENTITY-ASN] Local file %s was removed. Flagging routing arrays for rebuild.", src)
					}
				}
				if logIdentity {
					log.Printf("[IDENTITY-ASN] Cannot stat %s: %v", src, err)
				}
				continue
			}

			mtime := info.ModTime().UnixNano()
			if lastMtime, ok := asnFileMeta[src]; ok && lastMtime == mtime && !force {
				if len(asnFileRanges[src]) > 0 {
					continue
				}
				if loadBin(src, "Unchanged local file") {
					continue
				}
			}

			f, err := os.Open(src)
			if err != nil {
				if logIdentity {
					log.Printf("[IDENTITY-ASN] Cannot open %s: %v", src, err)
				}
				continue
			}
			asnFileMeta[src] = mtime
			reader = f
			changed = true
		}

		if reader != nil {
			parseAndCompile(src, reader)
		}
	}

	// Garbage-collect sources removed from the config.
	for src := range asnFileRanges {
		if !activeSources[src] {
			delete(asnFileRanges, src)
			changed = true
			if logIdentity {
				log.Printf("[IDENTITY-ASN] Garbage collected removed database source: %s", src)
			}
		}
	}
	for src := range asnFileMeta {
		if !activeSources[src] {
			delete(asnFileMeta, src)
		}
	}
	for src := range asnHTTPMeta {
		if !activeSources[src] {
			delete(asnHTTPMeta, src)
		}
	}

	if !changed {
		return
	}

	saveASNMeta(asnHTTPMeta)
	rebuildASNTable()
}

// saveASNRawCache streams an HTTP body to the raw cache with a hard size cap.
// [SECURITY] CWE-400: reads one byte past the limit so truncation is detected
// rather than silently persisting a partial database.
func saveASNRawCache(path string, body io.Reader) error {
	return atomicWriteBuf(path, 0644, func(bw *bufio.Writer) error {
		lr := io.LimitReader(body, asnMaxRawBytes+1)
		n, err := io.Copy(bw, lr)
		if err != nil {
			return err
		}
		if n > asnMaxRawBytes {
			return fmt.Errorf("payload exceeded %dMB safety limit", asnMaxRawBytes/(1024*1024))
		}
		return nil
	})
}

// parseAndCompile decodes a raw (optionally gzipped) payload, stores the parsed
// ranges in memory, and writes the compiled binary cache for the next boot.
func parseAndCompile(src string, reader io.ReadCloser) {
	defer reader.Close()

	header := make([]byte, 2)
	n, _ := io.ReadFull(reader, header)
	var decodeReader io.Reader

	if n == 2 && header[0] == 0x1f && header[1] == 0x8b {
		mr := io.MultiReader(bytes.NewReader(header[:n]), reader)
		gzr, err := gzip.NewReader(mr)
		if err != nil {
			if logIdentity {
				log.Printf("[IDENTITY-ASN] Gzip initialization error for %s: %v", src, err)
			}
			return
		}
		defer gzr.Close()
		// [SECURITY] Gzip-bomb guard.
		decodeReader = io.LimitReader(gzr, asnMaxDecompressedBytes)
	} else {
		decodeReader = io.MultiReader(bytes.NewReader(header[:n]), reader)
	}

	parsed := parseASNStream(decodeReader)
	asnFileRanges[src] = parsed
	if logIdentity {
		log.Printf("[IDENTITY-ASN] Parsed and loaded %d IP/ASN boundaries from: %s", len(parsed), src)
	}

	if binPath := asnBinPath(src); binPath != "" {
		if err := saveASNBinCache(binPath, parsed); err != nil && logIdentity {
			log.Printf("[IDENTITY-ASN] WARNING: failed to write binary cache: %v", err)
		}
	}
}

// rebuildASNTable merges every source's ranges, sorts by start address, and
// atomically publishes the new lookup table.
func rebuildASNTable() {
	var allRanges []AsnRange
	for _, r := range asnFileRanges {
		allRanges = append(allRanges, r...)
	}

	if len(allRanges) > 0 {
		sort.Slice(allRanges, func(i, j int) bool {
			return allRanges[i].Start.Compare(allRanges[j].Start) < 0
		})
		asnSnap.Store(&asnLookupTable{ranges: allRanges})
		if logIdentity {
			log.Printf("[IDENTITY-ASN] Rebuilt routing arrays. Loaded %d IP/ASN boundaries globally.", len(allRanges))
		}
	} else {
		asnSnap.Store(&asnLookupTable{ranges: nil})
		if logIdentity {
			log.Printf("[IDENTITY-ASN] Rebuilt routing arrays. No IP/ASN boundaries active.")
		}
	}
}

// fastExtractJSONStr pulls a string value out of a flat JSON line without
// reflection or map allocation.
//
// [PERF] json.Unmarshal on a multi-million-line database produces enough garbage
// to stall a constrained router. This walks bytes instead.
func fastExtractJSONStr(line []byte, key []byte) string {
	idx := bytes.Index(line, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)

	for start < len(line) && line[start] != ':' {
		start++
	}
	if start >= len(line) {
		return ""
	}
	start++

	for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
		start++
	}

	if start >= len(line) || line[start] != '"' {
		return ""
	}
	start++

	// Walk to the closing quote, skipping escaped quotes so a value containing
	// \" isn't truncated mid-string.
	end := 0
	for {
		i := bytes.IndexByte(line[start+end:], '"')
		if i < 0 {
			return ""
		}
		end += i

		bsCount := 0
		for j := start + end - 1; j >= start && line[j] == '\\'; j-- {
			bsCount++
		}
		if bsCount%2 != 0 {
			end++
			continue
		}
		break
	}

	return string(line[start : start+end])
}

// Precompiled keys for zero-allocation extraction.
var (
	keyStartIP     = []byte(`"start_ip"`)
	keyEndIP       = []byte(`"end_ip"`)
	keyNetwork     = []byte(`"network"`)
	keyASN         = []byte(`"asn"`)
	keyASName      = []byte(`"as_name"`)
	keyName        = []byte(`"name"`)
	keyCountryCode = []byte(`"country_code"`)
	keyCountry     = []byte(`"country"`)
)

func parseASNStream(r io.Reader) []AsnRange {
	var ranges []AsnRange
	scanner := bufio.NewScanner(r)

	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	linesProcessed := 0

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '[' || line[0] == ']' {
			continue
		}

		network := fastExtractJSONStr(line, keyNetwork)
		startIPStr := fastExtractJSONStr(line, keyStartIP)
		endIPStr := fastExtractJSONStr(line, keyEndIP)
		asn := fastExtractJSONStr(line, keyASN)
		asName := fastExtractJSONStr(line, keyASName)
		name := fastExtractJSONStr(line, keyName)
		countryCode := fastExtractJSONStr(line, keyCountryCode)
		country := fastExtractJSONStr(line, keyCountry)

		var start, end netip.Addr
		var err1, err2 error

		if network != "" {
			// [SECURITY] ParsePrefixUnmapped keeps IPv4-in-IPv6 parsing identical
			// to the rest of the pipeline.
			if prefix, err := ParsePrefixUnmapped(network); err == nil {
				start = prefix.Masked().Addr()
				end = lastAddr(prefix)
			} else {
				err1 = err
			}
		} else {
			start, err1 = netip.ParseAddr(startIPStr)
			end, err2 = netip.ParseAddr(endIPStr)
		}

		if err1 == nil && err2 == nil && asn != "" {
			// [SECURITY] Unmap before the version filter so an IPv4-in-IPv6 entry
			// can't slip past an ipv4-only configuration.
			start = start.Unmap()
			end = end.Unmap()

			if ipVersionSupport != "both" {
				if ipVersionSupport == "ipv4" && !start.Is4() {
					continue
				}
				if ipVersionSupport == "ipv6" && !start.Is6() {
					continue
				}
			}

			asnStr := strings.ToUpper(asn)
			if !strings.HasPrefix(asnStr, "AS") {
				asnStr = "AS" + asnStr
			}

			ownerName := asName
			if ownerName == "" {
				ownerName = name
			}

			cCode := countryCode
			if cCode == "" {
				cCode = country
			}

			ranges = append(ranges, AsnRange{
				Start:   start,
				End:     end,
				ASN:     asnStr,
				Name:    ownerName,
				Country: cCode,
			})
		}

		linesProcessed++
		// [PERF] Yield every 10k lines so a multi-million-line unpack doesn't
		// freeze the DNS listeners on a single-core router.
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	if err := scanner.Err(); err != nil && logIdentity {
		log.Printf("[IDENTITY-ASN] WARNING: Partial scanner error during ASN parsing: %v", err)
	}

	return ranges
}

// lastAddr returns the broadcast/highest address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()

	if addr.Is4() {
		b := addr.As4()
		var mask uint32
		if p.Bits() < 32 {
			mask = uint32(0xffffffff) >> p.Bits()
		}
		ip := binary.BigEndian.Uint32(b[:]) | mask
		binary.BigEndian.PutUint32(b[:], ip)
		return netip.AddrFrom4(b)
	}

	b := addr.As16()
	rem := 128 - p.Bits()
	for i := 15; i >= 0 && rem > 0; i-- {
		if rem >= 8 {
			b[i] = 0xff
			rem -= 8
		} else {
			b[i] |= byte((1 << rem) - 1)
			rem = 0
		}
	}
	return netip.AddrFrom16(b)
}

