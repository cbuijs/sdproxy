/*
File:    identity_asn.go
Version: 2.3.0
Last Updated: 04-Nov-2026 19:22 CET

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
  2.3.0  - [FIX] Enabled error, warning, and security constraint logs in `InitASN`,
           `pollASN`, `saveASNMeta`, `parseAndCompile`, and `parseASNStream` when
           `logSystem` or `logIdentity` is active, so Simple Logging Mode (`logSimple: true`)
           always surfaces errors/warnings while keeping routine polling silent.
  2.2.0  - [SECURITY/FIX] Saved `asn-meta.json` even when remote ASN databases return
           `304 Not Modified` so the refreshed `LastFetch` timestamp is persisted to
           disk instead of expiring repeatedly across restarts.
         - [SECURITY/FIX] Validated that local ASN files have not been modified
           (`FileMeta`) before taking the cold-boot binary cache fast-path in `pollASN`.
  2.1.0  - [SECURITY/FIX] Added missing `User-Agent` header (`cfg.Server.UserAgent`)
           to outbound ASN database HTTP requests in `pollASN` so WAF-protected
           endpoints (Cloudflare/IPinfo) do not block default Go-http-client requests.
         - [SECURITY/FIX] Upgraded gzip bomb protection in `parseAndCompile` to read
           `asnMaxDecompressedBytes + 1` and abort on overflow instead of silently
           truncating the ASN routing table mid-stream.
  2.0.0  - [TIER 2] The six copy-pasted gob-load blocks collapsed into
           loadASNBinCache (helpers_io.go) behind two local closures.
  1.38.0 - [SECURITY/RELIABILITY] Directory fsync on cache renames.
  1.37.0 - [SECURITY/FIX] Corrected []AsnRange vs []AsnRangeGob assertion.
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
	asnMaxRawBytes          = 256 * 1024 * 1024
	asnMaxDecompressedBytes = 2048 * 1024 * 1024
	asnFreshnessTTL         = 3 * 3600
)

type AsnRange struct {
	Start   netip.Addr
	End     netip.Addr
	ASN     string
	Name    string
	Country string
}

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
	if err := atomicWrite(path, b, 0644); err != nil && (logIdentity || logSystem) {
		log.Printf("[IDENTITY-ASN] WARNING: failed to persist meta file: %v", err)
	}
}

func InitASN() {
	if len(cfg.Identity.IPInfoASN) == 0 {
		return
	}
	if logIdentity || logSystem {
		log.Printf("[IDENTITY-ASN] Initialising ASN databases from %d source(s)", len(cfg.Identity.IPInfoASN))
	}

	if cfg.Server.FastStart || cfg.Identity.ASNFastStart {
		if logIdentity || logSystem {
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
		} else if logIdentity || logSystem {
			log.Printf("[IDENTITY-ASN] WARNING: Invalid asn_poll_interval %q: %v", pollStr, err)
		}
	}
}

func pollASN(force bool) {
	asnMu.Lock()
	defer asnMu.Unlock()

	changed := false
	metaDirty := false
	activeSources := make(map[string]bool)

	isStartup := asnSnap.Load() == nil || len(asnSnap.Load().ranges) == 0

	if force {
		if logIdentity {
			log.Printf("[IDENTITY-ASN] Force-refresh enabled. Bypassing metadata caches.")
		}
		asnHTTPMeta = make(map[string]catListHeaders)
		metaDirty = true
	} else if len(asnHTTPMeta) == 0 && cfg.Identity.ASNCacheDir != "" {
		asnHTTPMeta = loadASNMeta()
	}

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

	if isStartup && !force && cfg.Identity.ASNCacheDir != "" && len(cfg.Identity.IPInfoASN) > 0 {
		allLoaded := true
		for _, src := range cfg.Identity.IPInfoASN {
			binPath := asnBinPath(src)
			if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
				srcInfo, err1 := os.Stat(src)
				binInfo, err2 := os.Stat(binPath)
				if err1 != nil || err2 != nil || srcInfo.ModTime().After(binInfo.ModTime()) {
					allLoaded = false
					continue
				}
				asnFileMeta[src] = srcInfo.ModTime().UnixNano()
			}
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
					if logIdentity || logSystem {
						log.Printf("[IDENTITY-ASN] ERROR: Bad URL %s: %v", src, err)
					}
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
				switch {
				case err != nil:
					if len(asnFileRanges[src]) == 0 && hasCacheFile {
						r, handled := restore(src, fmt.Sprintf("Fetch failed for %s: %v", src, err))
						if handled {
							continue
						}
						reader = r
					} else if logIdentity || logSystem {
						log.Printf("[IDENTITY-ASN] WARNING: Fetch failed for %s: %v", src, err)
					}

				case resp.StatusCode == http.StatusNotModified:
					resp.Body.Close()
					m.LastFetch = nowUnix
					asnHTTPMeta[src] = m
					metaDirty = true

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
					metaDirty = true

					if cachePath != "" {
						err := saveASNRawCache(cachePath, resp.Body)
						resp.Body.Close()
						if err != nil {
							if logIdentity || logSystem {
								log.Printf("[IDENTITY-ASN] ERROR: saving payload for %s: %v", src, err)
							}
							continue
						}
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Saved remote database to local cache (%s) for %s", filepath.Base(cachePath), src)
						}
						if f, openErr := os.Open(cachePath); openErr == nil {
							reader = f
						} else if logIdentity || logSystem {
							log.Printf("[IDENTITY-ASN] ERROR: reopening cache file %s: %v", cachePath, openErr)
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
					} else if logIdentity || logSystem {
						log.Printf("[IDENTITY-ASN] WARNING: Failed to fetch. HTTP %d for %s", status, src)
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
				if logIdentity || logSystem {
					log.Printf("[IDENTITY-ASN] WARNING: Cannot stat %s: %v", src, err)
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
				if logIdentity || logSystem {
					log.Printf("[IDENTITY-ASN] WARNING: Cannot open %s: %v", src, err)
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
			metaDirty = true
		}
	}

	if metaDirty || changed {
		saveASNMeta(asnHTTPMeta)
	}

	if !changed {
		return
	}

	rebuildASNTable()
}

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

func parseAndCompile(src string, reader io.ReadCloser) {
	defer reader.Close()

	header := make([]byte, 2)
	n, _ := io.ReadFull(reader, header)
	var lr *io.LimitedReader

	if n == 2 && header[0] == 0x1f && header[1] == 0x8b {
		mr := io.MultiReader(bytes.NewReader(header[:n]), reader)
		gzr, err := gzip.NewReader(mr)
		if err != nil {
			if logIdentity || logSystem {
				log.Printf("[IDENTITY-ASN] ERROR: Gzip initialization error for %s: %v", src, err)
			}
			return
		}
		defer gzr.Close()
		lr = io.LimitReader(gzr, asnMaxDecompressedBytes+1).(*io.LimitedReader)
	} else {
		mr := io.MultiReader(bytes.NewReader(header[:n]), reader)
		lr = io.LimitReader(mr, asnMaxDecompressedBytes+1).(*io.LimitedReader)
	}

	parsed := parseASNStream(lr)
	if lr.N == 0 {
		if logIdentity || logSystem {
			log.Printf("[IDENTITY-ASN] SECURITY: Decompressed ASN payload exceeded %dMB limit for %s — aborting update to prevent truncated routing tables.",
				asnMaxDecompressedBytes/(1024*1024), src)
		}
		return
	}

	asnFileRanges[src] = parsed
	if logIdentity {
		log.Printf("[IDENTITY-ASN] Parsed and loaded %d IP/ASN boundaries from: %s", len(parsed), src)
	}

	if binPath := asnBinPath(src); binPath != "" {
		if err := saveASNBinCache(binPath, parsed); err != nil && (logIdentity || logSystem) {
			log.Printf("[IDENTITY-ASN] WARNING: failed to write binary cache: %v", err)
		}
	}
}

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
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}

	if err := scanner.Err(); err != nil && (logIdentity || logSystem) {
		log.Printf("[IDENTITY-ASN] WARNING: Partial scanner error during ASN parsing: %v", err)
	}

	return ranges
}

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
