/*
File:    identity_asn.go
Version: 1.22.0
Updated: 07-May-2026 12:48 CEST

Description: 
  Autonomous System Number (ASN) Identity Resolution and Database fetching.
  Retrieves and parses remote/local IPinfo JSON/GZ databases natively.

Changes:
  1.22.0 - [SECURITY] Mitigated GZIP decompression bombs by wrapping the internal 
           decompressed data stream within a strict 500MB `io.LimitReader`. Neutralizes 
           catastrophic memory exhaustion (OOM) attacks from weaponized upstream databases.
  1.21.0 - [SECURITY/FIX] Fortified `io.LimitReader` implementation. Evaluates the `Limit + 1` 
           boundary natively to accurately detect upstream truncation. Prevents incomplete 
           or malicious payloads exceeding the 100MB safety limit from circumventing errors 
           and persisting to the local disk caches.
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

type asnRange struct {
	start   netip.Addr
	end     netip.Addr
	asn     string
	name    string
	country string
}

type asnLookupTable struct {
	ranges []asnRange
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
		if ranges[h].start.Compare(addr) <= 0 {
			i = h + 1
		} else {
			j = h
		}
	}

	if i > 0 {
		r := ranges[i-1]
		if r.end.Compare(addr) >= 0 {
			return r.asn, r.name, r.country
		}
	}
	return "", "", ""
}

var (
	asnHTTPMeta   = make(map[string]catListHeaders)
	asnFileMeta   = make(map[string]int64)
	asnFileRanges = make(map[string][]asnRange) 
	asnMu         sync.Mutex
)

func loadASNMeta() map[string]catListHeaders {
	meta := make(map[string]catListHeaders)
	if cfg.Identity.ASNCacheDir == "" {
		return meta
	}
	b, err := os.ReadFile(filepath.Join(cfg.Identity.ASNCacheDir, "asn-meta.json"))
	if err == nil {
		json.Unmarshal(b, &meta)
	}
	return meta
}

func saveASNMeta(meta map[string]catListHeaders) {
	if cfg.Identity.ASNCacheDir == "" {
		return
	}
	os.MkdirAll(cfg.Identity.ASNCacheDir, 0755)
	b, err := json.Marshal(meta)
	if err == nil {
		path := filepath.Join(cfg.Identity.ASNCacheDir, "asn-meta.json")
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0644) == nil {
			os.Rename(tmp, path)
		}
	}
}

func InitASN() {
	if len(cfg.Identity.IPInfoASN) == 0 {
		return
	}
	log.Printf("[IDENTITY-ASN] Initialising ASN databases from %d source(s)", len(cfg.Identity.IPInfoASN))

	if cfg.Identity.ASNFastStart {
		log.Printf("[IDENTITY-ASN] Fast start enabled. ASN databases will load in the background.")
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
				for range ticker.C {
					pollASN(false) 
				}
			}()
		} else {
			log.Printf("[IDENTITY-ASN] Invalid asn_poll_interval %q: %v", pollStr, err)
		}
	}
}

func pollASN(force bool) {
	asnMu.Lock()
	defer asnMu.Unlock()

	changed := false
	activeSources := make(map[string]bool)

	if force {
		log.Printf("[IDENTITY-ASN] Force-refresh enabled. Bypassing metadata caches.")
		asnHTTPMeta = make(map[string]catListHeaders)
	} else if len(asnHTTPMeta) == 0 && cfg.Identity.ASNCacheDir != "" {
		asnHTTPMeta = loadASNMeta()
	}

	for _, src := range cfg.Identity.IPInfoASN {
		activeSources[src] = true
		var reader io.ReadCloser

		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			log.Printf("[IDENTITY-ASN] Checking/Fetching remote ASN database: %s", src)
			
			req, err := http.NewRequest(http.MethodGet, src, nil)
			if err != nil {
				log.Printf("[IDENTITY-ASN] Bad URL %s: %v", src, err)
				continue
			}

			var cachePath string
			hasCacheFile := false
			if cfg.Identity.ASNCacheDir != "" {
				os.MkdirAll(cfg.Identity.ASNCacheDir, 0755)
				h := sha256.Sum256([]byte(src))
				cachePath = filepath.Join(cfg.Identity.ASNCacheDir, "asn-"+hex.EncodeToString(h[:8])+".raw")
				if _, err := os.Stat(cachePath); err == nil {
					hasCacheFile = true
				}
			}

			if !force {
				if m, ok := asnHTTPMeta[src]; ok && hasCacheFile {
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
				if len(asnFileRanges[src]) == 0 && hasCacheFile {
					reader, _ = os.Open(cachePath)
					changed = true
					log.Printf("[IDENTITY-ASN] Fetch failed for %s: %v — falling back to local cache (%s)", src, err, filepath.Base(cachePath))
				} else {
					log.Printf("[IDENTITY-ASN] Fetch failed for %s: %v", src, err)
				}
			} else if resp.StatusCode == http.StatusNotModified {
				resp.Body.Close()
				if len(asnFileRanges[src]) == 0 && hasCacheFile {
					reader, _ = os.Open(cachePath)
					changed = true
					log.Printf("[IDENTITY-ASN] Not modified (304), loading local cache (%s) for %s", filepath.Base(cachePath), src)
				} else {
					continue
				}
			} else if resp.StatusCode == http.StatusOK {
				asnHTTPMeta[src] = catListHeaders{
					LastModified: resp.Header.Get("Last-Modified"),
					ETag:         resp.Header.Get("ETag"),
				}
				
				if cachePath != "" {
					f, err := os.Create(cachePath + ".tmp")
					if err == nil {
						// [SECURITY/FIX] CWE-400 Uncontrolled Resource Consumption Protection
						// Read precisely 1 byte beyond the maximum capacity limit to actively detect 
						// upstream truncation and reject the transaction natively.
						limitReader := io.LimitReader(resp.Body, 100*1024*1024 + 1)
						written, copyErr := io.Copy(f, limitReader)
						f.Close()
						
						if copyErr == nil {
							// Successfully evaluated the threshold bounds without truncation bypasses
							if written > 100*1024*1024 {
								os.Remove(cachePath + ".tmp")
								log.Printf("[IDENTITY-ASN] Error: payload exceeded 100MB safety limit for %s", src)
								resp.Body.Close()
								continue
							}
							os.Rename(cachePath+".tmp", cachePath)
							log.Printf("[IDENTITY-ASN] Saved remote database to local cache (%s) for %s", filepath.Base(cachePath), src)
							resp.Body.Close()
							
							var openErr error
							reader, openErr = os.Open(cachePath)
							if openErr != nil {
								log.Printf("[IDENTITY-ASN] Error reopening cache file %s: %v", cachePath, openErr)
							}
						} else {
							log.Printf("[IDENTITY-ASN] Error: Could not copy payload to disk safely for %s: %v", src, copyErr)
							resp.Body.Close()
						}
					} else {
						log.Printf("[IDENTITY-ASN] Warning: could not create cache file %s: %v. Parsing directly from memory.", cachePath+".tmp", err)
						reader = resp.Body 
					}
				} else {
					reader = resp.Body
				}
				
				if reader != nil {
					changed = true
				}
			} else {
				resp.Body.Close()
				if len(asnFileRanges[src]) == 0 && hasCacheFile {
					reader, _ = os.Open(cachePath)
					changed = true
					log.Printf("[IDENTITY-ASN] Failed to fetch. HTTP %d for %s — falling back to local cache (%s)", resp.StatusCode, src, filepath.Base(cachePath))
				} else {
					log.Printf("[IDENTITY-ASN] Failed to fetch. HTTP %d for %s", resp.StatusCode, src)
				}
			}
		} else {
			log.Printf("[IDENTITY-ASN] Checking local ASN database: %s", src)
			
			info, err := os.Stat(src)
			if err != nil {
				log.Printf("[IDENTITY-ASN] Cannot stat %s: %v", src, err)
				continue
			}
			mtime := info.ModTime().UnixNano()
			if lastMtime, ok := asnFileMeta[src]; ok && lastMtime == mtime && !force {
				if len(asnFileRanges[src]) > 0 {
					continue 
				}
			}

			f, err := os.Open(src)
			if err != nil {
				log.Printf("[IDENTITY-ASN] Cannot open %s: %v", src, err)
				continue
			}
			asnFileMeta[src] = mtime
			reader = f
			changed = true
		}

		if reader != nil {
			func() {
				defer reader.Close()
				
				header := make([]byte, 2)
				n, _ := io.ReadFull(reader, header)
				var decodeReader io.Reader

				if n == 2 && header[0] == 0x1f && header[1] == 0x8b {
					mr := io.MultiReader(bytes.NewReader(header[:n]), reader)
					gzr, err := gzip.NewReader(mr)
					if err != nil {
						log.Printf("[IDENTITY-ASN] Gzip initialization error for %s: %v", src, err)
						return
					}
					defer gzr.Close()
					// [SECURITY/FIX] GZIP Bomb Protection. Cap decompressed ASN databases 
					// to 500MB natively to prevent catastrophic memory exhaustion attacks.
					decodeReader = io.LimitReader(gzr, 500*1024*1024)
				} else {
					decodeReader = io.MultiReader(bytes.NewReader(header[:n]), reader)
				}

				parsed := parseASNStream(decodeReader)
				asnFileRanges[src] = parsed
				log.Printf("[IDENTITY-ASN] Parsed and loaded %d IP/ASN boundaries from: %s", len(parsed), src)
			}()
		}
	}

	for src := range asnFileRanges {
		if !activeSources[src] {
			delete(asnFileRanges, src)
			changed = true
			log.Printf("[IDENTITY-ASN] Garbage collected removed database source: %s", src)
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

	var allRanges []asnRange
	for _, r := range asnFileRanges {
		allRanges = append(allRanges, r...)
	}

	if len(allRanges) > 0 {
		sort.Slice(allRanges, func(i, j int) bool {
			return allRanges[i].start.Compare(allRanges[j].start) < 0
		})

		asnSnap.Store(&asnLookupTable{ranges: allRanges})
		log.Printf("[IDENTITY-ASN] Rebuilt routing arrays. Loaded %d IP/ASN boundaries globally.", len(allRanges))
	} else {
		asnSnap.Store(&asnLookupTable{ranges: nil})
		log.Printf("[IDENTITY-ASN] Rebuilt routing arrays. No IP/ASN boundaries active.")
	}
}

type ipinfoRow struct {
	StartIP     string `json:"start_ip,omitempty"`
	EndIP       string `json:"end_ip,omitempty"`
	Name        string `json:"name,omitempty"`
	Country     string `json:"country,omitempty"`

	Network     string `json:"network,omitempty"`
	ASName      string `json:"as_name,omitempty"`
	CountryCode string `json:"country_code,omitempty"`

	ASN         string `json:"asn"`
}

func parseASNStream(r io.Reader) []asnRange {
	var ranges []asnRange
	scanner := bufio.NewScanner(r)

	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '[' || line[0] == ']' {
			continue 
		}
		if line[len(line)-1] == ',' {
			line = line[:len(line)-1]
		}

		var row ipinfoRow
		if err := json.Unmarshal(line, &row); err == nil {
			var start, end netip.Addr
			var err1, err2 error

			if row.Network != "" {
				if prefix, err := netip.ParsePrefix(row.Network); err == nil {
					start = prefix.Masked().Addr()
					end = lastAddr(prefix)
				} else {
					err1 = err 
				}
			} else {
				start, err1 = netip.ParseAddr(row.StartIP)
				end, err2 = netip.ParseAddr(row.EndIP)
			}

			if err1 == nil && err2 == nil && row.ASN != "" {
				if ipVersionSupport != "both" {
					if ipVersionSupport == "ipv4" && !start.Is4() {
						continue
					}
					if ipVersionSupport == "ipv6" && !start.Is6() {
						continue
					}
				}

				asn := strings.ToUpper(row.ASN)
				if !strings.HasPrefix(asn, "AS") {
					asn = "AS" + asn
				}

				ownerName := row.ASName
				if ownerName == "" {
					ownerName = row.Name
				}
				
				countryCode := row.CountryCode
				if countryCode == "" {
					countryCode = row.Country
				}

				ranges = append(ranges, asnRange{
					start:   start.Unmap(),
					end:     end.Unmap(),
					asn:     asn,
					name:    ownerName,
					country: countryCode,
				})
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		log.Printf("[IDENTITY-ASN] WARNING: Partial scanner error during ASN parsing: %v", err)
	}
	
	return ranges
}

func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	
	if addr.Is4() {
		b := addr.As4()
		mask := uint32(0xffffffff) >> p.Bits()
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

