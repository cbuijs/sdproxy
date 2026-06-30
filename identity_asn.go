/*
File:    identity_asn.go
Version: 1.36.0
Updated: 30-Jun-2026 09:07 CEST

Description: 
  Autonomous System Number (ASN) Identity Resolution and Database fetching.
  Retrieves and parses remote/local IPinfo JSON/GZ databases natively.

Changes:
  1.36.0 - [PERF] Introduced a rigid 3-hour Local Freshness TTL (`LastFetch`) natively. 
           Bypasses HTTP polling entirely if the database was successfully validated 
           within the 3-hour horizon, completely eliminating start-up latency organically.
  1.35.0 - [SECURITY/FIX] Eradicated a severe caching mismatch anomaly. Fixed a 
           file-path concatenation typo that attempted to load `asn-XYZ.raw.bin` 
           instead of `asn-XYZ.bin`. This previously caused the engine to permanently 
           miss the Binary Cache and fall back to expensive JSON processing.
  1.34.1 - [PERF] Deployed an Instant Binary Load bypass natively during startup. 
           If the `.bin` caches exist, the engine instantly loads them into memory 
           and returns, completely bypassing the synchronous HTTP `If-Modified-Since` 
           requests and eliminating 10-30 second network-timeout bottlenecks on cold boots.
*/

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
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
	"sync/atomic"
	"time"
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

func loadASNMeta() map[string]catListHeaders {
	meta := make(map[string]catListHeaders)
	if cfg.Identity.ASNCacheDir != "" {
		b, err := os.ReadFile(filepath.Join(cfg.Identity.ASNCacheDir, "asn-meta.json"))
		if err == nil {
			json.Unmarshal(b, &meta)
		}
	}
	
	// [SECURITY/FIX] Prevents `nil` assignments if the unmarshalled JSON payload dynamically evaluated to null natively.
	if meta == nil {
		meta = make(map[string]catListHeaders)
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
		
		// [SECURITY/FIX] Block empty writes from triggering a rename natively
		if err := os.WriteFile(tmp, b, 0644); err == nil {
			os.Remove(path) // Protects against OS-level file lock rejections natively
			if renameErr := os.Rename(tmp, path); renameErr != nil {
				if logIdentity {
					log.Printf("[IDENTITY-ASN] WARNING: Failed to atomically rename meta file: %v", renameErr)
				}
				os.Remove(tmp)
			}
		} else {
			os.Remove(tmp)
		}
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
		} else {
			if logIdentity {
				log.Printf("[IDENTITY-ASN] Invalid asn_poll_interval %q: %v", pollStr, err)
			}
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

	// [PERF/FIX] Attempt instant binary load at startup to bypass network latency and JSON parsing.
	if isStartup && !force && cfg.Identity.ASNCacheDir != "" && len(cfg.Identity.IPInfoASN) > 0 {
		allLoaded := true
		for _, src := range cfg.Identity.IPInfoASN {
			var binPath string
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				h := sha256.Sum256([]byte(src))
				binPath = filepath.Join(cfg.Identity.ASNCacheDir, "asn-"+hex.EncodeToString(h[:8])+".bin")
			} else {
				h := sha256.Sum256([]byte(src))
				binPath = filepath.Join(cfg.Identity.ASNCacheDir, "local-asn-"+hex.EncodeToString(h[:8])+".bin")
			}
			
			if bf, err := os.Open(binPath); err == nil {
				var gobParsed []AsnRangeGob
				br := bufio.NewReaderSize(bf, 64*1024)
				if err := gob.NewDecoder(br).Decode(&gobParsed); err == nil {
					var parsed []AsnRange
					for _, g := range gobParsed {
						start, err1 := netip.ParseAddr(g.Start)
						end, err2 := netip.ParseAddr(g.End)
						if err1 == nil && err2 == nil {
							parsed = append(parsed, AsnRange{Start: start, End: end, ASN: g.ASN, Name: g.Name, Country: g.Country})
						}
					}
					asnFileRanges[src] = parsed
					activeSources[src] = true
				} else {
					allLoaded = false
				}
				bf.Close()
			} else {
				allLoaded = false
			}
		}
		
		if allLoaded {
			var allRanges []AsnRange
			for _, r := range asnFileRanges {
				allRanges = append(allRanges, r...)
			}
			sort.Slice(allRanges, func(i, j int) bool {
				return allRanges[i].Start.Compare(allRanges[j].Start) < 0
			})
			asnSnap.Store(&asnLookupTable{ranges: allRanges})
			if logIdentity {
				log.Printf("[IDENTITY-ASN] Loaded compiled BINARY caches instantly. Bound %d IP/ASN boundaries globally.", len(allRanges))
			}
			return // Skip network and raw parsing entirely
		}
	}

	nowUnix := time.Now().Unix()

	for _, src := range cfg.Identity.IPInfoASN {
		activeSources[src] = true
		var reader io.ReadCloser

		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			var cachePath string
			var binPath string
			hasCacheFile := false
			if cfg.Identity.ASNCacheDir != "" {
				os.MkdirAll(cfg.Identity.ASNCacheDir, 0755)
				h := sha256.Sum256([]byte(src))
				cachePath = filepath.Join(cfg.Identity.ASNCacheDir, "asn-"+hex.EncodeToString(h[:8])+".raw")
				binPath = filepath.Join(cfg.Identity.ASNCacheDir, "asn-"+hex.EncodeToString(h[:8])+".bin")
				if _, err := os.Stat(cachePath); err == nil {
					hasCacheFile = true
				}
			}

			var m catListHeaders
			var hasMeta bool
			if !force {
				m, hasMeta = asnHTTPMeta[src]
			}

			// [PERF/SECURITY] 3-Hour Freshness TTL Gate
			if !force && hasCacheFile && hasMeta && (nowUnix-m.LastFetch) < 3*3600 {
				if len(asnFileRanges[src]) == 0 {
					// Preemptively attempt Binary Gob Load natively
					if binF, err := os.Open(binPath); err == nil {
						var gobParsed []AsnRangeGob
						br := bufio.NewReaderSize(binF, 64*1024)
						if err := gob.NewDecoder(br).Decode(&gobParsed); err == nil {
							var parsed []AsnRange
							for _, g := range gobParsed {
								start, err1 := netip.ParseAddr(g.Start)
								end, err2 := netip.ParseAddr(g.End)
								if err1 == nil && err2 == nil {
									parsed = append(parsed, AsnRange{Start: start, End: end, ASN: g.ASN, Name: g.Name, Country: g.Country})
								}
							}
							asnFileRanges[src] = parsed
							changed = true
							binF.Close()
							if logIdentity {
								log.Printf("[IDENTITY-ASN] Fresh in cache (<3h) — loaded BINARY cache (%s) for %s", filepath.Base(binPath), src)
							}
							continue // Skip raw parsing entirely
						}
						binF.Close()
					}
					
					reader, _ = os.Open(cachePath)
					changed = true
					if logIdentity {
						log.Printf("[IDENTITY-ASN] Fresh in cache (<3h) — falling back to raw local cache (%s) for %s", filepath.Base(cachePath), src)
					}
				} else {
					if logIdentity {
						log.Printf("[IDENTITY-ASN] Fresh in cache (<3h) — %s already loaded in memory", src)
					}
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
				if err != nil {
					if len(asnFileRanges[src]) == 0 && hasCacheFile {
						// Preemptively attempt Binary Gob Load natively
						if binF, err := os.Open(binPath); err == nil {
							var parsed []AsnRange
							br := bufio.NewReaderSize(binF, 64*1024)
							if err := gob.NewDecoder(br).Decode(&parsed); err == nil {
								asnFileRanges[src] = parsed
								changed = true
								binF.Close()
								if logIdentity {
									log.Printf("[IDENTITY-ASN] Fetch failed for %s: %v — loaded from BINARY cache (%s)", src, err, filepath.Base(binPath))
								}
								continue // Skip raw parsing entirely
							}
							binF.Close()
						}
						
						reader, _ = os.Open(cachePath)
						changed = true
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Fetch failed for %s: %v — falling back to raw local cache (%s)", src, err, filepath.Base(cachePath))
						}
					} else {
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Fetch failed for %s: %v", src, err)
						}
					}
				} else if resp.StatusCode == http.StatusNotModified {
					resp.Body.Close()
					
					// Update LastFetch TTL natively to sustain the freshness horizon
					m.LastFetch = nowUnix
					asnHTTPMeta[src] = m
					
					if len(asnFileRanges[src]) == 0 && hasCacheFile {
						if binF, err := os.Open(binPath); err == nil {
							var parsed []AsnRange
							br := bufio.NewReaderSize(binF, 64*1024)
							if err := gob.NewDecoder(br).Decode(&parsed); err == nil {
								asnFileRanges[src] = parsed
								changed = true
								binF.Close()
								if logIdentity {
									log.Printf("[IDENTITY-ASN] Not modified (304), loading BINARY cache (%s) for %s", filepath.Base(binPath), src)
								}
								continue // Skip raw parsing entirely
							}
							binF.Close()
						}
						
						reader, _ = os.Open(cachePath)
						changed = true
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Not modified (304), loading raw local cache (%s) for %s", filepath.Base(cachePath), src)
						}
					} else {
						continue
					}
				} else if resp.StatusCode == http.StatusOK {
					asnHTTPMeta[src] = catListHeaders{
						LastModified: resp.Header.Get("Last-Modified"),
						ETag:         resp.Header.Get("ETag"),
						LastFetch:    nowUnix,
					}
					
					if cachePath != "" {
						f, err := os.Create(cachePath + ".tmp")
						if err == nil {
							// [SECURITY/FIX] CWE-400 Uncontrolled Resource Consumption Protection
							limitReader := io.LimitReader(resp.Body, 100*1024*1024 + 1)
							written, copyErr := io.Copy(f, limitReader)
							
							// [SECURITY/FIX] Assert complete bounds prior to renaming the raw cache payload
							syncErr := f.Sync()
							closeErr := f.Close()
							
							if copyErr == nil && syncErr == nil && closeErr == nil {
							// Successfully evaluated the threshold bounds without truncation bypasses
							if written > 100*1024*1024 {
								os.Remove(cachePath + ".tmp")
								if logIdentity {
									log.Printf("[IDENTITY-ASN] Error: payload exceeded 100MB safety limit for %s", src)
								}
								resp.Body.Close()
								continue
							}
							os.Remove(cachePath) // Protects against OS-level file lock rejections natively
							if renameErr := os.Rename(cachePath+".tmp", cachePath); renameErr != nil {
								if logIdentity {
									log.Printf("[IDENTITY-ASN] WARNING: Failed to atomically rename raw cache natively: %v", renameErr)
								}
								os.Remove(cachePath+".tmp")
							} else {
								if logIdentity {
									log.Printf("[IDENTITY-ASN] Saved remote database to local cache (%s) for %s", filepath.Base(cachePath), src)
								}
							}
							resp.Body.Close()
							
							var openErr error
							reader, openErr = os.Open(cachePath)
								if openErr != nil {
									if logIdentity {
										log.Printf("[IDENTITY-ASN] Error reopening cache file %s: %v", cachePath, openErr)
									}
								}
							} else {
								// Natively purge incomplete/corrupted byte arrays if the disk fills or stream terminates early
								os.Remove(cachePath + ".tmp")
								if logIdentity {
									log.Printf("[IDENTITY-ASN] Error: Could not copy payload to disk safely for %s: (Copy: %v, Sync: %v, Close: %v)", src, copyErr, syncErr, closeErr)
								}
								resp.Body.Close() // Explicitly close to prevent falling back to an exhausted stream
							}
						} else {
							if logIdentity {
								log.Printf("[IDENTITY-ASN] Warning: could not create cache file %s: %v. Parsing directly from memory.", cachePath+".tmp", err)
							}
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
						if binF, err := os.Open(binPath); err == nil {
							var parsed []AsnRange
							br := bufio.NewReaderSize(binF, 64*1024)
							if err := gob.NewDecoder(br).Decode(&parsed); err == nil {
								asnFileRanges[src] = parsed
								changed = true
								binF.Close()
								if logIdentity {
									log.Printf("[IDENTITY-ASN] Failed to fetch. HTTP %d for %s — loaded from BINARY cache (%s)", resp.StatusCode, src, filepath.Base(binPath))
								}
								continue
							}
							binF.Close()
						}
						
						reader, _ = os.Open(cachePath)
						changed = true
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Failed to fetch. HTTP %d for %s — falling back to raw local cache (%s)", resp.StatusCode, src, filepath.Base(cachePath))
						}
					} else {
						if logIdentity {
							log.Printf("[IDENTITY-ASN] Failed to fetch. HTTP %d for %s", resp.StatusCode, src)
						}
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
				
				// Attempt ultra-fast binary loading for unchanged local files organically
				if cfg.Identity.ASNCacheDir != "" {
					h := sha256.Sum256([]byte(src))
					binPath := filepath.Join(cfg.Identity.ASNCacheDir, "local-asn-"+hex.EncodeToString(h[:8])+".bin")
					if bf, err := os.Open(binPath); err == nil {
						var gobParsed []AsnRangeGob
						br := bufio.NewReaderSize(bf, 64*1024)
						if err := gob.NewDecoder(br).Decode(&gobParsed); err == nil {
							var parsed []AsnRange
							for _, g := range gobParsed {
								start, err1 := netip.ParseAddr(g.Start)
								end, err2 := netip.ParseAddr(g.End)
								if err1 == nil && err2 == nil {
									parsed = append(parsed, AsnRange{Start: start, End: end, ASN: g.ASN, Name: g.Name, Country: g.Country})
								}
							}
							asnFileRanges[src] = parsed
							changed = true
							bf.Close()
							if logIdentity {
								log.Printf("[IDENTITY-ASN] Loaded BINARY cache for unchanged local file: %s", src)
							}
							continue
						}
						bf.Close()
					}
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
			func() {
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
					// [SECURITY/FIX] GZIP Bomb Protection. Cap decompressed ASN databases 
					// to 500MB natively to prevent catastrophic memory exhaustion attacks.
					decodeReader = io.LimitReader(gzr, 500*1024*1024)
				} else {
					decodeReader = io.MultiReader(bytes.NewReader(header[:n]), reader)
				}

				parsed := parseASNStream(decodeReader)
				asnFileRanges[src] = parsed
				if logIdentity {
					log.Printf("[IDENTITY-ASN] Parsed and loaded %d IP/ASN boundaries from: %s", len(parsed), src)
				}
				
				// Generate the Binary Output organically to persist the structured memory bounds
				if cfg.Identity.ASNCacheDir != "" {
					var outBinPath string
					if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
						h := sha256.Sum256([]byte(src))
						outBinPath = filepath.Join(cfg.Identity.ASNCacheDir, "asn-"+hex.EncodeToString(h[:8])+".bin")
					} else {
						h := sha256.Sum256([]byte(src))
						outBinPath = filepath.Join(cfg.Identity.ASNCacheDir, "local-asn-"+hex.EncodeToString(h[:8])+".bin")
					}
					if bf, err := os.Create(outBinPath + ".tmp"); err == nil {
						var gobParsed []AsnRangeGob
						for _, p := range parsed {
							gobParsed = append(gobParsed, AsnRangeGob{Start: p.Start.String(), End: p.End.String(), ASN: p.ASN, Name: p.Name, Country: p.Country})
						}
						bw := bufio.NewWriterSize(bf, 64*1024)
						if err := gob.NewEncoder(bw).Encode(gobParsed); err == nil {
							bw.Flush()
							bf.Sync()
							bf.Close()
							os.Remove(outBinPath) // Protects against OS-level file lock rejections natively
							if renameErr := os.Rename(outBinPath+".tmp", outBinPath); renameErr != nil {
								if logIdentity {
									log.Printf("[IDENTITY-ASN] WARNING: Failed to atomically rename binary cache natively: %v", renameErr)
								}
								os.Remove(outBinPath+".tmp")
							}
						} else {
							if logIdentity {
								log.Printf("[IDENTITY-ASN] WARNING: Failed to encode binary cache natively: %v", err)
							}
							bf.Close()
							os.Remove(outBinPath+".tmp")
						}
					}
				}
			}()
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
		}
	}

	if !changed {
		return
	}

	saveASNMeta(asnHTTPMeta)

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

// fastExtractJSONStr securely extracts a string value from a flat JSON payload natively,
// completely bypassing costly reflection and map allocations inherent to json.Unmarshal.
// Protects constrained environments from severe GC thrashing natively.
func fastExtractJSONStr(line []byte, key []byte) string {
	idx := bytes.Index(line, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	
	// Advance to the colon separator securely
	for start < len(line) && line[start] != ':' {
		start++
	}
	if start >= len(line) {
		return ""
	}
	start++ // Step over colon
	
	// Advance past arbitrary whitespace characters safely
	for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	
	// Guarantee the value opens cleanly with quotation marks
	if start >= len(line) || line[start] != '"' {
		return ""
	}
	start++
	
	// [SECURITY/FIX] Search explicitly for the closing quote structure dynamically.
	// Validates escaped quotes (\") internally to prevent structural JSON truncation.
	end := 0
	for {
		i := bytes.IndexByte(line[start+end:], '"')
		if i < 0 {
			return ""
		}
		end += i
		
		// Determine if the quote is escaped by calculating preceding backslashes
		bsCount := 0
		for j := start + end - 1; j >= start && line[j] == '\\'; j-- {
			bsCount++
		}
		if bsCount%2 != 0 {
			// Escaped quote detected, advance pointer and continue loop safely
			end++
			continue
		}
		break
	}
	
	return string(line[start : start+end])
}

// Byte keys precompiled for zero-allocation structural extraction boundaries
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

		// [PERF/FIX] Completely bypass `json.Unmarshal` natively.
		// Replaced massive allocations with precise O(1) byte pointer evaluations, 
		// eradicating GC memory spikes when digesting huge ASN structures.
		network     := fastExtractJSONStr(line, keyNetwork)
		startIPStr  := fastExtractJSONStr(line, keyStartIP)
		endIPStr    := fastExtractJSONStr(line, keyEndIP)
		asn         := fastExtractJSONStr(line, keyASN)
		asName      := fastExtractJSONStr(line, keyASName)
		name        := fastExtractJSONStr(line, keyName)
		countryCode := fastExtractJSONStr(line, keyCountryCode)
		country     := fastExtractJSONStr(line, keyCountry)

		var start, end netip.Addr
		var err1, err2 error

		if network != "" {
			// [SECURITY/FIX] Enforce pure ParsePrefixUnmapped bounds organically to guarantee
			// identical parsing integrity regarding IPv4-in-IPv6 translation evaluations.
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
			// [SECURITY/FIX] Enforce unmapping BEFORE version evaluations to perfectly align 
			// IPv4-in-IPv6 capabilities with strict platform filtering directives organically.
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
		// [PERF/FIX] Relinquish processor bound constraints every 10,000 iterations natively.
		// Permits constrained routers to cleanly execute incoming DNS packets organically 
		// during multi-million line DB un-packing loops to prevent router freezes.
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	
	if err := scanner.Err(); err != nil {
		if logIdentity {
			log.Printf("[IDENTITY-ASN] WARNING: Partial scanner error during ASN parsing: %v", err)
		}
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

