/*
File: identity.go
Version: 1.26.0
Last Updated: 2026-03-08 14:00 CET
Description: Parses /etc/hosts and dnsmasq lease files to extract short hostnames
             for {client-name} substitution and local A/AAAA/PTR resolution.

             DESIGN — immutable snapshot with atomic pointer swap:
               All four lookup maps are grouped in an identitySnapshot struct.
               Readers load the current snapshot via a single atomic.Pointer.Load()
               — zero mutex overhead on the query hot path. The writer (pollIdentity)
               builds a completely new snapshot and atomically swaps it in.
               Old snapshots are GC'd once all in-flight readers release them.

               Maps inside a snapshot:
                 ipToName    IP  -> short hostname  (forward, for client-name resolution)
                 macToName   MAC -> short hostname  (forward, for client-name resolution)
                 nameToIPs   short hostname -> []net.IP  (reverse, for A/AAAA answers)
                 arpaToNames ARPA string    -> []string  (reverse, for PTR answers)

             PERFORMANCE — per-file mtime cache:
               Each file's mtime is stored after a successful parse. On the next
               poll tick the file is stat()'d first — if the mtime is unchanged
               the cached partial result is reused directly, skipping the open(),
               read(), and parse() entirely.

Changes:
  1.26.0 - [FIX] parseHostsBytes: now processes ALL hostname tokens per line.
           Previously only the first alias was stored; subsequent aliases (e.g.
           "mydevice.local" in "1.2.3.4 mydevice mydevice.local") were silently
           dropped — a regression for any hosts file with multi-name entries.
           [FIX] parseHostsBytes: inline # comments are now stripped before name
           parsing. Previously "1.2.3.4 router # main router" stored "#" as a
           hostname, polluting nameToIPs and arpaToNames with junk entries.
           [FIX] filterNullIPs: now also cleans arpaToNames for each null IP that
           is removed. Previously, filtering nameToIPs left arpaToNames intact —
           PTR queries for 0.0.0.0 or :: still resolved to the hostname even
           after the forward lookup had been corrected, creating an inconsistency
           that could confuse some DNS clients. Signature updated to accept
           arpaToNames; pollIdentity call-site updated accordingly.
  1.25.1 - [LOG] filterNullIPs now returns and logs the specific list of
           cleaned hostnames.
  1.25.0 - [FEAT] filterNullIPs added: when a hostname has multiple IPs including
           a NULL-IP (0.0.0.0 or ::), the NULL-IP is removed unless it's the
           only IP. Resolves blocklist vs local-override conflicts. Logs cleanup.
  1.24.0 - [PERF] LookupIPsByNameLower: new variant of LookupIPsByName that skips
           the strings.ToLower call. nameToIPs keys are always stored lowercase
           (storeEntry uses strings.ToLower on insert). Callers that have already
           normalised via lowerTrimDot — specifically resolveLocalIdentity in
           process.go — can call this directly and save a full byte scan per
           A/AAAA query that reaches the local-identity check.
  1.23.0 - [PERF] storeEntry: dropped redundant strings.ToLower on ARPA key and
           replaced strings.TrimSuffix with direct slice.
           [PERF] storeEntry returns shortName, eliminating duplicate dot-search
           in parseLeasesBytes.
  1.22.0 - [PERF] Replaced sync.RWMutex + 4 global maps with atomic.Pointer to
           an immutable identitySnapshot struct.
  1.21.0 - [PERF] LookupNameByMACOrIP: combined MAC+IP under single RLock.
  1.20.0 - [PERF] LookupIPsBySuffix: single RLock for entire suffix walk.
  1.19.0 - [FEAT] Poll interval configurable via identity.poll_interval.
  1.18.0 - [FEAT] LookupIPsBySuffix for subdomain matching.
  1.17.0 - [PERF] pollIdentity skips rebuild when no files changed.
  1.15.0 - Per-file mtime tracking, bytes-based parsing, pre-sized maps.
*/

package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// identitySnapshot is an immutable point-in-time view of all identity maps.
// Created fresh by pollIdentity and swapped in atomically. Readers hold a
// reference to the snapshot for the duration of their lookup — no locks needed.
// Go's GC ensures the old snapshot stays alive until all readers are done.
type identitySnapshot struct {
	ipToName    map[string]string
	macToName   map[string]string
	nameToIPs   map[string][]net.IP
	arpaToNames map[string][]string
}

// identSnap is the single source of truth for all identity lookups.
// Readers: identSnap.Load() — returns *identitySnapshot, zero contention.
// Writer:  identSnap.Store() — called only from pollIdentity goroutine.
var identSnap atomic.Pointer[identitySnapshot]

func init() {
	identSnap.Store(&identitySnapshot{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string),
		nameToIPs:   make(map[string][]net.IP),
		arpaToNames: make(map[string][]string),
	})
}

// parsedFile holds the per-file cached parse result and the mtime that produced it.
type parsedFile struct {
	cachedAt    time.Time
	ipToName    map[string]string
	macToName   map[string]string
	nameToIPs   map[string][]net.IP
	arpaToNames map[string][]string
	seen        map[string]bool
}

// fileCache is only accessed from the single pollIdentity goroutine — no sync needed.
var fileCache = make(map[string]*parsedFile)

func identityPollInterval() time.Duration {
	s := cfg.Identity.PollInterval
	if s <= 0 {
		return 30 * time.Second
	}
	if s < 5 {
		s = 5
	}
	return time.Duration(s) * time.Second
}

func InitIdentity() {
	if len(cfg.Identity.HostsFiles) == 0 && len(cfg.Identity.DnsmasqLeases) == 0 {
		log.Println("[IDENTITY] No hosts files or lease files configured — local identity resolution disabled.")
		return
	}

	interval := identityPollInterval()
	log.Printf("[IDENTITY] Initialising: %d hosts file(s), %d lease file(s), poll interval: %s",
		len(cfg.Identity.HostsFiles), len(cfg.Identity.DnsmasqLeases), interval)

	go func() {
		pollIdentity()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			pollIdentity()
		}
	}()
}

// LookupNameByIP returns the short hostname for a given IP, if known.
func LookupNameByIP(ip string) (string, bool) {
	name := identSnap.Load().ipToName[ip]
	return name, name != ""
}

// LookupNameByMAC returns the short hostname for a normalized MAC, if known.
func LookupNameByMAC(mac string) (string, bool) {
	name := identSnap.Load().macToName[mac]
	return name, name != ""
}

// LookupNameByMACOrIP returns the short hostname for a client, trying MAC first
// then IP. Single atomic.Pointer.Load — no locks, no contention.
// mac may be empty (non-Linux builds where ARP is unavailable).
func LookupNameByMACOrIP(mac, ip string) string {
	snap := identSnap.Load()
	if mac != "" {
		if name := snap.macToName[mac]; name != "" {
			return name
		}
	}
	return snap.ipToName[ip]
}

// LookupIPsByName returns all IPs mapped to a full hostname. O(1).
// Applies strings.ToLower to name before the map lookup. When the caller has
// already normalised via lowerTrimDot, use LookupIPsByNameLower to skip the
// redundant byte scan.
func LookupIPsByName(name string) []net.IP {
	return identSnap.Load().nameToIPs[strings.ToLower(name)]
}

// LookupIPsByNameLower is identical to LookupIPsByName but skips the
// strings.ToLower call. Only call this when name is already lowercase — e.g.
// after lowerTrimDot in ProcessDNS. Saves a full byte scan on every A/AAAA
// query that reaches the local-identity check.
func LookupIPsByNameLower(name string) []net.IP {
	return identSnap.Load().nameToIPs[name]
}

// LookupIPsBySuffix walks the query name label by label and returns the IPs of
// the first matching parent domain found in nameToIPs.
// Single atomic load for the entire walk — pure CPU, no I/O, no blocking.
func LookupIPsBySuffix(qname string) []net.IP {
	snap   := identSnap.Load()
	search := qname
	for {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
		if len(search) == 0 {
			break
		}
		if ips := snap.nameToIPs[search]; len(ips) > 0 {
			return ips
		}
	}
	return nil
}

// LookupNamesByARPA returns all hostnames for an ARPA string. O(1).
func LookupNamesByARPA(arpa string) []string {
	return identSnap.Load().arpaToNames[arpa]
}

func pollIdentity() {
	// Use previous snapshot size as hint for pre-sizing new maps.
	prev := identSnap.Load()
	hint := len(prev.ipToName) + 8

	freshIP   := make(map[string]string,   hint)
	freshMAC  := make(map[string]string,   hint)
	freshName := make(map[string][]net.IP, hint)
	freshARPA := make(map[string][]string, hint)

	anyChanged := false

	for _, path := range cfg.Identity.HostsFiles {
		pf, changed := getOrParse(path, false)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.DnsmasqLeases {
		pf, changed := getOrParse(path, true)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}

	if !anyChanged {
		return
	}

	// Filter out NULL IPs (0.0.0.0 or ::) from hostnames that also have other
	// valid IPs mapped to them — intelligently overrides generic blocklists with
	// user-defined local redirects. Also cleans arpaToNames to keep reverse
	// lookups consistent with the corrected forward map (bug fix v1.26.0).
	if cleanedNames := filterNullIPs(freshName, freshARPA); len(cleanedNames) > 0 {
		log.Printf("[IDENTITY] Cleaned %d hostnames: removed NULL-IPs (0.0.0.0 or ::) because valid alternate IPs were present: %s",
			len(cleanedNames), strings.Join(cleanedNames, ", "))
	}

	// Atomic swap — readers see the old snapshot until this completes,
	// then instantly see the new one. No partial state, no locks.
	identSnap.Store(&identitySnapshot{
		ipToName:    freshIP,
		macToName:   freshMAC,
		nameToIPs:   freshName,
		arpaToNames: freshARPA,
	})

	log.Printf("[IDENTITY] Maps rebuilt: %d IPs, %d MACs, %d hostnames, %d PTR records",
		len(freshIP), len(freshMAC), len(freshName), len(freshARPA))
}

func getOrParse(path string, isLeases bool) (*parsedFile, bool) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("[IDENTITY] Cannot stat %s: %v — skipping", path, err)
		return nil, false
	}
	mtime := info.ModTime()

	if cached, ok := fileCache[path]; ok && cached.cachedAt.Equal(mtime) {
		log.Printf("[IDENTITY] %s unchanged (mtime %s) — using cached %d entries",
			path, mtime.Format(time.RFC3339), len(cached.ipToName))
		return cached, false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[IDENTITY] Cannot read %s: %v — skipping", path, err)
		return nil, false
	}

	fileType := "hosts"
	if isLeases {
		fileType = "leases"
	}

	var pf *parsedFile
	if isLeases {
		pf = parseLeasesBytes(data)
	} else {
		pf = parseHostsBytes(data)
	}
	pf.cachedAt = mtime
	fileCache[path] = pf

	log.Printf("[IDENTITY] Parsed %s file %s: %d IPs, %d MACs, %d hostnames",
		fileType, path, len(pf.ipToName), len(pf.macToName), len(pf.nameToIPs))
	return pf, true
}

func mergePartial(
	pf       *parsedFile,
	freshIP   map[string]string,
	freshMAC  map[string]string,
	freshName map[string][]net.IP,
	freshARPA map[string][]string,
) {
	for k, v := range pf.ipToName {
		freshIP[k] = v
	}
	for k, v := range pf.macToName {
		freshMAC[k] = v
	}
	for k, v := range pf.nameToIPs {
		freshName[k] = append(freshName[k], v...)
	}
	for k, v := range pf.arpaToNames {
		freshARPA[k] = append(freshARPA[k], v...)
	}
}

// parseHostsBytes parses a hosts-file byte slice into a parsedFile.
//
// BUG FIX (v1.26.0 — two fixes):
//
//  1. ALL hostname tokens per line are now processed, not just the first.
//     Standard /etc/hosts allows multiple space-separated aliases on one line:
//       192.168.1.100  mydevice  mydevice.local  mydevice.lan
//     Previously only "mydevice" would be stored; all aliases were silently dropped.
//
//  2. Inline comments (everything from the first '#' to end-of-line) are now
//     stripped before name parsing. Previously a line like:
//       192.168.1.1  router  # main gateway
//     would store "#" as a valid hostname and corrupt nameToIPs/arpaToNames.
func parseHostsBytes(data []byte) *parsedFile {
	pf := &parsedFile{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string),
		nameToIPs:   make(map[string][]net.IP),
		arpaToNames: make(map[string][]string),
		seen:        make(map[string]bool),
	}

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimLeft(line, " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Strip inline comment — everything from the first '#' onwards is noise.
		if ci := bytes.IndexByte(line, '#'); ci >= 0 {
			line = bytes.TrimRight(line[:ci], " \t")
		}
		if len(line) == 0 {
			continue
		}

		// First token is the IP address.
		ipEnd := bytes.IndexAny(line, " \t")
		if ipEnd < 0 {
			continue // IP with no hostname — nothing to store
		}
		ipStr := string(line[:ipEnd])
		line = bytes.TrimLeft(line[ipEnd:], " \t")

		// All remaining tokens are hostnames/aliases — store every one of them.
		// /etc/hosts allows multiple aliases per line (hosts(5) manpage).
		for len(line) > 0 {
			nameEnd := bytes.IndexAny(line, " \t")
			var name []byte
			if nameEnd < 0 {
				name = line
				line = nil
			} else {
				name = line[:nameEnd]
				line = bytes.TrimLeft(line[nameEnd:], " \t")
			}
			if len(name) == 0 {
				break
			}
			storeEntry(ipStr, string(name), pf)
		}
	}
	return pf
}

func parseLeasesBytes(data []byte) *parsedFile {
	pf := &parsedFile{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string),
		nameToIPs:   make(map[string][]net.IP),
		arpaToNames: make(map[string][]string),
		seen:        make(map[string]bool),
	}

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		fields := bytes.Fields(line)
		if len(fields) < 4 {
			continue
		}

		macBytes  := fields[1]
		ipBytes   := fields[2]
		nameBytes := fields[3]

		if len(nameBytes) == 0 || bytes.Equal(nameBytes, []byte("*")) {
			continue
		}

		fullName := string(nameBytes)

		// storeEntry returns the pre-computed shortName, eliminating a duplicate
		// strings.IndexByte dot-search here. Returns "" when net.ParseIP fails
		// (malformed IP) — skip the MAC entry in that case too.
		shortName := storeEntry(string(ipBytes), fullName, pf)
		if shortName == "" {
			continue
		}

		if parsedMAC, err := net.ParseMAC(string(macBytes)); err == nil {
			pf.macToName[parsedMAC.String()] = shortName
		}
	}
	return pf
}

func isSinkIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}

// storeEntry populates all four maps in pf for a single IP+hostname pair and
// returns the shortName (first label of rawName). Returns "" when ip is
// unparseable — callers use this as a validity signal to skip further work.
//
// shortName is computed before the sink guard so it is always available to the
// caller regardless of whether the IP is loopback/unspecified. Sink IPs still
// get nameToIPs and arpaToNames entries (so local PTR and forward lookups work
// for ::1 / 127.0.0.1) but are excluded from ipToName (so they don't pollute
// client-name resolution with "localhost").
//
// ARPA key: dns.ReverseAddr always returns a lowercase, "." terminated string.
// strings.ToLower and strings.TrimSuffix are both redundant — we slice off the
// trailing dot directly with arpa[:len(arpa)-1].
func storeEntry(ip, rawName string, pf *parsedFile) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	// Compute shortName up-front — needed by the caller (parseLeasesBytes for
	// MAC->name) and by the ipToName store below, regardless of sink status.
	shortName := rawName
	if idx := strings.IndexByte(rawName, '.'); idx > 0 {
		shortName = rawName[:idx]
	}

	sink    := isSinkIP(parsedIP)
	fullKey := strings.ToLower(rawName)

	dedupKey := fullKey + "|" + ip
	if !pf.seen[dedupKey] {
		pf.seen[dedupKey] = true
		pf.nameToIPs[fullKey] = append(pf.nameToIPs[fullKey], parsedIP)

		if arpa, err := dns.ReverseAddr(ip); err == nil {
			// dns.ReverseAddr: always lowercase, always "." terminated.
			// Slicing off the trailing dot is faster than strings.TrimSuffix.
			key := arpa[:len(arpa)-1]
			pf.arpaToNames[key] = append(pf.arpaToNames[key], rawName)
		}
	}

	if !sink {
		pf.ipToName[ip] = shortName
	}
	return shortName
}

func splitLine(data []byte) (line, rest []byte) {
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return data, nil
	}
	line = data[:idx]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line, data[idx+1:]
}

// filterNullIPs removes unspecified-address IPs (0.0.0.0 or ::) from nameToIPs
// for any hostname that also has at least one valid (non-unspecified) IP, and
// removes the corresponding reverse entries from arpaToNames to keep forward
// and reverse lookups consistent.
//
// BUG FIX (v1.26.0): previous versions only cleaned nameToIPs. After that fix
// a PTR query for 0.0.0.0 / :: still resolved to the hostname because
// arpaToNames was not cleaned. This caused a forward/reverse inconsistency that
// could confuse DNS clients doing round-trip validation.
//
// Use case: a blocklist maps ads to 0.0.0.0, and a user adds a hosts entry
// mapping the same domain to a real local IP. filterNullIPs detects the mix,
// removes the 0.0.0.0 from both forward and reverse maps, leaving only the
// real IP visible to clients.
//
// Hostnames that ONLY map to NULL IPs are left untouched (the block is valid).
//
// Returns the distinct hostnames that had NULL-IPs pruned (for logging).
func filterNullIPs(nameToIPs map[string][]net.IP, arpaToNames map[string][]string) []string {
	var cleaned []string

	for name, ips := range nameToIPs {
		if len(ips) <= 1 {
			continue // nothing to filter: 0 or 1 IPs means no mixed case
		}

		// Pass 1: determine whether this hostname has a mix of null and valid IPs.
		hasNull, hasValid := false, false
		for _, ip := range ips {
			if ip.IsUnspecified() {
				hasNull = true
			} else {
				hasValid = true
			}
		}
		if !hasNull || !hasValid {
			continue // pure-null (blocklist) or pure-valid — leave untouched
		}

		// Pass 2: build the filtered forward slice and collect ARPA keys to clean.
		// Allocation only happens for hostnames that actually need filtering.
		filtered  := make([]net.IP, 0, len(ips))
		nullARPAs := make([]string, 0, 2) // 0.0.0.0 and :: at most
		for _, ip := range ips {
			if ip.IsUnspecified() {
				// Derive the ARPA key for this null IP so we can clean arpaToNames.
				if arpa, err := dns.ReverseAddr(ip.String()); err == nil {
					nullARPAs = append(nullARPAs, arpa[:len(arpa)-1]) // strip trailing dot
				}
			} else {
				filtered = append(filtered, ip)
			}
		}
		nameToIPs[name] = filtered

		// Clean arpaToNames: remove this hostname from every null-IP ARPA key.
		// nameToIPs keys are always lowercase (storeEntry lowercases on insert),
		// so name is already lowercase — compare case-insensitively against the
		// raw names stored in arpaToNames (storeEntry stores rawName there).
		for _, arpaKey := range nullARPAs {
			names := arpaToNames[arpaKey]
			kept  := names[:0] // reuse backing array — avoids an allocation
			for _, n := range names {
				if strings.ToLower(n) != name {
					kept = append(kept, n)
				}
			}
			if len(kept) == 0 {
				delete(arpaToNames, arpaKey)
			} else {
				arpaToNames[arpaKey] = kept
			}
		}

		cleaned = append(cleaned, name)
	}
	return cleaned
}

