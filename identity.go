/*
File: identity.go
Version: 1.18.0
Last Updated: 2026-03-01 19:00 CET
Description: Parses /etc/hosts and dnsmasq lease files to extract short hostnames
             for {client-name} substitution and local A/AAAA/PTR resolution.

             DESIGN — four O(1) lookup maps, rebuilt atomically each poll cycle:
               _ipToName    IP  -> short hostname  (forward, for client-name resolution)
               _macToName   MAC -> short hostname  (forward, for client-name resolution)
               _nameToIPs   short hostname -> []net.IP  (reverse, for A/AAAA answers)
               _arpaToNames ARPA string    -> []string  (reverse, for PTR answers)

             PERFORMANCE — per-file mtime cache:
               Each file's mtime is stored after a successful parse. On the next
               poll tick the file is stat()'d first — if the mtime is unchanged
               the cached partial result is reused directly, skipping the open(),
               read(), and parse() entirely. /etc/hosts almost never changes;
               the dnsmasq lease file changes on every DHCP event. This means
               most 30-second ticks are two stat() calls and a map merge, nothing
               more. Files are read into a single []byte buffer and parsed with
               bytes.IndexByte — no bufio.Scanner overhead, no per-line string
               allocation beyond the fields we actually keep.

Changes:
  1.18.0 - [FEAT] Added LookupIPsBySuffix for subdomain matching. A hosts entry
           "1.2.3.4 company.com" now also matches "www.company.com" and any
           deeper subdomain. Exact match is always tried first via LookupIPsByName;
           suffix walk is the fallback. resolveLocalIdentity in process.go drives
           both lookups in order.
  1.17.0 - [PERF] pollIdentity skips map rebuild when no files changed. Short names
           are only used for {client-name} resolution (ipToName / macToName)
           and must not influence DNS resolution — resolveLocalIdentity in
           process.go now does exact full-name lookup only, no fallback.
           Sink IPs (0.0.0.0, ::, 127.x, ::1) excluded from ipToName so they
           never appear in client routing or {client-name} substitution.
  1.15.0 - Added per-file mtime tracking, bytes-based parsing, pre-sized maps.
*/

package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// parsedFile holds the per-file cached parse result and the mtime that produced it.
// If the file's current mtime matches cachedAt, the partial maps are reused as-is.
type parsedFile struct {
	cachedAt    time.Time
	ipToName    map[string]string     // IP  -> short hostname
	macToName   map[string]string     // MAC -> short hostname (leases only)
	nameToIPs   map[string][]net.IP   // short hostname -> IPs
	arpaToNames map[string][]string   // ARPA -> hostnames
	seen        map[string]bool       // dedup set: "lowername|ip" keys
}

var (
	// identMu guards all four global maps as a unit.
	identMu sync.RWMutex

	_ipToName   = make(map[string]string)
	_macToName  = make(map[string]string)
	_nameToIPs  = make(map[string][]net.IP)
	_arpaToNames = make(map[string][]string)

	// Per-file parse caches — keyed by absolute file path.
	// Only written during pollIdentity (single goroutine) so no mutex needed.
	fileCache = make(map[string]*parsedFile)
)

func InitIdentity() {
	if len(cfg.Identity.HostsFiles) == 0 && len(cfg.Identity.DnsmasqLeases) == 0 {
		log.Println("[IDENTITY] No hosts files or lease files configured — local identity resolution disabled.")
		return
	}
	log.Printf("[IDENTITY] Initialising: %d hosts file(s), %d lease file(s)",
		len(cfg.Identity.HostsFiles), len(cfg.Identity.DnsmasqLeases))
	go func() {
		pollIdentity()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			pollIdentity()
		}
	}()
}

// LookupNameByIP returns the short hostname for a given IP, if known.
func LookupNameByIP(ip string) (string, bool) {
	identMu.RLock()
	name, ok := _ipToName[ip]
	identMu.RUnlock()
	return name, ok
}

// LookupNameByMAC returns the short hostname for a normalized MAC, if known.
func LookupNameByMAC(mac string) (string, bool) {
	identMu.RLock()
	name, ok := _macToName[mac]
	identMu.RUnlock()
	return name, ok
}

// LookupIPsByName returns all IPs mapped to a full hostname (case-insensitive). O(1).
func LookupIPsByName(name string) []net.IP {
	identMu.RLock()
	ips := _nameToIPs[strings.ToLower(name)]
	identMu.RUnlock()
	return ips
}

// LookupIPsBySuffix walks the query name label by label and returns the IPs of
// the first matching parent domain found in nameToIPs.
// e.g. "bla.company.com" tries "company.com", then "com".
// The exact name itself is intentionally skipped here — callers try that first
// via LookupIPsByName so we never duplicate the exact-match lookup.
// Zero allocation: reslices the input string, no copies.
func LookupIPsBySuffix(qname string) []net.IP {
	search := qname
	for {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:] // strip one label, e.g. "bla.company.com" -> "company.com"
		if len(search) == 0 {
			break
		}
		identMu.RLock()
		ips := _nameToIPs[search]
		identMu.RUnlock()
		if len(ips) > 0 {
			return ips
		}
	}
	return nil
}

// LookupNamesByARPA returns all hostnames for an ARPA string (lowercase, no trailing
// dot, e.g. "42.1.168.192.in-addr.arpa"). O(1).
func LookupNamesByARPA(arpa string) []string {
	identMu.RLock()
	names := _arpaToNames[arpa]
	identMu.RUnlock()
	return names
}

// pollIdentity checks each configured file for mtime changes. If no file has
// changed since the last poll the function returns immediately — no map rebuild,
// no lock contention, no allocations. Only when at least one file is new or
// modified are the four global maps rebuilt and atomically swapped.
func pollIdentity() {
	// Count current total entries to pre-size fresh maps and avoid rehashing.
	identMu.RLock()
	hint := len(_ipToName) + 8
	identMu.RUnlock()

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

	// Nothing changed — skip the rebuild entirely, no lock, no allocation swap.
	if !anyChanged {
		return
	}

	identMu.Lock()
	_ipToName    = freshIP
	_macToName   = freshMAC
	_nameToIPs   = freshName
	_arpaToNames = freshARPA
	identMu.Unlock()

	log.Printf("[IDENTITY] Maps rebuilt: %d IPs, %d MACs, %d hostnames, %d PTR records",
		len(freshIP), len(freshMAC), len(freshName), len(freshARPA))
}

// getOrParse returns the cached parsedFile for path if the file's mtime is
// unchanged (changed=false), otherwise reads, parses, caches, and returns it
// (changed=true). Returns (nil, false) if the file cannot be stat'd or read.
func getOrParse(path string, isLeases bool) (*parsedFile, bool) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("[IDENTITY] Cannot stat %s: %v — skipping", path, err)
		return nil, false
	}
	mtime := info.ModTime()

	// Cache hit: mtime unchanged — reuse, no I/O, signal no change.
	if cached, ok := fileCache[path]; ok && cached.cachedAt.Equal(mtime) {
		log.Printf("[IDENTITY] %s unchanged (mtime %s) — using cached %d entries",
			path, mtime.Format(time.RFC3339), len(cached.ipToName))
		return cached, false
	}

	// Cache miss or file changed — read and parse.
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
	return pf, true // signal that this file changed
}

// mergePartial copies one file's partial maps into the global fresh maps.
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

// parseHostsBytes parses a /etc/hosts file from a raw byte slice.
//
// Format:  IP  Hostname  [Aliases...]
//
// Uses bytes.IndexByte for line splitting and field scanning — no per-line
// string allocation until we've confirmed the line has the fields we need.
func parseHostsBytes(data []byte) *parsedFile {
	pf := &parsedFile{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string), // always empty for hosts files
		nameToIPs:   make(map[string][]net.IP),
		arpaToNames: make(map[string][]string),
		seen:        make(map[string]bool),
	}

	for len(data) > 0 {
		// Slice off one line
		line, rest := splitLine(data)
		data = rest

		// Trim leading whitespace and skip comments/blanks
		line = bytes.TrimLeft(line, " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Extract IP field (up to first whitespace)
		ipEnd := bytes.IndexAny(line, " \t")
		if ipEnd < 0 {
			continue
		}
		ipBytes := line[:ipEnd]
		line     = bytes.TrimLeft(line[ipEnd:], " \t")

		// Extract hostname field (up to next whitespace or end)
		nameEnd := bytes.IndexAny(line, " \t")
		var nameBytes []byte
		if nameEnd < 0 {
			nameBytes = line
		} else {
			nameBytes = line[:nameEnd]
		}
		if len(nameBytes) == 0 {
			continue
		}

		ip       := string(ipBytes)
		fullName := string(nameBytes) // full name — storeEntry handles short-name logic
		storeEntry(ip, fullName, pf)
	}
	return pf
}

// parseLeasesBytes parses a dnsmasq leases file from a raw byte slice.
//
// Format:  ExpiryTime  MAC  IP  Hostname  ClientID
//
// Same zero-allocation approach as parseHostsBytes — bytes only until we
// have confirmed the line is a valid lease with a real hostname.
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

		// Need at least 4 fields: expiry MAC IP hostname
		fields := bytes.Fields(line)
		if len(fields) < 4 {
			continue
		}

		macBytes  := fields[1]
		ipBytes   := fields[2]
		nameBytes := fields[3]

		// Skip placeholder hostnames
		if len(nameBytes) == 0 || bytes.Equal(nameBytes, []byte("*")) {
			continue
		}

		ip       := string(ipBytes)
		fullName := string(nameBytes) // full name — storeEntry handles short-name logic
		storeEntry(ip, fullName, pf)

		// MAC -> name (leases only) — use short name for clean device labels
		shortName := fullName
		if idx := strings.IndexByte(fullName, '.'); idx > 0 {
			shortName = fullName[:idx]
		}
		if parsedMAC, err := net.ParseMAC(string(macBytes)); err == nil {
			pf.macToName[parsedMAC.String()] = shortName
		}
	}
	return pf
}

// isSinkIP returns true for addresses used as blocklist targets rather than
// real device addresses — 0.0.0.0, ::, 127.x.x.x, and ::1.
// Sink IPs must not pollute ipToName (client routing) or short-name reverse
// lookups (device name resolution).
func isSinkIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}

// storeEntry adds one IP/hostname pair to all relevant partial maps.
//
// nameToIPs and arpaToNames use the full name as key — exact-match only.
// Short names (first label) are ONLY stored in ipToName for {client-name}
// resolution and must never appear in nameToIPs or arpaToNames, to prevent
// blocklist entries (e.g. "0.0.0.0 ads.example.com" stored as "ads") from
// intercepting unrelated queries.
//
// Sink IPs (0.0.0.0, ::, 127.x, ::1) are excluded from ipToName entirely —
// they are blocklist targets, not real devices.
//
// Deduplication is keyed on (lowername|ip) to handle repeated lines.
func storeEntry(ip, rawName string, pf *parsedFile) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}

	sink    := isSinkIP(parsedIP)
	fullKey := strings.ToLower(rawName)

	// --- Full-name reverse maps (always, sink or not) ---
	dedupKey := fullKey + "|" + ip
	if !pf.seen[dedupKey] {
		pf.seen[dedupKey] = true
		pf.nameToIPs[fullKey] = append(pf.nameToIPs[fullKey], parsedIP)

		if arpa, err := dns.ReverseAddr(ip); err == nil {
			arpaKey := strings.TrimSuffix(strings.ToLower(arpa), ".")
			pf.arpaToNames[arpaKey] = append(pf.arpaToNames[arpaKey], rawName)
		}
	}

	// Sink IPs stop here — no ipToName entry, no client routing influence.
	if sink {
		return
	}

	// --- Forward map: short name only, real IPs only ---
	// ipToName is exclusively for {client-name} substitution and client routing.
	// Store the short hostname (first label) so device labels are clean —
	// "my-laptop" rather than "my-laptop.lan".
	shortName := rawName
	if idx := strings.IndexByte(rawName, '.'); idx > 0 {
		shortName = rawName[:idx]
	}
	pf.ipToName[ip] = shortName
}

// splitLine returns the first line and the remaining bytes.
// Handles \n and \r\n line endings.
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

