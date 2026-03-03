/*
File: identity.go
Version: 1.22.0
Last Updated: 2026-03-03 18:00 CET
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
  1.22.0 - [PERF] Replaced sync.RWMutex + 4 global maps with atomic.Pointer to
           an immutable identitySnapshot struct. Eliminates identMu entirely —
           readers pay zero lock overhead. On the hot path ProcessDNS called
           LookupNameByMACOrIP on every query under RLock; now it's a single
           atomic pointer load + two map reads. On a 10-worker UDP pool this
           removes 10 concurrent mutex acquisitions per query burst.
           The old LookupNameByMACOrIP combined two lookups under one RLock
           (v1.21.0). That optimisation is now moot — atomic loads are cheaper
           than even a single uncontended RLock.
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

// LookupIPsByName returns all IPs mapped to a full hostname (case-insensitive). O(1).
func LookupIPsByName(name string) []net.IP {
	return identSnap.Load().nameToIPs[strings.ToLower(name)]
}

// LookupIPsBySuffix walks the query name label by label and returns the IPs of
// the first matching parent domain found in nameToIPs.
// Single atomic load for the entire walk — pure CPU, no I/O, no blocking.
func LookupIPsBySuffix(qname string) []net.IP {
	snap := identSnap.Load()
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

		ipEnd := bytes.IndexAny(line, " \t")
		if ipEnd < 0 {
			continue
		}
		ipBytes := line[:ipEnd]
		line     = bytes.TrimLeft(line[ipEnd:], " \t")

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

		storeEntry(string(ipBytes), string(nameBytes), pf)
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

		ip       := string(ipBytes)
		fullName := string(nameBytes)
		storeEntry(ip, fullName, pf)

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

func isSinkIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback()
}

func storeEntry(ip, rawName string, pf *parsedFile) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}

	sink    := isSinkIP(parsedIP)
	fullKey := strings.ToLower(rawName)

	dedupKey := fullKey + "|" + ip
	if !pf.seen[dedupKey] {
		pf.seen[dedupKey] = true
		pf.nameToIPs[fullKey] = append(pf.nameToIPs[fullKey], parsedIP)

		if arpa, err := dns.ReverseAddr(ip); err == nil {
			arpaKey := strings.TrimSuffix(strings.ToLower(arpa), ".")
			pf.arpaToNames[arpaKey] = append(pf.arpaToNames[arpaKey], rawName)
		}
	}

	if sink {
		return
	}

	shortName := rawName
	if idx := strings.IndexByte(rawName, '.'); idx > 0 {
		shortName = rawName[:idx]
	}
	pf.ipToName[ip] = shortName
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

