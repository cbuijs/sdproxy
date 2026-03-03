/*
File: identity.go
Version: 1.21.0
Last Updated: 2026-03-03 16:00 CET
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
               most poll ticks are two stat() calls and a map merge, nothing more.
               Files are read into a single []byte buffer and parsed with
               bytes.IndexByte — no bufio.Scanner overhead, no per-line string
               allocation beyond the fields we actually keep.

Changes:
  1.21.0 - [PERF] Added LookupNameByMACOrIP: combines the MAC→name and IP→name
           lookups under a single identMu.RLock instead of two separate calls.
           ProcessDNS previously called LookupNameByMAC + LookupNameByIP as two
           independent RLock/RUnlock cycles per query. The combined function halves
           that to one cycle — the critical section is pure CPU (two map lookups),
           so holding the lock across both is safe and saves a full mutex round-trip
           on every query.
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
	"sync"
	"time"

	"github.com/miekg/dns"
)

// parsedFile holds the per-file cached parse result and the mtime that produced it.
type parsedFile struct {
	cachedAt    time.Time
	ipToName    map[string]string
	macToName   map[string]string
	nameToIPs   map[string][]net.IP
	arpaToNames map[string][]string
	seen        map[string]bool
}

var (
	identMu sync.RWMutex

	_ipToName    = make(map[string]string)
	_macToName   = make(map[string]string)
	_nameToIPs   = make(map[string][]net.IP)
	_arpaToNames = make(map[string][]string)

	fileCache = make(map[string]*parsedFile)
)

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

// LookupNameByMACOrIP returns the short hostname for a client, trying MAC first
// then IP under a single identMu.RLock. Use this instead of calling LookupNameByMAC
// and LookupNameByIP separately — it halves the mutex round-trips on the query
// hot path from two RLock/RUnlock cycles to one.
//
// mac may be empty (e.g. on non-Linux builds where ARP is unavailable) — the
// function falls through cleanly to the IP lookup in that case.
func LookupNameByMACOrIP(mac, ip string) string {
	identMu.RLock()
	defer identMu.RUnlock()
	if mac != "" {
		if name := _macToName[mac]; name != "" {
			return name
		}
	}
	return _ipToName[ip]
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
// Single RLock for the entire walk — the critical section is pure CPU (map
// lookups only, no I/O or blocking). Reduces lock overhead from O(labels) to O(1).
func LookupIPsBySuffix(qname string) []net.IP {
	identMu.RLock()
	defer identMu.RUnlock()

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
		if ips := _nameToIPs[search]; len(ips) > 0 {
			return ips
		}
	}
	return nil
}

// LookupNamesByARPA returns all hostnames for an ARPA string. O(1).
func LookupNamesByARPA(arpa string) []string {
	identMu.RLock()
	names := _arpaToNames[arpa]
	identMu.RUnlock()
	return names
}

func pollIdentity() {
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

