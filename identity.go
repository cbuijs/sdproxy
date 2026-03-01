/*
File: identity.go
Version: 1.14.0
Last Updated: 2026-03-01 14:00 CET
Description: Parses /etc/hosts and dnsmasq lease files to extract short hostnames
             for {client-name} substitution and local A/AAAA/PTR resolution.

             KEY DESIGN: Builds four maps at poll time (ipToName, macToName,
             nameToIPs, arpaToNames) so that all query-time lookups in process.go
             are O(1) hash lookups instead of O(n) full-table scans.

             Single RWMutex covers all four maps; a full fresh-map rebuild each
             cycle auto-evicts stale entries for devices that changed IP or left.

Changes:
  1.14.0 - [PERF] Replaced sync.Map with RWMutex + plain maps (better for periodic
           full-rebuild pattern). Added nameToIPs and arpaToNames reverse maps,
           pre-computed at poll time, making resolveLocalIdentity and resolveLocalPTR
           in process.go O(1) instead of O(n). Full rebuild eliminates stale entries.
           [PERF] Replaced strings.Split(".")[0] with strings.IndexByte — zero alloc.
           [FEAT] Added storeEntry() helper to centralise all four map updates.
           [FEAT] Added dns.ReverseAddr pre-computation so PTR answers need no
           per-query iteration over the IP table.
  1.13.1 - Initial sync.Map version with O(n) scan approach.
*/

package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns" // for dns.ReverseAddr — pre-computes PTR keys at poll time
)

var (
	// identMu guards all four maps as a unit so the atomic swap in pollIdentity
	// is always consistent — readers never see a partially-rebuilt state.
	identMu sync.RWMutex

	// Forward maps
	_ipToName  = make(map[string]string) // "192.168.1.42"        -> "my-laptop"
	_macToName = make(map[string]string) // "aa:bb:cc:dd:ee:ff"   -> "my-laptop"

	// Reverse maps — pre-computed at poll time for O(1) query-time access.
	// Keyed by lowercase short hostname and lowercase ARPA string (no trailing dot).
	_nameToIPs   = make(map[string][]net.IP)   // "my-laptop" -> [192.168.1.42, ...]
	_arpaToNames = make(map[string][]string)   // "42.1.168.192.in-addr.arpa" -> ["my-laptop"]
)

func InitIdentity() {
	if len(cfg.Identity.HostsFiles) == 0 && len(cfg.Identity.DnsmasqLeases) == 0 {
		return
	}
	go func() {
		pollIdentity() // Immediate first run
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

// LookupIPsByName returns all IPs mapped to a given short hostname (case-insensitive).
// O(1) pre-computed lookup — replaces the O(n) ipNameMap.Range() scan.
func LookupIPsByName(name string) []net.IP {
	identMu.RLock()
	ips := _nameToIPs[strings.ToLower(name)]
	identMu.RUnlock()
	return ips
}

// LookupNamesByARPA returns all hostnames for a pre-formatted ARPA address string
// (lowercase, no trailing dot, e.g. "42.1.168.192.in-addr.arpa").
// O(1) pre-computed lookup — replaces the O(n) ipNameMap.Range() scan.
func LookupNamesByARPA(arpa string) []string {
	identMu.RLock()
	names := _arpaToNames[arpa]
	identMu.RUnlock()
	return names
}

// pollIdentity rebuilds all four maps from scratch then swaps them atomically.
// Fresh rebuild (vs incremental Store) is the only correct way to handle IP
// changes, lease renewals, and devices leaving — incremental maps accumulate
// stale entries indefinitely.
func pollIdentity() {
	freshIP   := make(map[string]string,   64)
	freshMAC  := make(map[string]string,   64)
	freshName := make(map[string][]net.IP, 64)
	freshARPA := make(map[string][]string, 64)

	for _, path := range cfg.Identity.HostsFiles {
		parseHostsFile(path, freshIP, freshName, freshARPA)
	}
	for _, path := range cfg.Identity.DnsmasqLeases {
		parseLeasesFile(path, freshIP, freshMAC, freshName, freshARPA)
	}

	identMu.Lock()
	_ipToName    = freshIP
	_macToName   = freshMAC
	_nameToIPs   = freshName
	_arpaToNames = freshARPA
	identMu.Unlock()
}

// storeEntry adds one IP/hostname pair to all three relevant maps (forward, reverse,
// and ARPA). Called from both parseHostsFile and parseLeasesFile to keep the
// map-update logic in one place.
func storeEntry(
	ip, shortName string,
	freshIP   map[string]string,
	freshName map[string][]net.IP,
	freshARPA map[string][]string,
) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}
	key := strings.ToLower(shortName)

	freshIP[ip] = shortName
	freshName[key] = append(freshName[key], parsedIP)

	// Pre-compute the ARPA key so PTR lookups in process.go require no iteration.
	// dns.ReverseAddr always appends a trailing dot — strip it for consistent keying.
	if arpa, err := dns.ReverseAddr(ip); err == nil {
		arpaKey := strings.TrimSuffix(strings.ToLower(arpa), ".")
		freshARPA[arpaKey] = append(freshARPA[arpaKey], shortName)
	}
}

// parseHostsFile reads standard /etc/hosts format: IP Hostname [Aliases...]
func parseHostsFile(
	path      string,
	freshIP   map[string]string,
	freshName map[string][]net.IP,
	freshARPA map[string][]string,
) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, rawName := fields[0], fields[1]

		// Zero-allocation short hostname extraction: "host.lan" -> "host"
		// strings.IndexByte avoids the []string slice that strings.Split allocates.
		shortName := rawName
		if idx := strings.IndexByte(rawName, '.'); idx > 0 {
			shortName = rawName[:idx]
		}

		storeEntry(ip, shortName, freshIP, freshName, freshARPA)
	}
}

// parseLeasesFile reads standard dnsmasq leases format:
//   ExpiryTime  MAC_Address  IP_Address  Hostname  Client_ID
func parseLeasesFile(
	path      string,
	freshIP   map[string]string,
	freshMAC  map[string]string,
	freshName map[string][]net.IP,
	freshARPA map[string][]string,
) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 4 {
			continue
		}
		macStr, ipStr, rawName := fields[1], fields[2], fields[3]

		if rawName == "*" || rawName == "" {
			continue
		}

		// Zero-allocation short hostname extraction
		shortName := rawName
		if idx := strings.IndexByte(rawName, '.'); idx > 0 {
			shortName = rawName[:idx]
		}

		storeEntry(ipStr, shortName, freshIP, freshName, freshARPA)

		// MAC->name mapping is only available in lease files, not /etc/hosts
		if parsedMAC, err := net.ParseMAC(macStr); err == nil {
			freshMAC[parsedMAC.String()] = shortName
		}
	}
}

