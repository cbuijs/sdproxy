/*
File:    identity.go
Version: 2.9.0
Updated: 02-May-2026 11:28 CEST

Description: 
  Local client identity resolution from hosts files, DHCP leases, and IPinfo ASN databases.
  Extracted parsing rules into identity_parsers.go.

Changes:
  2.9.0  - [FIX] Addressed an internal deduplication loop flaw in `mergePartial` 
           that failed to evaluate dynamic array growth, eliminating edge-case 
           duplicate A/AAAA/PTR responses inflating DNS payloads.
  2.8.0  - [FIX/PERF] Resolved a payload inflation regression in `mergePartial`. 
           IP addresses and ARPA hostnames mapping to the same identity across 
           multiple configuration sources are now strictly deduplicated natively.
  2.7.0  - [LOGGING] Added verbose logging to clearly indicate when identity 
           files are actively being loaded and parsed from disk.
  2.6.0  - [FIX] Addressed a memory leak where `fileCache` retained parsed Hosts and DHCP 
           lease files indefinitely even after they were removed from the active `config.yaml`.
*/

package main

import (
	"bytes"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	kindHosts   = "hosts"
	kindDnsmasq = "dnsmasq"
	kindIsc     = "isc"
	kindKea     = "kea"
	kindOdhcpd  = "odhcpd"
)

type identitySnapshot struct {
	ipToName    map[string]string
	macToName   map[string]string
	nameToIPs   map[string][]netip.Addr
	arpaToNames map[string][]string
}

// identSnap holds the active, lock-free routing and identity tables dynamically 
// mapped from the system's DHCP and Hosts configurations.
var identSnap atomic.Pointer[identitySnapshot]

func init() {
	identSnap.Store(&identitySnapshot{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string),
		nameToIPs:   make(map[string][]netip.Addr),
		arpaToNames: make(map[string][]string),
	})
}

type parsedFile struct {
	cachedAt    time.Time
	ipToName    map[string]string
	macToName   map[string]string
	nameToIPs   map[string][]netip.Addr
	arpaToNames map[string][]string
	seen        map[string]bool
}

// fileCache prevents redundant parsing operations by retaining the processed struct 
// in memory unless the underlying file's Last-Modified-Time changes natively.
var fileCache = make(map[string]*parsedFile)

// InitIdentity synchronizes the parsing and allocation of all Identity data sources.
func InitIdentity() {
	InitASN()

	if len(cfg.Identity.HostsFiles) == 0 &&
		len(cfg.Identity.DnsmasqLeases) == 0 &&
		len(cfg.Identity.IscLeases) == 0 &&
		len(cfg.Identity.KeaLeases) == 0 &&
		len(cfg.Identity.OdhcpdLeases) == 0 {
		log.Println("[IDENTITY] No local lease/hosts files configured — local identity resolution disabled.")
		return
	}

	totalLeases := len(cfg.Identity.DnsmasqLeases) +
		len(cfg.Identity.IscLeases) +
		len(cfg.Identity.KeaLeases) +
		len(cfg.Identity.OdhcpdLeases)

	pollInterval := cfg.Identity.PollInterval

	if pollInterval == 0 {
		log.Printf("[IDENTITY] Initialising: %d hosts file(s), %d lease file(s) "+
			"(dnsmasq:%d isc:%d kea:%d odhcpd:%d), loading ONCE at startup (poll_interval: 0)",
			len(cfg.Identity.HostsFiles), totalLeases,
			len(cfg.Identity.DnsmasqLeases), len(cfg.Identity.IscLeases),
			len(cfg.Identity.KeaLeases), len(cfg.Identity.OdhcpdLeases))

		pollIdentity()
		return
	}

	// Floor constraint to prevent CPU and I/O starvation from hyper-polling
	if pollInterval < 0 {
		pollInterval = 30 
	} else if pollInterval < 5 {
		pollInterval = 5  
	}

	interval := time.Duration(pollInterval) * time.Second

	log.Printf("[IDENTITY] Initialising: %d hosts file(s), %d lease file(s) "+
		"(dnsmasq:%d isc:%d kea:%d odhcpd:%d), poll interval: %s",
		len(cfg.Identity.HostsFiles), totalLeases,
		len(cfg.Identity.DnsmasqLeases), len(cfg.Identity.IscLeases),
		len(cfg.Identity.KeaLeases), len(cfg.Identity.OdhcpdLeases),
		interval)

	pollIdentity() // Ensure synchronous population before listeners start

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			pollIdentity()
		}
	}()
}

// LookupNameByMACOrIP prioritizes physical hardware address identification,
// securely falling back to dynamic IP allocations if the MAC is unknown.
func LookupNameByMACOrIP(mac, ip string) string {
	snap := identSnap.Load()
	if mac != "" {
		if name := snap.macToName[mac]; name != "" {
			return name
		}
	}
	return snap.ipToName[ip]
}

// LookupIPsByNameLower resolves localized subdomains directly into mapped `netip.Addr` structures.
func LookupIPsByNameLower(name string) ([]netip.Addr, string) {
	snap := identSnap.Load()

	if addrs := snap.nameToIPs[name]; len(addrs) > 0 {
		return addrs, name
	}

	search := name
	for {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]

		if addrs := snap.nameToIPs[search]; len(addrs) > 0 {
			for _, a := range addrs {
				if a.IsUnspecified() {
					return addrs, search
				}
			}
		}
	}

	return nil, ""
}

// LookupNamesByARPA natively retrieves hostname targets bound to local PTR blocks.
func LookupNamesByARPA(arpa string) []string {
	return identSnap.Load().arpaToNames[arpa]
}

// pollIdentity acts as the master orchestrator for evaluating, processing, 
// and atomically swapping the local identity tables at runtime.
func pollIdentity() {
	prev := identSnap.Load()
	hint := len(prev.ipToName) + 8

	freshIP   := make(map[string]string,       hint)
	freshMAC  := make(map[string]string,       hint)
	freshName := make(map[string][]netip.Addr, hint)
	freshARPA := make(map[string][]string,     hint)

	anyChanged := false
	activePaths := make(map[string]bool)

	for _, path := range cfg.Identity.HostsFiles {
		activePaths[path] = true
		pf, changed := getOrParse(path, kindHosts)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.DnsmasqLeases {
		activePaths[path] = true
		pf, changed := getOrParse(path, kindDnsmasq)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.IscLeases {
		activePaths[path] = true
		pf, changed := getOrParse(path, kindIsc)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.KeaLeases {
		activePaths[path] = true
		pf, changed := getOrParse(path, kindKea)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.OdhcpdLeases {
		activePaths[path] = true
		pf, changed := getOrParse(path, kindOdhcpd)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}

	// [SECURITY/PERF] Garbage Collection: Prune removed tracking files from the cache
	for path := range fileCache {
		if !activePaths[path] {
			delete(fileCache, path)
			anyChanged = true
			log.Printf("[IDENTITY] Garbage collected removed file source: %s", path)
		}
	}

	if !anyChanged {
		return
	}

	if cleanedNames := filterNullIPs(freshName, freshARPA); len(cleanedNames) > 0 {
		log.Printf("[IDENTITY] Cleaned %d hostnames: removed NULL-IPs (0.0.0.0 or ::) because valid alternate IPs were present: %s",
			len(cleanedNames), strings.Join(cleanedNames, ", "))
	}

	identSnap.Store(&identitySnapshot{
		ipToName:    freshIP,
		macToName:   freshMAC,
		nameToIPs:   freshName,
		arpaToNames: freshARPA,
	})

	log.Printf("[IDENTITY] Maps rebuilt: %d IPs, %d MACs, %d hostnames, %d PTR records",
		len(freshIP), len(freshMAC), len(freshName), len(freshARPA))
}

// getOrParse safely evaluates file modification bounds natively to restrict disk operations.
func getOrParse(path, kind string) (*parsedFile, bool) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("[IDENTITY] Cannot stat %s: %v — skipping", path, err)
		return nil, false
	}
	mtime := info.ModTime()

	if cached, ok := fileCache[path]; ok && cached.cachedAt.Equal(mtime) {
		return cached, false
	}

	log.Printf("[IDENTITY] Loading/Parsing modified %s file: %s", kind, path)

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[IDENTITY] Cannot read %s: %v — skipping", path, err)
		return nil, false
	}

	var pf *parsedFile
	switch kind {
	case kindDnsmasq:
		pf = parseDnsmasqLeasesBytes(data)
	case kindIsc:
		pf = parseIscLeasesBytes(data)
	case kindKea:
		pf = parseKeaLeasesBytes(data)
	case kindOdhcpd:
		pf = parseOdhcpdLeasesBytes(data)
	default: 
		pf = parseHostsBytes(data)
	}
	pf.cachedAt = mtime
	fileCache[path] = pf

	log.Printf("[IDENTITY] Parsed %s file %s: %d IPs, %d MACs, %d hostnames",
		kind, path, len(pf.ipToName), len(pf.macToName), len(pf.nameToIPs))
	return pf, true
}

// mergePartial incorporates parsed data sources into the comprehensive global map,
// employing robust deduplication across files to prevent Answer inflation loops.
func mergePartial(
	pf       *parsedFile,
	freshIP   map[string]string,
	freshMAC  map[string]string,
	freshName map[string][]netip.Addr,
	freshARPA map[string][]string,
) {
	for k, v := range pf.ipToName {
		freshIP[k] = v
	}
	for k, v := range pf.macToName {
		freshMAC[k] = v
	}
	
	for k, v := range pf.nameToIPs {
		// [FIX] Deduplicate cross-file IPs natively to prevent bloated Answer sections.
		// Evaluates against the dynamically expanding `freshName` slice to ensure newly 
		// injected intra-file duplicates are correctly intercepted.
		if _, ok := freshName[k]; ok {
			for _, newAddr := range v {
				isDup := false
				for _, exAddr := range freshName[k] {
					if exAddr == newAddr {
						isDup = true
						break
					}
				}
				if !isDup {
					freshName[k] = append(freshName[k], newAddr)
				}
			}
		} else {
			// Allocate a fresh slice to guarantee clean memory bounds
			freshName[k] = append([]netip.Addr(nil), v...) 
		}
	}
	
	for k, v := range pf.arpaToNames {
		// Maintain parity by deduplicating structural Reverse Resolution PTR records natively.
		if _, ok := freshARPA[k]; ok {
			for _, newName := range v {
				isDup := false
				for _, exName := range freshARPA[k] {
					if exName == newName {
						isDup = true
						break
					}
				}
				if !isDup {
					freshARPA[k] = append(freshARPA[k], newName)
				}
			}
		} else {
			freshARPA[k] = append([]string(nil), v...)
		}
	}
}

func newParsedFile() *parsedFile {
	return &parsedFile{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string),
		nameToIPs:   make(map[string][]netip.Addr),
		arpaToNames: make(map[string][]string),
		seen:        make(map[string]bool),
	}
}

func isSinkAddr(a netip.Addr) bool {
	return a.IsUnspecified() || a.IsLoopback()
}

func storeEntry(ip, rawName string, pf *parsedFile) string {
	parsedAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	parsedAddr = parsedAddr.Unmap()

	// [PERF] Filter entry based on global SupportIPVersion setting to save memory.
	if ipVersionSupport != "both" {
		if ipVersionSupport == "ipv4" && !parsedAddr.Is4() {
			return ""
		}
		if ipVersionSupport == "ipv6" && !parsedAddr.Is6() {
			return ""
		}
	}

	shortName := rawName
	if idx := strings.IndexByte(rawName, '.'); idx > 0 {
		shortName = rawName[:idx]
	}

	sink    := isSinkAddr(parsedAddr)
	fullKey := strings.ToLower(rawName)

	dedupKey := fullKey + "|" + ip
	if !pf.seen[dedupKey] {
		pf.seen[dedupKey] = true
		pf.nameToIPs[fullKey] = append(pf.nameToIPs[fullKey], parsedAddr)

		if arpa, err := dns.ReverseAddr(ip); err == nil {
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

func filterNullIPs(nameToIPs map[string][]netip.Addr, arpaToNames map[string][]string) []string {
	var cleaned []string

	for name, addrs := range nameToIPs {
		if len(addrs) <= 1 {
			continue
		}

		hasNull, hasValid := false, false
		for _, a := range addrs {
			if a.IsUnspecified() {
				hasNull = true
			} else {
				hasValid = true
			}
		}
		if !hasNull || !hasValid {
			continue
		}

		filtered  := make([]netip.Addr, 0, len(addrs))
		nullARPAs := make([]string, 0, 2)
		for _, a := range addrs {
			if a.IsUnspecified() {
				if arpa, err := dns.ReverseAddr(a.String()); err == nil {
					nullARPAs = append(nullARPAs, arpa[:len(arpa)-1])
				}
			} else {
				filtered = append(filtered, a)
			}
		}
		nameToIPs[name] = filtered

		for _, arpaKey := range nullARPAs {
			names := arpaToNames[arpaKey]
			kept  := names[:0]
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

