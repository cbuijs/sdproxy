/*
File:    identity.go
Version: 1.27.0
Updated: 2026-03-12 20:00 CET

Description:
  Parses /etc/hosts and DHCP lease files (dnsmasq, ISC DHCP, Kea DHCP4,
  odhcpd) to extract short hostnames for {client-name} substitution and
  local A/AAAA/PTR resolution.

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

  SUPPORTED LEASE FORMATS:
    dnsmasq  — one record per line, space-separated:
                 <expiry> <mac> <ip> <hostname> <clientid>
                 Common file: /tmp/dhcp.leases, /var/lib/misc/dnsmasq.leases

    ISC DHCP — block-structured (dhcpd.leases). Only leases with
                 "binding state active" or "binding state static" are imported.
                 ISC appends new blocks for the same IP over time; the last
                 active block wins, which matches ISC DHCP's own behaviour.
                 Common file: /var/lib/dhcp/dhcpd.leases

    Kea DHCP4 — CSV file with a header row. Only state=0 (active) rows are
                 imported. Trailing FQDN dot in the hostname field is stripped.
                 Common file: /var/lib/kea/kea-leases4.csv

    odhcpd   — state file written by the OpenWrt DHCPv4/DHCPv6/RA daemon.
                 Data lines start with '#'; format per line:
                   # <iface> <mac-or-duid> <iaid> <hostname> <ttl> [<ip/plen>...]
                 DHCPv4 MAC is colon-separated; DHCPv6 DUID is plain hex.
                 Hostname '-' means no name was supplied — entry is skipped.
                 IP addresses include a prefix-length suffix (/32, /128) that
                 is stripped before parsing.
                 NOTE: On a standard OpenWrt dnsmasq+odhcpd setup, odhcpd
                 writes /tmp/hosts/odhcpd in hosts format (already supported
                 via hosts_files). Point odhcp_leases at the internal state
                 file only when running odhcpd standalone (no dnsmasq).
                 Common file: /var/lib/odhcpd/dhcp.leases,
                              /tmp/odhcpd/dhcp.leases

Changes:
  1.27.0 - [FEAT] parseOdhcpdLeasesBytes: new parser for the odhcpd internal
           state file. Lines beginning with '#' are the data records. Format:
           '# <iface> <mac/duid> <iaid> <hostname> <remaining-secs> [<ip/plen>...]'
           MAC (colon-separated) is stored in macToName; DUID-only entries
           (no-colon hex strings) have no MAC but their IPs are still stored.
           IP/prefix-length pairs are split on '/' before net.ParseIP.
           Hostname '-' is treated as absent. kindOdhcpd constant added.
           [FEAT] parseIscLeasesBytes: new parser for ISC DHCP block-structured
           lease files (/var/lib/dhcp/dhcpd.leases etc.). Handles active/static/
           free/expired/released/abandoned binding states; only active+static are
           imported. Last active block for a given IP wins (ISC append semantics).
           [FEAT] parseKeaLeasesBytes: new parser for Kea DHCP4 CSV lease files
           (/var/lib/kea/kea-leases4.csv etc.). Skips header row, imports only
           state=0 (active) rows, strips trailing FQDN dot from hostname field.
           [FEAT] getOrParse signature changed from (path string, isLeases bool)
           to (path, kind string) using named constants kindHosts / kindDnsmasq /
           kindIsc / kindKea / kindOdhcpd — dispatch is a simple switch, easy
           to extend with future formats.
           [FEAT] pollIdentity now iterates cfg.Identity.IscLeases,
           cfg.Identity.KeaLeases, and cfg.Identity.OdhcpdLeases in addition
           to HostsFiles and DnsmasqLeases.
           [FEAT] InitIdentity early-return guard and startup log now cover all
           five file-list slices. newParsedFile() helper added to deduplicate
           map initialisation across all four parsers.
  1.26.0 - [FIX] parseHostsBytes: now processes ALL hostname tokens per line.
           [FIX] parseHostsBytes: inline # comments are now stripped.
           [FIX] filterNullIPs: now also cleans arpaToNames for removed NULL-IPs.
  1.25.1 - [LOG] filterNullIPs now returns and logs the specific list of
           cleaned hostnames.
  1.25.0 - [FEAT] filterNullIPs: removes NULL-IPs when valid alternates exist.
  1.24.0 - [PERF] LookupIPsByNameLower: skips strings.ToLower when already lower.
  1.23.0 - [PERF] storeEntry: dropped redundant ToLower on ARPA key; returns
           shortName to avoid a duplicate dot-search in parseLeasesBytes.
  1.22.0 - [PERF] Replaced sync.RWMutex + 4 global maps with atomic.Pointer to
           an immutable identitySnapshot struct.
  1.21.0 - [PERF] LookupNameByMACOrIP: combined MAC+IP under single RLock.
  1.20.0 - [PERF] LookupIPsBySuffix: single RLock for entire suffix walk.
  1.19.0 - [FEAT] Poll interval configurable via identity.poll_interval.
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

// ---------------------------------------------------------------------------
// File-kind constants — passed to getOrParse to select the right parser.
// Adding a new format: add a constant here and a case in getOrParse's switch.
// ---------------------------------------------------------------------------

const (
	kindHosts   = "hosts"
	kindDnsmasq = "dnsmasq"
	kindIsc     = "isc"
	kindKea     = "kea"
	kindOdhcpd  = "odhcpd"
)

// ---------------------------------------------------------------------------
// Snapshot & maps
// ---------------------------------------------------------------------------

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
// Writer:  identSnap.Store() — called only from the pollIdentity goroutine.
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

// ---------------------------------------------------------------------------
// Initialisation & polling
// ---------------------------------------------------------------------------

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

// InitIdentity starts the background polling goroutine that keeps all identity
// maps fresh. Called once from main() after config is loaded.
func InitIdentity() {
	if len(cfg.Identity.HostsFiles) == 0 &&
		len(cfg.Identity.DnsmasqLeases) == 0 &&
		len(cfg.Identity.IscLeases) == 0 &&
		len(cfg.Identity.KeaLeases) == 0 &&
		len(cfg.Identity.OdhcpdLeases) == 0 {
		log.Println("[IDENTITY] No files configured — local identity resolution disabled.")
		return
	}

	totalLeases := len(cfg.Identity.DnsmasqLeases) +
		len(cfg.Identity.IscLeases) +
		len(cfg.Identity.KeaLeases) +
		len(cfg.Identity.OdhcpdLeases)

	interval := identityPollInterval()
	log.Printf("[IDENTITY] Initialising: %d hosts file(s), %d lease file(s) "+
		"(dnsmasq:%d isc:%d kea:%d odhcpd:%d), poll interval: %s",
		len(cfg.Identity.HostsFiles), totalLeases,
		len(cfg.Identity.DnsmasqLeases), len(cfg.Identity.IscLeases),
		len(cfg.Identity.KeaLeases), len(cfg.Identity.OdhcpdLeases),
		interval)

	go func() {
		pollIdentity()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			pollIdentity()
		}
	}()
}

// ---------------------------------------------------------------------------
// Public lookup helpers — all lock-free via atomic snapshot load
// ---------------------------------------------------------------------------

// LookupNameByIP returns the short hostname for a given IP string, if known.
func LookupNameByIP(ip string) (string, bool) {
	name := identSnap.Load().ipToName[ip]
	return name, name != ""
}

// LookupNameByMAC returns the short hostname for a normalised MAC, if known.
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
// already normalised via lowerTrimDot, use LookupIPsByNameLower instead.
func LookupIPsByName(name string) []net.IP {
	return identSnap.Load().nameToIPs[strings.ToLower(name)]
}

// LookupIPsByNameLower is identical to LookupIPsByName but skips the
// strings.ToLower call. Only call this when name is already lowercase — e.g.
// after lowerTrimDot in ProcessDNS.
func LookupIPsByNameLower(name string) []net.IP {
	return identSnap.Load().nameToIPs[name]
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

// ---------------------------------------------------------------------------
// Poll & merge
// ---------------------------------------------------------------------------

func pollIdentity() {
	// Pre-size new maps using the previous snapshot as a hint.
	prev := identSnap.Load()
	hint := len(prev.ipToName) + 8

	freshIP   := make(map[string]string,   hint)
	freshMAC  := make(map[string]string,   hint)
	freshName := make(map[string][]net.IP, hint)
	freshARPA := make(map[string][]string, hint)

	anyChanged := false

	for _, path := range cfg.Identity.HostsFiles {
		pf, changed := getOrParse(path, kindHosts)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.DnsmasqLeases {
		pf, changed := getOrParse(path, kindDnsmasq)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.IscLeases {
		pf, changed := getOrParse(path, kindIsc)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.KeaLeases {
		pf, changed := getOrParse(path, kindKea)
		if changed {
			anyChanged = true
		}
		if pf != nil {
			mergePartial(pf, freshIP, freshMAC, freshName, freshARPA)
		}
	}
	for _, path := range cfg.Identity.OdhcpdLeases {
		pf, changed := getOrParse(path, kindOdhcpd)
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

	// Filter out NULL IPs (0.0.0.0 or ::) from hostnames that also have valid
	// IPs — cleanly overrides generic blocklists with local redirects.
	// Also cleans arpaToNames to keep reverse lookups consistent (fix v1.26.0).
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

// ---------------------------------------------------------------------------
// File reading helper — mtime cache + parser dispatch
// ---------------------------------------------------------------------------

// getOrParse stats the file first. When the mtime matches the cached entry the
// cached parsedFile is returned as-is. Otherwise the file is read and handed to
// the parser selected by kind. Second return value is true when a fresh parse
// actually happened (used to decide whether to rebuild the snapshot).
func getOrParse(path, kind string) (*parsedFile, bool) {
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
	default: // kindHosts
		pf = parseHostsBytes(data)
	}
	pf.cachedAt = mtime
	fileCache[path] = pf

	log.Printf("[IDENTITY] Parsed %s file %s: %d IPs, %d MACs, %d hostnames",
		kind, path, len(pf.ipToName), len(pf.macToName), len(pf.nameToIPs))
	return pf, true
}

// mergePartial copies one parsedFile's maps into the four fresh accumulator maps.
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

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// parseHostsBytes parses a hosts-file byte slice into a parsedFile.
//
// BUG FIX (v1.26.0 — two fixes):
//  1. ALL hostname tokens per line are now processed, not just the first.
//     Standard /etc/hosts allows multiple space-separated aliases on one line:
//       192.168.1.100  mydevice  mydevice.local  mydevice.lan
//     Previously only "mydevice" would be stored; aliases were silently dropped.
//  2. Inline comments (everything from the first '#' to end-of-line) are now
//     stripped before name parsing. Previously "1.2.3.4 router # main gateway"
//     would store "#" as a valid hostname, corrupting nameToIPs/arpaToNames.
func parseHostsBytes(data []byte) *parsedFile {
	pf := newParsedFile()

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimLeft(line, " \t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Strip inline comment.
		if ci := bytes.IndexByte(line, '#'); ci >= 0 {
			line = bytes.TrimRight(line[:ci], " \t")
		}
		if len(line) == 0 {
			continue
		}

		// First token is the IP address.
		ipEnd := bytes.IndexAny(line, " \t")
		if ipEnd < 0 {
			continue
		}
		ipStr := string(line[:ipEnd])
		line = bytes.TrimLeft(line[ipEnd:], " \t")

		// All remaining tokens are hostnames/aliases — store every one.
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

// parseDnsmasqLeasesBytes parses a dnsmasq lease file into a parsedFile.
//
// dnsmasq lease format — one record per line, five space-separated fields:
//   <expiry-epoch>  <mac>  <ip>  <hostname>  <client-id>
//
// Example:
//   1710000000 aa:bb:cc:dd:ee:ff 192.168.1.42 mylaptop 01:aa:bb:cc:dd:ee:ff
//
// Common file locations:
//   /var/lib/misc/dnsmasq.leases         OpenWRT, most Linux distros
//   /tmp/dhcp.leases                     OpenWRT (tmpfs, lost on reboot)
//   /var/lib/dnsmasq/dnsmasq.leases      Debian/Ubuntu with custom --dhcp-leasefile
//   /etc/dnsmasq.d/dnsmasq.leases        Some minimal embedded distros
func parseDnsmasqLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// Fields: [0]=expiry [1]=mac [2]=ip [3]=hostname [4]=clientid
		fields := bytes.Fields(line)
		if len(fields) < 4 {
			continue
		}

		nameBytes := fields[3]
		if len(nameBytes) == 0 || bytes.Equal(nameBytes, []byte("*")) {
			continue // hostname not provided by DHCP client
		}

		shortName := storeEntry(string(fields[2]), string(nameBytes), pf)
		if shortName == "" {
			continue // malformed IP — skip MAC too
		}

		if mac, err := net.ParseMAC(string(fields[1])); err == nil {
			pf.macToName[mac.String()] = shortName
		}
	}
	return pf
}

// parseIscLeasesBytes parses an ISC DHCP lease database into a parsedFile.
//
// ISC DHCP lease format — block-structured, one lease per {} block:
//
//   lease 192.168.1.42 {
//     starts 1 2024/01/15 10:00:00;
//     ends   1 2024/01/15 22:00:00;
//     binding state active;
//     next binding state free;
//     hardware ethernet aa:bb:cc:dd:ee:ff;
//     uid "\001\xaa\xbb\xcc\xdd\xee\xff";
//     client-hostname "mylaptop";
//   }
//
// Important details:
//   - ISC DHCP appends new lease blocks for the same IP as clients renew.
//     The last *active* block in the file is authoritative for that IP,
//     matching the behaviour of the ISC daemon itself.
//   - Only "binding state active" and "binding state static" leases are
//     imported. States free/expired/released/abandoned are skipped.
//   - A lease block without a "client-hostname" line is silently ignored.
//
// Common file locations:
//   /var/lib/dhcp/dhcpd.leases           Debian/Ubuntu
//   /var/lib/dhcpd/dhcpd.leases          RHEL/CentOS/Fedora
//   /var/db/dhcpd.leases                 FreeBSD/pfSense/OPNsense
//   /var/state/dhcp/dhcpd.leases         Some OpenWRT builds with ISC DHCP
//   /etc/dhcpd.leases                    Legacy / minimal installs
func parseIscLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()

	var (
		inLease     bool
		leaseIP     string
		leaseMAC    string
		leaseName   string
		leaseActive bool
	)

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if !inLease {
			// Looking for "lease <ip> {" — start of a new block.
			if !bytes.HasPrefix(line, []byte("lease ")) {
				continue
			}
			after := line[len("lease "):]
			end := bytes.IndexByte(after, ' ')
			if end < 0 {
				continue
			}
			leaseIP     = string(after[:end])
			leaseMAC    = ""
			leaseName   = ""
			leaseActive = false
			inLease     = true
			continue
		}

		// --- inside a lease block ---

		// Closing brace — commit the block if it's active and has a hostname.
		if bytes.Equal(line, []byte("}")) {
			if leaseActive && leaseName != "" {
				shortName := storeEntry(leaseIP, leaseName, pf)
				if shortName != "" && leaseMAC != "" {
					if mac, err := net.ParseMAC(leaseMAC); err == nil {
						// Last active block wins for the same IP (ISC append semantics).
						pf.macToName[mac.String()] = shortName
					}
				}
			}
			inLease = false
			continue
		}

		// "binding state active;"  /  "binding state static;"  /  etc.
		if bytes.HasPrefix(line, []byte("binding state ")) {
			state := bytes.TrimSuffix(line[len("binding state "):], []byte(";"))
			leaseActive = bytes.Equal(state, []byte("active")) ||
				bytes.Equal(state, []byte("static"))
			continue
		}

		// "hardware ethernet aa:bb:cc:dd:ee:ff;"
		if bytes.HasPrefix(line, []byte("hardware ethernet ")) {
			mac := bytes.TrimSuffix(line[len("hardware ethernet "):], []byte(";"))
			leaseMAC = string(bytes.TrimSpace(mac))
			continue
		}

		// `client-hostname "mylaptop";`
		if bytes.HasPrefix(line, []byte("client-hostname ")) {
			name := line[len("client-hostname "):]
			name = bytes.TrimSuffix(name, []byte(";"))
			name = bytes.Trim(name, `"`)
			leaseName = string(bytes.TrimSpace(name))
			continue
		}
	}
	return pf
}

// parseKeaLeasesBytes parses a Kea DHCP4 CSV lease file into a parsedFile.
//
// Kea stores DHCP4 leases as a CSV file with a required header row. Column
// positions are fixed. Only state=0 (active) rows are imported.
//
// CSV column layout (0-indexed):
//   0  address          — IPv4 address
//   1  hwaddr           — MAC address (colon-separated)
//   2  client_id        — DHCP option 61 (ignored)
//   3  valid_lifetime   — lease duration in seconds
//   4  expire           — Unix timestamp of expiry
//   5  subnet_id
//   6  fqdn_fwd         — whether DDNS forward update was done
//   7  fqdn_rev         — whether DDNS reverse update was done
//   8  hostname         — client-supplied hostname (may be FQDN with trailing dot)
//   9  state            — 0=active, 1=declined, 2=expired-reclaimed
//  10  user_context     — arbitrary JSON (may contain commas — use SplitN)
//  11  pool_id
//
// Common file locations:
//   /var/lib/kea/kea-leases4.csv                 Default Kea install
//   /var/lib/kea/dhcp4.leases                    Alternative package name
//   /usr/local/var/lib/kea/kea-leases4.csv       FreeBSD ports / pkgsrc
//   /run/kea/kea-leases4.csv                     Containers / minimal setups
//   /etc/kea/leases4.csv                         Custom path via kea-dhcp4.conf:
//                                                  "lease-database": {
//                                                    "type": "memfile",
//                                                    "name": "/etc/kea/leases4.csv"
//                                                  }
func parseKeaLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()

	firstLine := true
	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// Skip the mandatory header row (starts with "address,").
		if firstLine {
			firstLine = false
			if bytes.HasPrefix(line, []byte("address,")) {
				continue
			}
		}

		// SplitN into 11 parts so user_context (col 10) with embedded commas
		// is captured as a single remainder and doesn't mis-shift later cols.
		fields := bytes.SplitN(line, []byte(","), 11)
		if len(fields) < 10 {
			continue
		}

		addrBytes  := bytes.TrimSpace(fields[0])
		macBytes   := bytes.TrimSpace(fields[1])
		nameBytes  := bytes.TrimSpace(fields[8])
		stateBytes := bytes.TrimSpace(fields[9])

		// Only import active leases (state == "0").
		if !bytes.Equal(stateBytes, []byte("0")) {
			continue
		}
		if len(nameBytes) == 0 {
			continue
		}

		// Kea sometimes writes FQDNs with a trailing dot — strip it.
		nameStr := string(bytes.TrimSuffix(nameBytes, []byte(".")))

		shortName := storeEntry(string(addrBytes), nameStr, pf)
		if shortName != "" && len(macBytes) > 0 {
			if mac, err := net.ParseMAC(string(macBytes)); err == nil {
				pf.macToName[mac.String()] = shortName
			}
		}
	}
	return pf
}

// parseOdhcpdLeasesBytes parses an odhcpd internal state file into a parsedFile.
//
// odhcpd is the OpenWrt DHCP/DHCPv6/RA daemon. When running standalone (without
// dnsmasq) it maintains an internal lease state file. Data lines start with '#'
// — this is intentional and not a comment marker in this format.
//
// Line format:
//   # <ifname> <mac-or-duid> <iaid> <hostname> <remaining-secs> [<ip/plen> ...]
//
// Field details:
//   ifname        — network interface (e.g. "br-lan") — not used here
//   mac-or-duid   — for DHCPv4: colon-separated MAC (e.g. "1c:69:7a:65:b4:ae")
//                   for DHCPv6: hex DUID without separators (e.g. "0003000100aabbcc...")
//   iaid          — DHCP Identity Association ID (integer, typically 0 for v4)
//   hostname      — client-supplied hostname; "-" means none provided — skip
//   remaining-secs — seconds until expiry (may be 0 for expired entries)
//   ip/plen       — one or more IP addresses with prefix length (e.g.
//                   "192.168.1.42/32", "fd12:3456:789a::1/128"). The /plen
//                   suffix is stripped before parsing.
//
// NOTE on standard OpenWrt dnsmasq+odhcpd setups:
//   odhcpd writes /tmp/hosts/odhcpd in standard hosts format for dnsmasq to
//   read. That file is already handled by parseHostsBytes via hosts_files.
//   Point odhcp_leases at the internal state file only when running odhcpd
//   standalone (no dnsmasq), where dnsmasq integration does not apply.
//
// Common file locations:
//   /var/lib/odhcpd/dhcp.leases    Default when odhcpd writes its state file
//   /tmp/odhcpd/dhcp.leases        tmpfs variant (lost on reboot)
//
// UCI configuration for the state file path (/etc/config/dhcp):
//   config odhcpd 'odhcpd'
//     option leasefile '/tmp/hosts/odhcpd'       # hosts format — use hosts_files
//     # To get the internal state file, configure a leasetrigger script
//     # or check the path odhcpd was started with (-S flag).
func parseOdhcpdLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)

		// odhcpd state files use '#' as the DATA line prefix, not as a comment.
		// Lines that do NOT start with '#' are structural (e.g. blank lines,
		// future format extensions) and are skipped.
		if len(line) == 0 || line[0] != '#' {
			continue
		}

		// Strip the leading '#' and re-split the remainder into fields.
		// Expected layout after '#':
		//   [0]=ifname [1]=mac/duid [2]=iaid [3]=hostname [4]=remaining [5..]=ip/plen
		fields := bytes.Fields(line[1:])
		if len(fields) < 6 {
			continue // need at least iface mac iaid name ttl one-addr
		}

		nameBytes := fields[3]
		if len(nameBytes) == 0 || bytes.Equal(nameBytes, []byte("-")) {
			continue // no hostname provided by this client
		}

		macOrDUID := string(fields[1])
		hostname  := string(nameBytes)

		// Try each address field (index 5 onwards). Each looks like "ip/prefixlen".
		// We strip the /prefixlen and parse just the IP.
		var shortName string
		for _, addrField := range fields[5:] {
			ipStr := string(addrField)

			// Strip /prefixlen suffix if present.
			if slash := bytes.IndexByte(addrField, '/'); slash >= 0 {
				ipStr = string(addrField[:slash])
			}

			sn := storeEntry(ipStr, hostname, pf)
			if sn != "" && shortName == "" {
				shortName = sn // keep the shortName from the first valid IP
			}
		}

		// Only try to store the MAC entry when at least one IP was valid.
		// DHCPv4 MACs are colon-separated and parse cleanly with net.ParseMAC.
		// DHCPv6 DUIDs are plain hex — net.ParseMAC will reject them, which is
		// correct (we have no IP↔MAC mapping to offer for DUID-only clients).
		if shortName != "" {
			if mac, err := net.ParseMAC(macOrDUID); err == nil {
				pf.macToName[mac.String()] = shortName
			}
		}
	}
	return pf
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

// newParsedFile allocates a parsedFile with all maps initialised.
// Keeps the map-init boilerplate in one place across all parsers.
func newParsedFile() *parsedFile {
	return &parsedFile{
		ipToName:    make(map[string]string),
		macToName:   make(map[string]string),
		nameToIPs:   make(map[string][]net.IP),
		arpaToNames: make(map[string][]string),
		seen:        make(map[string]bool),
	}
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
// get nameToIPs and arpaToNames entries (so PTR and forward lookups work for
// ::1 / 127.0.0.1) but are excluded from ipToName (won't pollute client-name
// resolution with "localhost").
//
// ARPA key: dns.ReverseAddr always returns lowercase + trailing dot.
// Trailing dot is sliced off directly — strings.TrimSuffix is not needed.
func storeEntry(ip, rawName string, pf *parsedFile) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

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
			key := arpa[:len(arpa)-1] // always lowercase, strip trailing dot
			pf.arpaToNames[key] = append(pf.arpaToNames[key], rawName)
		}
	}

	if !sink {
		pf.ipToName[ip] = shortName
	}
	return shortName
}

// splitLine returns the bytes up to the first '\n' and the remainder.
// Handles both LF and CRLF line endings.
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
// and reverse lookups consistent (BUG FIX v1.26.0).
//
// Use case: a blocklist maps ads to 0.0.0.0, and a user adds a hosts entry
// mapping the same domain to a real local IP. filterNullIPs detects the mix,
// removes the 0.0.0.0 from both forward and reverse maps, leaving only the
// real IP visible to clients.
//
// Hostnames that ONLY map to NULL IPs are left untouched (the block is valid).
// Returns the distinct hostnames that had NULL-IPs pruned (for logging).
func filterNullIPs(nameToIPs map[string][]net.IP, arpaToNames map[string][]string) []string {
	var cleaned []string

	for name, ips := range nameToIPs {
		if len(ips) <= 1 {
			continue
		}

		hasNull, hasValid := false, false
		for _, ip := range ips {
			if ip.IsUnspecified() {
				hasNull = true
			} else {
				hasValid = true
			}
		}
		if !hasNull || !hasValid {
			continue
		}

		filtered  := make([]net.IP, 0, len(ips))
		nullARPAs := make([]string, 0, 2)
		for _, ip := range ips {
			if ip.IsUnspecified() {
				if arpa, err := dns.ReverseAddr(ip.String()); err == nil {
					nullARPAs = append(nullARPAs, arpa[:len(arpa)-1])
				}
			} else {
				filtered = append(filtered, ip)
			}
		}
		nameToIPs[name] = filtered

		// Remove this hostname from every null-IP ARPA key.
		// nameToIPs keys are always lowercase (storeEntry lowercases on insert),
		// so name is already lowercase here.
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

