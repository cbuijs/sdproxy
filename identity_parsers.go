/*
File:    identity_parsers.go
Description:
  String and byte parsing for various hosts and lease formats.
  Extracted from identity.go to isolate formatting constraints.
  Supports hosts, dnsmasq, ISC DHCP, Kea, and odhcpd lease formats.
*/

package main

import (
	"bytes"
	"net"
)

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// parseHostsBytes parses a hosts-file byte slice into a parsedFile.
// ALL hostname tokens per line are processed (fix v1.26.0).
// Inline # comments are stripped (fix v1.26.0).
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

// parseDnsmasqLeasesBytes parses a dnsmasq flat-file lease database.
//
// Format (one record per line, five space-separated fields):
//
//	<expiry-epoch>  <mac>  <ip>  <hostname>  <client-id>
//
// Hostname '*' means the client didn't supply one — entry is skipped.
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

// parseIscLeasesBytes parses an ISC DHCP block-structured lease database.
//
// Only active and static bindings are imported. Last active block for a given
// IP wins (ISC append semantics). Block format:
//
//	lease 192.168.1.x {
//	  binding state active;
//	  hardware ethernet aa:bb:cc:dd:ee:ff;
//	  client-hostname "myhostname";
//	}
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
		if len(line) == 0 {
			continue
		}

		// "lease 192.168.x.x {" — begins a new block.
		if bytes.HasPrefix(line, []byte("lease ")) {
			inLease     = true
			leaseMAC    = ""
			leaseName   = ""
			leaseActive = false
			trimmed := bytes.TrimPrefix(line, []byte("lease "))
			trimmed = bytes.TrimSuffix(bytes.TrimSpace(trimmed), []byte("{"))
			leaseIP = string(bytes.TrimSpace(trimmed))
			continue
		}

		if !inLease {
			continue
		}

		// "}" — end of block; commit if active and named.
		if bytes.Equal(line, []byte("}")) {
			if leaseActive && leaseName != "" {
				shortName := storeEntry(leaseIP, leaseName, pf)
				if shortName != "" && leaseMAC != "" {
					if mac, err := net.ParseMAC(leaseMAC); err == nil {
						pf.macToName[mac.String()] = shortName
					}
				}
			}
			inLease = false
			continue
		}

		// "binding state active;" / "binding state static;" / etc.
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

// parseKeaLeasesBytes parses a Kea DHCP4 CSV lease file.
//
// Only state=0 (active) rows are imported. Header row is skipped.
// CSV column layout (0-indexed): 0=address, 1=hwaddr, 8=hostname, 9=state.
// SplitN(11) prevents user_context (col 10) with embedded commas from
// mis-shifting later columns.
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

		fields := bytes.SplitN(line, []byte(","), 11)
		if len(fields) < 10 {
			continue
		}

		addrBytes  := bytes.TrimSpace(fields[0])
		macBytes   := bytes.TrimSpace(fields[1])
		nameBytes  := bytes.TrimSpace(fields[8])
		stateBytes := bytes.TrimSpace(fields[9])

		if !bytes.Equal(stateBytes, []byte("0")) {
			continue // only import active leases
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

// parseOdhcpdLeasesBytes parses an odhcpd internal state file.
//
// odhcpd (OpenWrt) uses '#' as the DATA line prefix (not a comment marker).
// Format after the leading '#':
//
//	<ifname> <mac/duid> <iaid> <hostname> <remaining-secs> [<ip/plen>...]
//
// Hostname '-' means no hostname was supplied — entry is skipped.
// IP addresses include a prefix-length suffix (/32, /128) that is stripped.
func parseOdhcpdLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)

		// Data lines start with '#'; all other lines are structural — skip.
		if len(line) == 0 || line[0] != '#' {
			continue
		}

		// Strip the leading '#' and split remainder into fields.
		// [0]=ifname [1]=mac/duid [2]=iaid [3]=hostname [4]=remaining [5..]=ip/plen
		fields := bytes.Fields(line[1:])
		if len(fields) < 6 {
			continue
		}

		nameBytes := fields[3]
		if len(nameBytes) == 0 || bytes.Equal(nameBytes, []byte("-")) {
			continue // no hostname provided
		}

		macOrDUID := string(fields[1])
		hostname  := string(nameBytes)

		var shortName string
		for _, addrField := range fields[5:] {
			ipStr := string(addrField)
			// Strip /prefixlen suffix if present.
			if slash := bytes.IndexByte(addrField, '/'); slash >= 0 {
				ipStr = string(addrField[:slash])
			}
			sn := storeEntry(ipStr, hostname, pf)
			if sn != "" && shortName == "" {
				shortName = sn
			}
		}

		// DHCPv4 MACs parse cleanly; DHCPv6 DUIDs are rejected by ParseMAC (correct).
		if shortName != "" {
			if mac, err := net.ParseMAC(macOrDUID); err == nil {
				pf.macToName[mac.String()] = shortName
			}
		}
	}
	return pf
}

