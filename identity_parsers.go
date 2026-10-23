/*
File:    identity_parsers.go
Version: 1.5.0
Updated: 29-May-2026 08:53 CEST

Description:
  String and byte parsing for various hosts and lease formats.
  Extracted from identity.go to isolate formatting constraints.
  Supports hosts, dnsmasq, ISC DHCP, Kea, and odhcpd lease formats.

Changes:
  1.5.0 - [PERF] Executed explicit CPU yielding (`time.Sleep`) inside the primary 
          iteration blocks organically. Safely avoids suffocating DNS router logic 
          natively when evaluating gargantuan local hosts files.
  1.4.1 - [BUG/FIX] Added missing "os" import needed by parseLocalFile to fix compilation failure.
  1.4.0 - [SECURITY/FIX] Replaced standard `netip.ParsePrefix` with the unified 
          `ParsePrefixUnmapped` helper. Enforces strict unmapping parity with 
          `parental_loader.go` to prevent bypasses via IPv4-mapped IPv6 CIDR blocks.
*/

package main

import (
	"bytes"
	"net"
	"time"
)

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// parseHostsBytes parses a hosts-file byte slice into a parsedFile.
// ALL hostname tokens per line are processed.
// Inline # comments are stripped.
func parseHostsBytes(data []byte) *parsedFile {
	pf := newParsedFile()
	linesProcessed := 0

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
		
		linesProcessed++
		// Prevent large Hosts files from freezing UDP listeners natively
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	return pf
}

// parseDnsmasqLeasesBytes parses a dnsmasq flat-file lease database.
func parseDnsmasqLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()
	linesProcessed := 0

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
		
		linesProcessed++
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	return pf
}

// parseIscLeasesBytes parses an ISC DHCP block-structured lease database.
func parseIscLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()
	linesProcessed := 0

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

		if bytes.HasPrefix(line, []byte("hardware ethernet ")) {
			mac := bytes.TrimSuffix(line[len("hardware ethernet "):], []byte(";"))
			leaseMAC = string(bytes.TrimSpace(mac))
			continue
		}

		if bytes.HasPrefix(line, []byte("client-hostname ")) {
			name := line[len("client-hostname "):]
			name = bytes.TrimSuffix(name, []byte(";"))
			name = bytes.Trim(name, `"`)
			leaseName = string(bytes.TrimSpace(name))
			continue
		}
		
		linesProcessed++
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	return pf
}

// parseKeaLeasesBytes parses a Kea DHCP4 CSV lease file.
func parseKeaLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()
	linesProcessed := 0

	firstLine := true
	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

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

		nameStr := string(bytes.TrimSuffix(nameBytes, []byte(".")))

		shortName := storeEntry(string(addrBytes), nameStr, pf)
		if shortName != "" && len(macBytes) > 0 {
			if mac, err := net.ParseMAC(string(macBytes)); err == nil {
				pf.macToName[mac.String()] = shortName
			}
		}
		
		linesProcessed++
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	return pf
}

// parseOdhcpdLeasesBytes parses an odhcpd internal state file.
func parseOdhcpdLeasesBytes(data []byte) *parsedFile {
	pf := newParsedFile()
	linesProcessed := 0

	for len(data) > 0 {
		line, rest := splitLine(data)
		data = rest

		line = bytes.TrimSpace(line)

		if len(line) == 0 || line[0] != '#' {
			continue
		}

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
			if slash := bytes.IndexByte(addrField, '/'); slash >= 0 {
				ipStr = string(addrField[:slash])
			}
			sn := storeEntry(ipStr, hostname, pf)
			if sn != "" && shortName == "" {
				shortName = sn
			}
		}

		if shortName != "" {
			if mac, err := net.ParseMAC(macOrDUID); err == nil {
				pf.macToName[mac.String()] = shortName
			}
		}
		
		linesProcessed++
		if linesProcessed%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	return pf
}

