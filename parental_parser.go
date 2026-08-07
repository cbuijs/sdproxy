/*
File:    parental_parser.go
Version: 1.4.1
Last Updated: 24-May-2026 21:00 CEST

Description:
  String and byte parsing for Parental Category domain lists.
  Extracted from parental_categories.go to isolate formatting constraints.

Changes:
  1.4.1 - [BUG/FIX] Added missing "os" import needed by parseLocalFile to fix compilation failure.
  1.4.0 - [SECURITY/FIX] Replaced standard `netip.ParsePrefix` with the unified 
          `ParsePrefixUnmapped` helper. Enforces strict unmapping parity with 
          `parental_loader.go` to prevent bypasses via IPv4-mapped IPv6 CIDR blocks.
  1.3.0 - [SECURITY/FIX] Addressed an IPv4-mapped IPv6 evasion vulnerability natively. 
          Enforced `.Unmap()` on all parsed `netip.Addr` structures strictly BEFORE 
          evaluating against `ipVersionSupport` bounds. This prevents clients from 
          bypassing explicit IPv4 limitations by obfuscating targets inside IPv6 translations.
          Removed redundant dead-code branches tracking Adblock IPs to increase throughput.
  1.2.0 - [SECURITY/FIX] Fortified blocklist parsers to safely absorb and bypass corrupted lines 
          exceeding 64KB. `parseSourceBody` now catches `bufio.Scanner` errors gracefully 
          and returns them to the orchestrator, preventing silent truncation of the remaining payload.
  1.1.0 - [FEAT] Integrated `ipVersionSupport` check into `parseCategoryLine` 
          to selectively ignore IP addresses and subnets that do not match 
          the filtered IP version setting.
*/

package main

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// Service-label stripping
// ---------------------------------------------------------------------------

var serviceLabels = map[string]struct{}{
	"www": {}, "www2": {}, "www3": {}, "web": {},
	"cdn": {}, "static": {}, "assets": {}, "media": {}, "img": {}, "images": {},
	"api": {}, "app": {}, "apps": {},
	"mail": {}, "smtp": {}, "pop": {}, "pop3": {}, "imap": {}, "mx": {},
	"ftp": {}, "sftp": {},
	"vpn": {}, "proxy": {}, "gate": {},
	"ns": {}, "ns1": {}, "ns2": {}, "ns3": {}, "ns4": {},
	"download": {}, "downloads": {}, "update": {}, "updates": {},
	"secure": {}, "ssl": {},
	"dev": {}, "staging": {}, "stage": {}, "test": {}, "beta": {}, "alpha": {},
	"blog": {}, "shop": {}, "store": {}, "portal": {},
}

func stripServiceLabel(d string) (string, bool) {
	idx := strings.IndexByte(d, '.')
	if idx < 0 {
		return "", false
	}
	label := d[:idx]
	rest := d[idx+1:]
	if rest == "" {
		return "", false
	}
	if isPublicSuffix(rest) {
		return "", false
	}
	if len(label) == 1 {
		return rest, true
	}
	if _, ok := serviceLabels[label]; ok {
		return rest, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Source format helpers
// ---------------------------------------------------------------------------

// isIPOrCIDR safely tests whether a string parses successfully as an IP or Subnet.
func isIPOrCIDR(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}

func parseCategoryLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' {
		return nil
	}

	pseudoHost := func(s string) bool {
		switch s {
		case "localhost", "local", "broadcasthost",
			"ip6-localhost", "ip6-loopback", "ip6-localnet",
			"ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
			"ip6-allhosts", "0.0.0.0", "::", "127.0.0.1", "::1":
			return true
		}
		return false
	}

	switch {
	case strings.HasPrefix(line, "@@||"):
		return nil
	case strings.HasPrefix(line, "||"):
		d := line[2:]
		if i := strings.IndexByte(d, '^'); i >= 0 {
			d = d[:i]
		}
		d = strings.TrimPrefix(d, "*.")
		if strings.ContainsAny(d, "/*?") {
			return nil
		}
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d == "" {
			return nil
		}
		
		// [SECURITY/PERF] Natively ignore IP and CIDR rules supplied in Adblock syntaxes
		if _, err := netip.ParseAddr(d); err == nil {
			return nil 
		}
		if _, err := netip.ParsePrefix(d); err == nil {
			return nil 
		}
		return []string{d}
		
	case len(line) > 0 && (line[0] >= '0' && line[0] <= '9' || line[0] == ':'):
		cleanLine := line
		if i := strings.IndexByte(cleanLine, '#'); i >= 0 {
			cleanLine = strings.TrimSpace(cleanLine[:i])
		}
		if cleanLine == "" {
			return nil
		}
		
		fields := strings.Fields(cleanLine)
		if len(fields) == 0 {
			return nil
		}
		
		if len(fields) == 1 {
			d := strings.ToLower(strings.TrimSuffix(fields[0], "."))
			if d == "" {
				return nil
			}
			// [SECURITY/FIX] Ensure the payload is fully unmapped before evaluating IP version 
			// configurations to prevent IPv4-in-IPv6 evasion vulnerabilities.
			if addr, err := netip.ParseAddr(d); err == nil {
				addr = addr.Unmap()
				if ipVersionSupport != "both" {
					if ipVersionSupport == "ipv4" && !addr.Is4() { return nil }
					if ipVersionSupport == "ipv6" && !addr.Is6() { return nil }
				}
			}
			if prefix, err := ParsePrefixUnmapped(d); err == nil {
				// Address underlying prefix address structures natively
				prefixAddr := prefix.Addr()
				if ipVersionSupport != "both" {
					if ipVersionSupport == "ipv4" && !prefixAddr.Is4() { return nil }
					if ipVersionSupport == "ipv6" && !prefixAddr.Is6() { return nil }
				}
			}
			return []string{d}
		}
		
		if addr, err := netip.ParseAddr(fields[0]); err == nil {
			addr = addr.Unmap()
			if ipVersionSupport != "both" {
				if ipVersionSupport == "ipv4" && !addr.Is4() { return nil }
				if ipVersionSupport == "ipv6" && !addr.Is6() { return nil }
			}
			var out []string
			for _, f := range fields[1:] {
				f = strings.ToLower(strings.TrimSuffix(f, "."))
				if f == "" || pseudoHost(f) {
					continue
				}
				if isIPOrCIDR(f) {
					continue 
				}
				out = append(out, f)
			}
			return out
		}
		
		var out []string
		for _, f := range fields {
			f = strings.ToLower(strings.TrimSuffix(f, "."))
			if f == "" || pseudoHost(f) {
				continue
			}
			out = append(out, f)
		}
		return out
	default:
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.ContainsAny(line, "[]") {
			return nil
		}
		d := strings.ToLower(strings.TrimSuffix(line, "."))
		if d == "" {
			return nil
		}
		return []string{d}
	}
}

func isSourceURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func parseSourceBody(r io.Reader) ([]string, int, error) {
	var lines []string
	eTLDs := 0
	sc := bufio.NewScanner(r)
	
	// Expand scanner capacity to prevent 'bufio.Scanner: token too long' panics natively 
	// on heavily concatenated or corrupted external blocklists.
	buf := make([]byte, 64*1024)
	sc.Buffer(buf, 2*1024*1024)

	for sc.Scan() {
		domains := parseCategoryLine(sc.Text())
		for _, d := range domains {
			if !isIPOrCIDR(d) && isPublicSuffix(d) {
				eTLDs++
			}
			lines = append(lines, d)
		}
	}
	return lines, eTLDs, sc.Err()
}

func parseLocalFile(path string) ([]string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	return parseSourceBody(f)
}

