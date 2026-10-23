/*
File:    routes.go
Version: 1.10.0
Last Updated: 22-Oct-2026 13:45 CEST
Description:
  Route-key classification and MAC-glob matching for sdproxy.

  Every entry under routes: is auto-detected as one of fourteen types at startup:
    MAC (exact)       — "aa:bb:cc:dd:ee:ff"
    MAC (glob)        — "aa:bb:??:??:??:??" / "aa:bb:cc:*:*:*"
    EDNS0 MAC (exact) — "mac:aa:bb:cc:dd:ee:ff"
    EDNS0 MAC (glob)  — "mac:aa:bb:??:??:??:??" / "mac:aa:bb:cc:*:*:*"
    IP                — "192.168.1.50"
    CIDR              — "192.168.1.0/24"
    ECS IP            — "ecs:203.0.113.5"
    ECS CIDR          — "ecs:203.0.113.0/24"
    ASN               — "AS1136"
    Country           — "CC:NL"
    Path              — "/dns-query" or "path:/kids"
    SNI               — "sni:doh.example.com"
    Port              — "port:53" or "port:853"
    client-name       — any DHCP/hosts hostname, e.g. "alice-iphone"

  Query-time precedence: 
  MAC exact > MAC glob > EDNS0 MAC exact > EDNS0 MAC glob > IP > CIDR > ECS IP > ECS CIDR > ASN > Country > client-name > SNI > PATH > PORT.

Changes:
  1.10.0 - [FIX] Hardened `parseEDNS0MAC` to accept 12-byte unseparated hex
           strings (e.g. "aabbccddeeff") in addition to 6-byte raw binary and
           colon/hyphen-separated textual MAC formats, and widened textual buffer
           bounds to handle trailing whitespace/null padding cleanly.
  1.9.0  - [FEAT] Added `rkEDNSMAC`, `rkEDNSMACGlob`, `parseMACKey`, and `parseEDNS0MAC`
           to support matching EDNS0 Option 65001 (dnsmasq) MAC addresses and globs
           via `mac:<mac>` and `mac:<mac-glob>` in `routes:`.
  1.8.0  - [FIX] Added `rkInvalid` so malformed `ecs:`, `port:`, `sni:`, and `path:`
           keys do not silently fall through to `rkClientName`.
         - [FIX] Added address family check in `matchECSCIDR` before comparing
           prefix lengths so IPv6 `/56` ECS prefixes never match IPv4 `/24` rules.
  1.7.0  - [FEAT] Added `rkECSIP`, `rkECSCIDR`, `parseECSKey`, and `matchECSCIDR` to
           support matching EDNS0 Client Subnet (`ecs:`) IP addresses and CIDR prefixes
           in `routes:`.
  1.6.0  - [FIX] Made `sni:`, `path:`, and `port:` prefix matching case-insensitive
           in `classifyRouteKey` and `parsePort`.
  1.5.0  - [FEAT] Added support for mapping specific listener ports (port:).
  1.4.0  - [FEAT] Added support for mapping ISO 3166-1 alpha-2 Country Codes (CC:).
  1.3.0  - [PERF] Employs zero-allocation fast-glob matching natively instead 
           of `path.Match`.
  1.2.0  - [FEAT] Added support for mapping Autonomous System Numbers (ASN).
*/

package main

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// edns0OptMAC is the EDNS0 option code 65001 (0xFDE9) used by dnsmasq (--add-mac)
// to embed the querying client's MAC address.
const edns0OptMAC uint16 = 65001

// routeKeyType classifies a routes: YAML key at startup.
type routeKeyType uint8

const (
	rkMAC         routeKeyType = iota // exact MAC  — net.ParseMAC succeeded
	rkMACGlob                         // MAC with ? / * wildcards
	rkEDNSMAC                         // EDNS0 Option 65001 exact MAC (mac:<mac>)
	rkEDNSMACGlob                     // EDNS0 Option 65001 MAC glob (mac:<glob>)
	rkIP                              // exact IP address
	rkCIDR                            // CIDR prefix
	rkECSIP                           // EDNS0 Client Subnet exact IP (ecs:<ip>)
	rkECSCIDR                         // EDNS0 Client Subnet CIDR prefix (ecs:<cidr>)
	rkASN                             // Autonomous System Number
	rkCountry                         // ISO 3166-1 alpha-2 Country Code
	rkPath                            // HTTP URL Path (DoH/DoH3)
	rkSNI                             // TLS Server Name Indication (DoT/DoQ/DoH/DoH3)
	rkPort                            // Listener Port
	rkClientName                      // DHCP/hosts hostname (catch-all)
	rkInvalid                         // Malformed prefixed route key
)

// classifyRouteKey determines which routing table a key belongs to.
// Called once per route entry at startup — never on the hot path.
func classifyRouteKey(key string) routeKeyType {
	lowerKey := strings.ToLower(key)
	if strings.HasPrefix(lowerKey, "sni:") {
		if lowerTrimDot(strings.TrimSpace(key[4:])) == "" {
			return rkInvalid
		}
		return rkSNI
	}
	if strings.HasPrefix(lowerKey, "path:") {
		if strings.TrimSpace(key[5:]) == "" {
			return rkInvalid
		}
		return rkPath
	}
	if strings.HasPrefix(key, "/") {
		return rkPath
	}
	if strings.HasPrefix(lowerKey, "port:") {
		if _, ok := parsePort(key); !ok {
			return rkInvalid
		}
		return rkPort
	}
	if strings.HasPrefix(lowerKey, "mac:") {
		rest := strings.TrimSpace(key[4:])
		if mac, err := net.ParseMAC(rest); err == nil && len(mac) == 6 {
			return rkEDNSMAC
		}
		if isMACGlob(rest) {
			return rkEDNSMACGlob
		}
		return rkInvalid
	}
	if strings.HasPrefix(lowerKey, "ecs:") {
		rest := strings.TrimSpace(key[4:])
		if _, err := netip.ParseAddr(rest); err == nil {
			return rkECSIP
		}
		if _, err := ParsePrefixUnmapped(rest); err == nil {
			return rkECSCIDR
		}
		return rkInvalid
	}
	if strings.HasPrefix(strings.ToUpper(key), "AS") && isAllDigits(key[2:]) {
		return rkASN
	}
	if strings.HasPrefix(strings.ToUpper(key), "CC:") && len(key) == 5 {
		return rkCountry
	}
	if mac, err := net.ParseMAC(key); err == nil && len(mac) == 6 {
		return rkMAC
	}
	if isMACGlob(key) {
		return rkMACGlob
	}
	if _, err := netip.ParseAddr(key); err == nil {
		return rkIP
	}
	if _, err := netip.ParsePrefix(key); err == nil {
		return rkCIDR
	}
	return rkClientName
}

// parseMACKey strips the case-insensitive "mac:" prefix and returns the trimmed target.
func parseMACKey(key string) string {
	if len(key) >= 4 && strings.EqualFold(key[:4], "mac:") {
		return strings.TrimSpace(key[4:])
	}
	return strings.TrimSpace(key)
}

const hexDigits = "0123456789abcdef"

// parseEDNS0MAC decodes an EDNS0 Option 65001 byte payload into a normalized
// lowercase 6-octet colon-separated MAC string ("aa:bb:cc:dd:ee:ff").
// Supports standard 6-byte raw binary (dnsmasq --add-mac), 17-byte textual MACs
// (dnsmasq --add-mac=text), and 12-byte unseparated hex strings.
func parseEDNS0MAC(b []byte) string {
	if len(b) == 6 {
		if b[0]|b[1]|b[2]|b[3]|b[4]|b[5] == 0 {
			return ""
		}
		var buf [17]byte
		for i := 0; i < 6; i++ {
			if i > 0 {
				buf[i*3-1] = ':'
			}
			buf[i*3] = hexDigits[b[i]>>4]
			buf[i*3+1] = hexDigits[b[i]&0x0f]
		}
		return string(buf[:])
	}
	if len(b) >= 11 && len(b) <= 32 {
		s := strings.Trim(string(b), "\x00 \t\r\n")
		if len(s) == 12 {
			var buf [17]byte
			var nonZero byte
			for i := 0; i < 6; i++ {
				hi := parseHexNibble(s[i*2])
				lo := parseHexNibble(s[i*2+1])
				if hi > 15 || lo > 15 {
					return ""
				}
				nonZero |= (hi << 4) | lo
				if i > 0 {
					buf[i*3-1] = ':'
				}
				buf[i*3] = hexDigits[hi]
				buf[i*3+1] = hexDigits[lo]
			}
			if nonZero == 0 {
				return ""
			}
			return string(buf[:])
		}
		if mac, err := net.ParseMAC(s); err == nil && len(mac) == 6 {
			if mac[0]|mac[1]|mac[2]|mac[3]|mac[4]|mac[5] == 0 {
				return ""
			}
			return mac.String()
		}
	}
	return ""
}

// parseECSKey strips the case-insensitive "ecs:" prefix and returns the trimmed target.
func parseECSKey(key string) string {
	if len(key) >= 4 && strings.EqualFold(key[:4], "ecs:") {
		return strings.TrimSpace(key[4:])
	}
	return strings.TrimSpace(key)
}

// matchECSCIDR reports whether an incoming EDNS0 Client Subnet (addr + prefix)
// is contained within the configured rulePrefix (addr is inside rulePrefix and
// the ECS prefix is at least as specific as rulePrefix).
func matchECSCIDR(rulePrefix, ecsPrefix netip.Prefix, ecsAddr netip.Addr) bool {
	if !ecsAddr.IsValid() || !rulePrefix.Contains(ecsAddr) {
		return false
	}
	if ecsPrefix.IsValid() && ecsPrefix.Addr().Is4() == rulePrefix.Addr().Is4() {
		return ecsPrefix.Bits() >= rulePrefix.Bits()
	}
	return true
}

// isAllDigits reports whether s contains exclusively numerical characters.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isMACGlob reports whether s is a MAC-address-shaped glob pattern.
func isMACGlob(s string) bool {
	if !strings.ContainsAny(s, "?*") {
		return false
	}
	parts := strings.Split(strings.ToLower(s), ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return false
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '?' || c == '*') {
				return false
			}
		}
	}
	return true
}

// normaliseMACGlob lowercases a validated MAC glob so runtime comparisons
// against already-lowercase MAC strings need no per-query case conversion.
func normaliseMACGlob(s string) string {
	return strings.ToLower(s)
}

// matchMACGlob reports whether mac matches pattern.
func matchMACGlob(pattern, mac string) bool {
	return matchGlob(pattern, mac)
}

// parsePort strictly parses a string port identifier to ensure structural validity.
func parsePort(portStr string) (string, bool) {
	clean := portStr
	if len(clean) >= 5 && strings.EqualFold(clean[:5], "port:") {
		clean = clean[5:]
	}
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return "", false
	}
	if p, err := strconv.ParseUint(clean, 10, 16); err == nil && p > 0 {
		return strconv.FormatUint(p, 10), true
	}
	return "", false
}

