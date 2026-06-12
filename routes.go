/*
File:    routes.go
Version: 1.2.0
Updated: 2026-04-15 11:29 CEST
Description:
  Route-key classification and MAC-glob matching for sdproxy.

  Every entry under routes: is auto-detected as one of eight types at startup:
    MAC (exact)  — "aa:bb:cc:dd:ee:ff"
    MAC (glob)   — "aa:bb:??:??:??:??" / "aa:bb:cc:*:*:*"
    IP           — "192.168.1.50"
    CIDR         — "192.168.1.0/24"
    ASN          — "AS1136"
    Path         — "/dns-query" or "path:/kids"
    SNI          — "sni:doh.example.com"
    client-name  — any DHCP/hosts hostname, e.g. "alice-iphone"

  Query-time precedence: 
  MAC exact > MAC glob > IP > CIDR > ASN > client-name > SNI > PATH.

Changes:
  1.2.0 - [FEAT] Added support for mapping Autonomous System Numbers (ASN).
*/

package main

import (
	"net"
	"net/netip"
	"path"
	"strings"
)

// routeKeyType classifies a routes: YAML key at startup.
type routeKeyType uint8

const (
	rkMAC        routeKeyType = iota // exact MAC  — net.ParseMAC succeeded
	rkMACGlob                        // MAC with ? / * wildcards
	rkIP                             // exact IP address
	rkCIDR                           // CIDR prefix
	rkASN                            // Autonomous System Number
	rkPath                           // HTTP URL Path (DoH/DoH3)
	rkSNI                            // TLS Server Name Indication (DoT/DoQ/DoH/DoH3)
	rkClientName                     // DHCP/hosts hostname (catch-all)
)

// classifyRouteKey determines which routing table a key belongs to.
// Called once per route entry at startup — never on the hot path.
func classifyRouteKey(key string) routeKeyType {
	if strings.HasPrefix(key, "sni:") {
		return rkSNI
	}
	if strings.HasPrefix(key, "path:") || strings.HasPrefix(key, "/") {
		return rkPath
	}
	if strings.HasPrefix(strings.ToUpper(key), "AS") && isAllDigits(key[2:]) {
		return rkASN
	}
	if _, err := net.ParseMAC(key); err == nil {
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
	ok, err := path.Match(pattern, mac)
	return err == nil && ok
}

