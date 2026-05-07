/*
File:    process_helpers.go
Version: 1.7.0
Updated: 01-May-2026 11:07 CEST

Description:
  Synchronization pools, string builders, and high-performance global 
  utilities for the sdproxy DNS processing pipeline.
  Extracted from process.go to isolate memory pools and string manipulation 
  away from the primary hot-path logic.

Changes:
  1.7.0 - [SECURITY/FIX] Resolved a severe cache coalescing vulnerability within 
          `buildSFKey`. The SingleFlight execution group now strictly incorporates 
          `DoBit` (DNSSEC OK) and `CdBit` (Checking Disabled) flags into the hashing 
          signature. This securely neutralizes a regression where non-validating clients 
          could accidentally hijack and corrupt DNSSEC payload responses for strict resolvers.
  1.6.0 - [LOGGING] Fixed a telemetry regression where `cleanUpstreamHost` inadvertently 
          stripped the `+ECH` protocol marker from upstream connection logs. The helper 
          now natively detects and prepends `[ECH]` to the output string to ensure 
          Encrypted Client Hello statuses are visible in the Web UI and console.
  1.5.0 - [FIX] Expanded `buildSFKey` buffer capacity and bitwise shifting 
          to accommodate the new uint16 route index structure seamlessly, 
          resolving silent routing overflows on extreme configurations.
  1.4.0 - [LOGGING] Suppressed `[UNKNOWN-ASN]` tags for private, loopback, and link-local IP addresses in telemetry.
  1.3.0 - [LOGGING] Appended `[UNKNOWN-ASN]` to the buildClientID builder for 
          private/LAN IPs that cannot be mapped to the IPinfo public databases.
*/

package main

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// ---------------------------------------------------------------------------
// Global Synchronization Pools & Trackers
// ---------------------------------------------------------------------------

// clientIDPool reuses string builders for generating Client ID log lines,
// ensuring zero-allocation string concatenations on the hot path.
var clientIDPool = sync.Pool{New: func() any { return new(strings.Builder) }}

// sfGroup deduplicates identical concurrent upstream queries (Thundering Herd prevention).
var sfGroup singleflight.Group

// sfResult is the internal payload passed back by the singleflight execution group.
type sfResult struct {
	msg  *dns.Msg
	addr string
}

// coalescedTotal tracks how many redundant upstream queries were successfully 
// suppressed by the singleflight group.
var coalescedTotal atomic.Int64

// revalSem bounds the maximum number of background cache-revalidation routines
// that can execute simultaneously to prevent goroutine explosion.
const revalSemCap = 32
var revalSem = make(chan struct{}, revalSemCap)

// msgPool provides highly-recyclable dns.Msg structures to heavily reduce 
// Garbage Collection (GC) pressure during intense query floods.
var msgPool = sync.Pool{New: func() any { return new(dns.Msg) }}

// ---------------------------------------------------------------------------
// Key Builders & Formatters
// ---------------------------------------------------------------------------

// buildClientID generates the descriptive client identity string used throughout
// the logging architecture (e.g., "192.168.1.10 (alice-ipad)").
func buildClientID(ip, name string, addr netip.Addr) string {
	if name == "" && !logASNDetails {
		return ip
	}

	sb := clientIDPool.Get().(*strings.Builder)
	sb.Reset()

	sb.WriteString(ip)
	if name != "" {
		sb.WriteString(" (" + name + ")")
	}

	if logASNDetails {
		asn, asnName, asnCountry := LookupASNDetails(addr)
		if asn != "" {
			sb.WriteString(" [")
			sb.WriteString(asn)
			if asnName != "" {
				sb.WriteString(" ")
				sb.WriteString(asnName)
			}
			if asnCountry != "" {
				sb.WriteString(", ")
				sb.WriteString(asnCountry)
			}
			sb.WriteString("]")
		} else if addr.IsValid() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
			sb.WriteString(" [UNKNOWN-ASN]")
		}
	}

	s := sb.String()
	clientIDPool.Put(sb)
	return s
}

// buildSFKey constructs a highly specific cache key for the SingleFlight 
// execution group, ensuring only identical questions intended for the exact
// same upstream route index and DNSSEC constraints are coalesced.
// [PERF] Uses strings.Builder with exact capacity sizing for zero-allocation
// string conversion on return.
func buildSFKey(name string, qtype uint16, routeIdx uint16, doBit bool, cdBit bool, clientName string) string {
	var sb strings.Builder

	// Pre-allocate exact buffer size: name length + 6 control bytes + clientName length
	// (1 for name terminator, 2 for qtype, 2 for uint16 routeIdx, 1 for flags).
	capSize := len(name) + 6
	if clientName != "" {
		capSize += 1 + len(clientName)
	}
	sb.Grow(capSize)

	sb.WriteString(name)
	sb.WriteByte(0)
	sb.WriteByte(byte(qtype >> 8))
	sb.WriteByte(byte(qtype))
	sb.WriteByte(byte(routeIdx >> 8))
	sb.WriteByte(byte(routeIdx))
	
	// Pack cryptographic constraints into a single byte payload to prevent execution drift
	var flags byte
	if doBit {
		flags |= 1
	}
	if cdBit {
		flags |= 2
	}
	sb.WriteByte(flags)

	if clientName != "" {
		sb.WriteByte(0)
		sb.WriteString(clientName)
	}

	return sb.String()
}

// cleanUpstreamHost extracts a clean "Hostname (IP)" or just "IP" from the 
// upstream connection log, stripping redundant schemas or HTTP path data
// while preserving the ECH status indicator if successfully negotiated.
func cleanUpstreamHost(s string) string {
	if s == "" {
		return ""
	}
	
	echMarker := ""
	if strings.Contains(s, "+ECH://") {
		echMarker = "[ECH] "
	}
	
	// Remove scheme "proto://"
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	
	parts := strings.SplitN(s, " (", 2)
	hostPart := parts[0]
	
	// Remove path or query strings (e.g., HTTP paths)
	if slashIdx := strings.IndexByte(hostPart, '/'); slashIdx >= 0 {
		hostPart = hostPart[:slashIdx]
	}
	
	if len(parts) > 1 {
		ipPart := parts[1]
		ipPart = strings.TrimSuffix(ipPart, ")")
		// Strip port from IP
		if host, _, err := net.SplitHostPort(ipPart); err == nil {
			ipPart = host
		}
		return echMarker + hostPart + " (" + ipPart + ")"
	}
	
	// Strip port if it's just a raw host/IP
	if host, _, err := net.SplitHostPort(hostPart); err == nil {
		hostPart = host
	}
	return echMarker + hostPart
}

