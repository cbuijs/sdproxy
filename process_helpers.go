/*
File:    process_helpers.go
Version: 1.14.0
Updated: 07-Jul-2026 14:44 CEST

Description:
  Synchronization pools, string builders, and high-performance global 
  utilities for the sdproxy DNS processing pipeline.
  Extracted from process.go to isolate memory pools and string manipulation 
  away from the primary hot-path logic.

Changes:
  1.14.0 - [SECURITY] Passed `bypassGlobal` dynamically to `buildSFKey` to avert 
           SingleFlight hash collisions between standard and bypassed payloads natively.
  1.13.0 - [PERF] Obliterated massive heap allocations within `extractIPFromPTR` 
           natively. IPv6 reverse zones (`.ip6.arpa`) are now decoded through O(1) 
           mathematical array indices directly into a `[16]byte` block. Bypasses 
           `strings.Split` and string builders entirely, slashing GC latency 
           during intense reverse-DNS floods.
  1.12.0 - [SECURITY/FIX] Dynamically injected `Qclass` parameters into the 
           SingleFlight caching signature (`buildSFKey`) natively. Neutralizes 
           theoretical cross-class hash collisions within the execution pool 
           and maintains strict mathematical parity.
*/

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// ErrSilentDrop is a sentinel error used by upstream execution pools to cleanly 
// terminate consensus loops without writing a response to the client.
var ErrSilentDrop = errors.New("silent_drop")

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
// suppressed by the singleflight group natively.
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
// same upstream route index, subnets, and DNSSEC constraints are coalesced.
// [PERF] Uses strings.Builder with exact capacity sizing for zero-allocation
// string conversion on return.
func buildSFKey(name string, qtype uint16, qclass uint16, routeIdx uint16, doBit bool, cdBit bool, bypassGlobal bool, clientName string, ecs string) string {
	var sb strings.Builder

	// [SECURITY/PERF] Pre-allocate exact buffer size to prevent dynamic heap escapes.
	// Name length + 8 structural control bytes + 1 null-byte + clientName length + 1 null-byte + ecs length
	// (1 for name terminator, 2 for qtype, 2 for qclass, 2 for uint16 routeIdx, 1 for flags).
	capSize := len(name) + 8 + 1 + len(clientName) + 1 + len(ecs)
	sb.Grow(capSize)

	sb.WriteString(name)
	sb.WriteByte(0)
	sb.WriteByte(byte(qtype >> 8))
	sb.WriteByte(byte(qtype))
	sb.WriteByte(byte(qclass >> 8))
	sb.WriteByte(byte(qclass))
	sb.WriteByte(byte(routeIdx >> 8))
	sb.WriteByte(byte(routeIdx))
	
	// Pack cryptographic constraints into a single byte payload to prevent execution drift natively.
	var flags byte
	if doBit {
		flags |= 1
	}
	if cdBit {
		flags |= 2
	}
	if bypassGlobal {
		flags |= 4
	}
	sb.WriteByte(flags)

	// [SECURITY/FIX] Unconditionally append null-byte delimiters regardless of empty strings.
	// Prevents severe hash collisions where parallel clients containing alternating string arrays 
	// generated perfectly identical concatenated boundaries, hijacking routing and caching states.
	sb.WriteByte(0)
	sb.WriteString(clientName)
	sb.WriteByte(0)
	sb.WriteString(ecs)

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
	
	// Remove scheme "proto://" natively
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	
	parts := strings.SplitN(s, " (", 2)
	hostPart := parts[0]
	
	// Remove path or query strings (e.g., HTTP paths) natively
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
	
	// Strip port if it's just a raw host/IP natively
	if host, _, err := net.SplitHostPort(hostPart); err == nil {
		hostPart = host
	}
	return echMarker + hostPart
}

// ---------------------------------------------------------------------------
// DNS Message & IP Utilities
// ---------------------------------------------------------------------------

// parseHexNibble converts an ASCII hex byte directly into its numerical equivalent natively.
func parseHexNibble(b byte) byte {
	if b >= '0' && b <= '9' { return b - '0' }
	if b >= 'a' && b <= 'f' { return b - 'a' + 10 }
	if b >= 'A' && b <= 'F' { return b - 'A' + 10 }
	return 16 // Sentinel for invalid boundaries
}

// extractIPFromPTR parses an in-addr.arpa or ip6.arpa reverse-lookup name
// and returns the underlying IP address as a string. Returns "" if invalid.
// Expects a lowercase, dot-trimmed qname.
func extractIPFromPTR(name string) string {
	if strings.HasSuffix(name, ".in-addr.arpa") {
		p := strings.TrimSuffix(name, ".in-addr.arpa")
		parts := strings.Split(p, ".")
		if len(parts) == 4 {
			return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		}
	} else if strings.HasSuffix(name, ".ip6.arpa") {
		p := strings.TrimSuffix(name, ".ip6.arpa")
		
		// [PERF/FIX] IPv6 Reverse zones strictly follow a deterministic 63-byte structure (32 hex chars + 31 dots).
		// Natively unpacking the nibbles directly from the string descriptor completely eradicates 
		// massive array allocation and `strings.Split` heap escapes during reverse-DNS floods.
		if len(p) != 63 {
			return ""
		}
		
		var b [16]byte
		for i := 0; i < 16; i++ {
			// Map physical index coordinates directly. 
			// Nibbles are ordered inverse, spaced by dots natively.
			hiIdx := 62 - (i * 4) 
			loIdx := 60 - (i * 4)
			
			hi := parseHexNibble(p[hiIdx])
			lo := parseHexNibble(p[loIdx])
			
			if hi > 15 || lo > 15 {
				return ""
			}
			b[i] = (hi << 4) | lo
		}
		return netip.AddrFrom16(b).String()
	}
	return ""
}

// SetNegativeSOA natively synthesizes an SOA record for negative caching proofs (RFC 2308).
// Binds strictly to the requested QNAME to prevent stub resolvers from aggressively 
// retrying missing or intercepted records natively.
func SetNegativeSOA(msg *dns.Msg, name string, ttl uint32) {
	msg.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns.sdproxy.", Mbox: "hostmaster.sdproxy.",
		Serial:  1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: ttl,
	}}
}

// PreserveEDNS0 extracts and deeply clones the client's EDNS0 payload natively.
// Crucial for satisfying RFC 6891 requirements; strict resolvers often reject 
// synthesized block responses if their initial OPT limits are ignored.
func PreserveEDNS0(req *dns.Msg, resp *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		resp.Extra = append(resp.Extra, dns.Copy(opt))
	}
}

// RcodeStr returns a string representation of a DNS return code dynamically.
// Natively mitigates index out-of-bounds panics on unknown RCODE mappings.
func RcodeStr(rcode int) string {
	if str, ok := dns.RcodeToString[rcode]; ok {
		return str
	}
	return fmt.Sprintf("RCODE:%d", rcode)
}

// ParsePrefixUnmapped parses a CIDR string and structurally unmaps IPv4-in-IPv6 boundaries natively.
// Eliminates a severe evasion vector where malicious clients attempt to bypass IPv4 ACLs 
// and Domain blocks by shrouding payloads in IPv6 translation mechanics.
func ParsePrefixUnmapped(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return prefix, err
	}
	
	// Rigorously enforce protocol abstraction stripping natively
	if prefix.Addr().Is4In6() {
		bits := prefix.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
	}
	return prefix, nil
}

