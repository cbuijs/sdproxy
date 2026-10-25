/*
File:    process_helpers.go
Version: 1.22.0
Last Updated: 25-Oct-2026 15:10 CET

Description:
  Synchronization pools, string builders, and high-performance global
  utilities for the sdproxy DNS processing pipeline.
  Extracted from process.go to isolate memory pools and string manipulation
  away from the primary hot-path logic.

Changes:
  1.22.0 - [SECURITY/FIX] Added `bypassPolicies` and `bypassLocal` flags to
           `buildSFKey` so SingleFlight request coalescing isolates queries
           with differing policy or local-resolution contexts.
  1.21.0 - [FEAT] Added `appendClientEDNS` to enrich `clientID` with incoming
           EDNS0 Option 65001 (`[MAC: <mac>]`) alongside EDNS0 Client Subnet
           (`[ECS: <addr>/<mask>]`) across all query logs.
  1.20.0 - [FEAT] Added `appendClientECS` to enrich `clientID` with incoming
           EDNS0 Client Subnet (`[ECS: <addr>/<mask>]`) across all query logs.
  1.19.0 - [PERF] Eradicated `fmt.Sprintf` heap allocations natively within `RcodeStr`.
  1.18.0 - [SECURITY/FIX] Resolved uint16 parsing regression within `extractIPFromPTR`.
  1.17.0 - [SECURITY/FIX] Added RecursionDesired to the SingleFlight key so
           recursive and non-recursive exchanges cannot coalesce.
  1.16.0 - [PERF] Eradicated massive heap allocations within `extractIPFromPTR`
           natively.
  1.15.0 - [CLEANUP] Streamlined `parseHexNibble` evaluation mechanics.
  1.14.0 - [SECURITY] Passed `bypassGlobal` dynamically to `buildSFKey`.
  1.13.0 - [PERF] Obliterated massive heap allocations within `extractIPFromPTR`
           natively.
*/

package main

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

var ErrSilentDrop = errors.New("silent_drop")

// ---------------------------------------------------------------------------
// Global Synchronization Pools & Trackers
// ---------------------------------------------------------------------------

var clientIDPool = sync.Pool{New: func() any { return new(strings.Builder) }}

var sfGroup singleflight.Group

type sfResult struct {
	msg  *dns.Msg
	addr string
}

var coalescedTotal atomic.Int64

const revalSemCap = 32

var revalSem = make(chan struct{}, revalSemCap)

var msgPool = sync.Pool{New: func() any { return new(dns.Msg) }}

// ---------------------------------------------------------------------------
// Key Builders & Formatters
// ---------------------------------------------------------------------------

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

func appendClientEDNS(clientID string, ecsAddr netip.Addr, ecsPrefix netip.Prefix, ednsMAC string) string {
	if !ecsAddr.IsValid() && ednsMAC == "" {
		return clientID
	}
	sb := clientIDPool.Get().(*strings.Builder)
	sb.Reset()
	sb.WriteString(clientID)
	if ecsAddr.IsValid() {
		sb.WriteString(" [ECS: ")
		if ecsPrefix.IsValid() {
			sb.WriteString(ecsAddr.String())
			sb.WriteByte('/')
			sb.WriteString(itoa64(int64(ecsPrefix.Bits())))
		} else {
			sb.WriteString(ecsAddr.String())
		}
		sb.WriteByte(']')
	}
	if ednsMAC != "" {
		sb.WriteString(" [MAC: ")
		sb.WriteString(ednsMAC)
		sb.WriteByte(']')
	}
	s := sb.String()
	clientIDPool.Put(sb)
	return s
}

// buildSFKey constructs a cache key for the SingleFlight execution group.
func buildSFKey(name string, qtype uint16, qclass uint16, routeIdx uint16, doBit bool, cdBit bool, bypassGlobal bool, bypassPolicies bool, bypassLocal bool, recursionDesired bool, clientName string, ecs string) string {
	var sb strings.Builder

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
	if recursionDesired {
		flags |= 8
	}
	if bypassPolicies {
		flags |= 16
	}
	if bypassLocal {
		flags |= 32
	}
	sb.WriteByte(flags)

	sb.WriteByte(0)
	sb.WriteString(clientName)
	sb.WriteByte(0)
	sb.WriteString(ecs)

	return sb.String()
}

func cleanUpstreamHost(s string) string {
	if s == "" {
		return ""
	}

	echMarker := ""
	if strings.Contains(s, "+ECH://") {
		echMarker = "[ECH] "
	}

	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}

	parts := strings.SplitN(s, " (", 2)
	hostPart := parts[0]

	if slashIdx := strings.IndexByte(hostPart, '/'); slashIdx >= 0 {
		hostPart = hostPart[:slashIdx]
	}

	if len(parts) > 1 {
		ipPart := parts[1]
		ipPart = strings.TrimSuffix(ipPart, ")")
		if host, _, err := net.SplitHostPort(ipPart); err == nil {
			ipPart = host
		}
		return echMarker + hostPart + " (" + ipPart + ")"
	}

	if host, _, err := net.SplitHostPort(hostPart); err == nil {
		hostPart = host
	}
	return echMarker + hostPart
}

// ---------------------------------------------------------------------------
// DNS Message & IP Utilities
// ---------------------------------------------------------------------------

func parseHexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	}
	return 16
}

func extractIPFromPTR(name string) string {
	if strings.HasSuffix(name, ".in-addr.arpa") {
		p := name[:len(name)-13]
		var b [4]byte
		var octet int
		var val int
		var hasVal bool

		for i := 0; i < len(p); i++ {
			c := p[i]
			if c == '.' {
				if !hasVal || octet >= 3 {
					return ""
				}
				b[3-octet] = byte(val)
				octet++
				val = 0
				hasVal = false
			} else if c >= '0' && c <= '9' {
				val = val*10 + int(c-'0')
				if val > 255 {
					return ""
				}
				hasVal = true
			} else {
				return ""
			}
		}
		if !hasVal || octet != 3 {
			return ""
		}
		b[0] = byte(val)
		return netip.AddrFrom4(b).String()

	} else if strings.HasSuffix(name, ".ip6.arpa") {
		p := strings.TrimSuffix(name, ".ip6.arpa")

		if len(p) != 63 {
			return ""
		}

		var b [16]byte
		for i := 0; i < 16; i++ {
			hiIdx := 62 - (i * 4)
			loIdx := 60 - (i * 4)

			hi := parseHexNibble(p[hiIdx])
			lo := parseHexNibble(p[loIdx])

			if hi > 15 || lo > 15 {
				return ""
			}
			b[i] = (byte(hi) << 4) | byte(lo)
		}
		return netip.AddrFrom16(b).String()
	}
	return ""
}

func SetNegativeSOA(msg *dns.Msg, name string, ttl uint32) {
	msg.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "ns.sdproxy.", Mbox: "hostmaster.sdproxy.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: ttl,
	}}
}

func PreserveEDNS0(req *dns.Msg, resp *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		resp.Extra = append(resp.Extra, dns.Copy(opt))
	}
}

func RcodeStr(rcode int) string {
	if str, ok := dns.RcodeToString[rcode]; ok {
		return str
	}
	return "RCODE:" + itoa64(int64(rcode))
}

func ParsePrefixUnmapped(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return prefix, err
	}

	if prefix.Addr().Is4In6() {
		bits := prefix.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
	}
	return prefix, nil
}
