/*
File:    process_filters.go
Version: 2.12.0
Updated: 07-May-2026 10:23 CEST

Description:
  Verbose Deep Packet Filtering operations for Target-Names and IP Addresses.
  This file evaluates DNS response payloads deeply to prevent Server-Side 
  Request Forgery (SSRF) via DNS Rebinding, filters out blocked IP addresses 
  natively, and guarantees strict adherence to RFC 1035 QNAME syntax bounds.

Changes:
  2.12.0 - [SECURITY/FIX] Upgraded the DPI telemetry logging payload structures 
           to natively accept `originalQName` and `originalQNameTrimmed`. Prevents 
           analytical obfuscation internally triggered by the new CNAME Spoofing mechanic.
  2.11.0 - [PERF/FIX] Eradicated domain suffix-walking evaluations for parsed IP 
           payloads in `filterResponseIPs`. Explicitly restricts IP filtering 
           to the optimized `domainPolicyCIDRSnap` array natively, bypassing 
           O(N) string manipulations on raw IP addresses.
  2.10.0 - [SECURITY/FIX] Hardened Domain Policy IP Filtering. Replaced flawed String-based 
           CIDR lookup failures with explicit `netip.Prefix` boundary evaluations. The system 
           now dynamically filters out-of-bounds `A`/`AAAA` payloads that intersect exactly 
           with explicitly configured Domain Policy subnets dynamically.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// DNS QNAME Validation
// ---------------------------------------------------------------------------

// validQNAMEChars acts as a highly optimized, zero-allocation lookup table 
// (O(1) boolean array) to instantly verify if a character conforms to standard 
// RFC 1035/1123 hostname syntax boundaries.
var validQNAMEChars = [256]bool{
	'-': true, '_': true,
	'*': true, '/': true,
	'+': true, '=': true, 
	'0': true, '1': true, '2': true, '3': true, '4': true, '5': true, '6': true, '7': true, '8': true, '9': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true, 'g': true, 'h': true, 'i': true, 'j': true, 'k': true, 'l': true, 'm': true, 'n': true, 'o': true, 'p': true, 'q': true, 'r': true, 's': true, 't': true, 'u': true, 'v': true, 'w': true, 'x': true, 'y': true, 'z': true,
	'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true, 'G': true, 'H': true, 'I': true, 'J': true, 'K': true, 'L': true, 'M': true, 'N': true, 'O': true, 'P': true, 'Q': true, 'R': true, 'S': true, 'T': true, 'U': true, 'V': true, 'W': true, 'X': true, 'Y': true, 'Z': true,
}

// isValidQNAME rigorously analyzes a DNS query name to prevent buffer overflows, 
// malformed payload injections, and protocol violations. It enforces label length 
// bounds (63 bytes), total length constraints (253 bytes), and valid character mappings.
func isValidQNAME(name string, qtype uint16) bool {
	l := len(name)
	if l == 0 || l > 253 {
		return false
	}
	if name == "." {
		return true 
	}

	labelLen := 0
	var lastChar byte
	hasSlash := false

	for i := 0; i < l; i++ {
		c := name[i]

		if c == '.' {
			// A DNS label cannot exceed 63 bytes in length per RFC 1035
			if labelLen == 0 || labelLen > 63 {
				return false 
			}
			// Hostnames cannot end with a hyphen
			if lastChar == '-' {
				return false
			}
			labelLen = 0
			lastChar = c
			continue
		}

		// Hostnames cannot start with a hyphen
		if labelLen == 0 && c == '-' {
			return false
		}

		// Ensure the character exists within the authorized ASCII boundary
		if !validQNAMEChars[c] {
			return false 
		}

		// Asterisks are strictly reserved for wildcard records and must occupy their own label
		if c == '*' {
			if (i != 0 && name[i-1] != '.') || (i+1 < l && name[i+1] != '.') {
				return false
			}
		}

		if c == '/' {
			hasSlash = true
		}

		labelLen++
		lastChar = c
	}

	// Catch trailing label boundary constraints if the domain lacks a root dot
	if labelLen > 0 {
		if labelLen > 63 || lastChar == '-' {
			return false
		}
	}

	// Classless In-Addr Arpa mappings allow slashes, standard domains do not
	if hasSlash {
		if qtype != dns.TypePTR && qtype != dns.TypeSOA && qtype != dns.TypeNS && qtype != dns.TypeTXT {
			return false
		}
		if !strings.HasSuffix(name, ".arpa.") && !strings.HasSuffix(name, ".arpa") {
			return false
		}
	}

	return true
}

// bogonPrefixes maintains the strict list of globally unroutable, private, 
// and reserved IP spaces (RFC 1918, RFC 6598, RFC 4193, etc.).
var bogonPrefixes []netip.Prefix

func init() {
	prefixes := []string{
		"0.0.0.0/8",          // "This network"
		"10.0.0.0/8",         // Private-Use (RFC 1918)
		"100.64.0.0/10",      // Shared Address Space (RFC 6598)
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link Local
		"172.16.0.0/12",      // Private-Use (RFC 1918)
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1
		"192.31.196.0/24",    // AS112-v4
		"192.52.193.0/24",    // AMT
		"192.88.99.0/24",     // 6to4 Relay Anycast
		"192.168.0.0/16",     // Private-Use (RFC 1918)
		"192.175.48.0/24",    // Direct Delegation AS112 Service
		"198.18.0.0/15",      // Benchmarking
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved for Future Use

		"::/128",             // Unspecified Address
		"::1/128",            // Loopback Address
		"::/96",              // IPv4-compatible Address
		"::ffff:0:0/96",      // IPv4-mapped Address
		"0100::/64",          // Discard-Only Address Block
		"64:ff9b::/96",       // IPv4-IPv6 Translation
		"64:ff9b:1::/48",     // IPv4-IPv6 Translation Local
		"2001:2::/48",        // Benchmarking
		"2001:3::/32",        // AMT
		"2001:4:112::/48",    // AS112-v6
		"2001:10::/28",       // ORCHIDv2
		"2001:20::/28",       // ORCHIDv2
		"2001:db8::/32",      // Documentation
		"3ffe::/16",          // 6bone
		"fc00::/7",           // Unique-Local
		"fe80::/10",          // Linked-Scoped Unicast
		"fec0::/10",          // Site-Local
		"ff00::/8",           // Multicast
	}
	for _, p := range prefixes {
		// MustParsePrefix safely enforces termination if invalid configurations are supplied at compile time
		bogonPrefixes = append(bogonPrefixes, netip.MustParsePrefix(p))
	}
}

// ---------------------------------------------------------------------------
// Target Name Policy Check
// ---------------------------------------------------------------------------

// checkTargetNames performs deep inspection on incoming Answer records, scrutinizing 
// CNAME chains, Service Bindings (SVCB/HTTPS), and MX/NS delegations.
// If any downstream target domain matches a block policy natively, the entire response 
// is categorically blocked, thwarting attackers who attempt to bypass domain blocks 
// via nested CNAME aliases.
func checkTargetNames(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, clientMAC, clientIP string, clientAddr netip.Addr, clientName, clientID, protocol, sni, path string, bypassPolicies bool, originalQName string) bool {
	if !cfg.Server.TargetName {
		return false
	}

	for _, rr := range resp.Answer {
		var target string
		var targetAddr netip.Addr

		// Extract target hostnames and endpoint addresses securely from the structural payload
		switch rec := rr.(type) {
		case *dns.CNAME:
			target = rec.Target
		case *dns.MX:
			target = rec.Mx
		case *dns.NS:
			target = rec.Ns
		case *dns.PTR:
			target = rec.Ptr
		case *dns.SRV:
			target = rec.Target
		case *dns.SOA:
			target = rec.Ns 
		case *dns.SVCB:
			target = rec.Target
		case *dns.HTTPS:
			target = rec.Target
		case *dns.A:
			if a, ok := netip.AddrFromSlice(rec.A); ok {
				targetAddr = a.Unmap()
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(rec.AAAA); ok {
				targetAddr = a.Unmap()
			}
		default:
			continue 
		}

		// Bypass empty or root targets natively
		if !targetAddr.IsValid() && (target == "" || target == ".") {
			continue
		}

		if target != "" {
			target = lowerTrimDot(target)
		}

		// -------------------------------------------------------------------
		// 1. Evaluate against Global Domain Policies
		// -------------------------------------------------------------------
		if target != "" && hasDomainPolicy.Load() && !bypassPolicies {
			policyAction, policyBlocked, policyMatched, _, _, _ := walkDomainMaps(target)
			if policyBlocked {
				IncrBlockedDomain(target, "Domain Policy Target ("+policyMatched+")")
				recordRecentBlock(clientIP, target, "Domain Policy Target ("+policyMatched+")")
				
				if policyAction == PolicyActionBlock && globalBlockAction == BlockActionLog {
					if logQueries {
						log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK TARGET (LOG ONLY) (Domain Policy (%s)) | %s",
							protocol, clientID,
							originalQName, dns.TypeToString[r.Question[0].Qtype], policyMatched, getBlockActionLogStr(r.Question[0].Qtype))
					}
					return false // Bypass
				}
				
				// Execute the enforced block action natively
				dropped := writePolicyAction(w, r, policyAction)
				
				if logQueries {
					var actionLogStr string
					if policyAction == PolicyActionBlock {
						actionLogStr = getBlockActionLogStr(r.Question[0].Qtype)
					} else if policyAction == PolicyActionDrop {
						actionLogStr = "DROP"
					} else {
						actionLogStr = dns.RcodeToString[policyAction]
						if actionLogStr == "" {
							actionLogStr = fmt.Sprintf("RCODE:%d", policyAction)
						}
					}
					
					statusMark := "POLICY BLOCK TARGET"
					if dropped { statusMark = "POLICY DROP TARGET" }
					
					log.Printf("[DNS] [%s] %s -> %s %s | %s (Domain Policy (%s)) | %s",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], statusMark, policyMatched, actionLogStr)
				}
				return true
			}
		}

		// -------------------------------------------------------------------
		// 2. Evaluate against Parental Control Profiles
		// -------------------------------------------------------------------
		if hasParental && (clientMAC != "" || clientIP != "" || clientName != "" || sni != "" || path != "") {
			// Trigger standard parental checking logic using the discovered target or IP.
			// Set silentStats=true to prevent duplicate scalar counters. 
			// Inherit bypassPolicies state to honor explicit Custom Rule overrides downstream.
			blocked, blockTTL, _, reason, cat, matchedApex := CheckParental(clientMAC, clientIP, clientAddr, clientName, sni, path, target, targetAddr, true, bypassPolicies)
			if blocked {
				IncrParentalBlock()
				
				domainStr := target
				if domainStr == "" && targetAddr.IsValid() {
					domainStr = targetAddr.String()
				}
				
				IncrBlockedDomain(domainStr, reason+" (Target)")
				recordRecentBlock(clientIP, domainStr, reason+" (Target)")

				if globalBlockAction == BlockActionDrop {
					if logQueries {
						log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL DROP TARGET | DROP",
							protocol, clientID,
							originalQName, dns.TypeToString[r.Question[0].Qtype])
					}
					return true
				} else if globalBlockAction == BlockActionLog {
					if logQueries {
						catStr := ""
						if cat != "" {
							catStr = fmt.Sprintf(" (Category: %s, apex: %s)", cat, matchedApex)
						}
						log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK TARGET (LOG ONLY)%s | %s",
							protocol, clientID,
							originalQName, dns.TypeToString[r.Question[0].Qtype], catStr, getBlockActionLogStr(r.Question[0].Qtype))
					}
					return false 
				} else {
					blockResp := generateBlockMsg(r, blockTTL)
					_ = w.WriteMsg(blockResp)
					msgPool.Put(blockResp)
	
					if logQueries {
						rcodeStr := getBlockActionLogStr(r.Question[0].Qtype)
						catStr := ""
						if cat != "" {
							catStr = fmt.Sprintf(" (Category: %s, apex: %s)", cat, matchedApex)
						}
						log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK TARGET%s | %s",
							protocol, clientID,
							originalQName, dns.TypeToString[r.Question[0].Qtype], catStr, rcodeStr)
					}
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// IP Filter Policy Check
// ---------------------------------------------------------------------------

// filterResponseIPs dynamically strips explicitly blocked IP endpoints from 
// upstream Answer sections natively. If all valid endpoints are stripped, the 
// query is fully denied to prevent the client from accessing the forbidden addresses.
func filterResponseIPs(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, clientMAC, clientIP string, clientAddr netip.Addr, clientName, clientID, protocol, sni, path string, bypassPolicies bool, originalQName, originalQNameTrimmed string) bool {
	if !cfg.Server.FilterIPs || len(resp.Answer) == 0 {
		return false
	}

	var keptAnswers []dns.RR
	var filteredCount int
	var totalIPs int

	var blockCat string
	var blockApex string
	var blockBlockTTL uint32

	for _, rr := range resp.Answer {
		var targetAddr netip.Addr
		isIP := false
		
		switch rec := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(rec.A); ok {
				targetAddr = a.Unmap()
				isIP = true
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(rec.AAAA); ok {
				targetAddr = a.Unmap()
				isIP = true
			}
		}

		// Natively bypass constraint evaluations on non-IP records
		if !isIP {
			keptAnswers = append(keptAnswers, rr)
			continue
		}

		totalIPs++

		// Execute Parental check utilizing the physical IP strict struct rather than generating heap strings
		blocked, blockTTL, _, reason, cat, matchedApex := CheckParental(clientMAC, clientIP, clientAddr, clientName, sni, path, "", targetAddr, true, bypassPolicies)

		// Dynamically evaluate Domain Policy for explicit IP String matches natively if not bypassed
		if !blocked && hasDomainPolicy.Load() && !bypassPolicies {
			// [PERF/FIX] Check Domain Policy CIDRs natively directly against the unpacked IP payload.
			// Explicitly omits walkDomainMaps(targetAddr.String()) to prevent catastrophic 
			// CPU cycle waste doing domain suffix-walking (e.g. 192.168.1.1 -> 168.1.1 -> 1.1) on raw IP strings.
			if cidrs := domainPolicyCIDRSnap.Load(); cidrs != nil {
				for _, c := range *cidrs {
					if c.prefix.Contains(targetAddr) {
						blocked = true
						blockTTL = syntheticTTL
						reason = "Domain Policy IP Filter (" + c.prefix.String() + ")"
						break
					}
				}
			}
		}

		if blocked {
			filteredCount++
			blockCat = cat
			blockApex = matchedApex
			blockBlockTTL = blockTTL

			ipStr := targetAddr.String() // Lazily generate log string only if explicitly blocked

			IncrFilteredIP(ipStr, originalQNameTrimmed)
			IncrBlockedDomain(originalQNameTrimmed, reason+" (IP Filter: "+ipStr+" rule: "+matchedApex+")")
			recordRecentBlock(clientIP, originalQNameTrimmed, reason+" (IP Filter: "+ipStr+" rule: "+matchedApex+")")

			if globalBlockAction == BlockActionLog {
				// Audit mode preserves the answer securely while logging the hit
				keptAnswers = append(keptAnswers, rr) 
				if logQueries {
					catStr := ""
					if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, rule: %s)", cat, matchedApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL IP FILTERED (LOG ONLY)%s | Retained %s",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], catStr, ipStr)
				}
			} else {
				if logQueries {
					catStr := ""
					if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, rule: %s)", cat, matchedApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL IP FILTERED%s | Removed %s",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], catStr, ipStr)
				}
			}
		} else {
			keptAnswers = append(keptAnswers, rr)
		}
	}

	// Sinkhole the connection entirely if all viable connection paths were stripped
	if filteredCount > 0 && totalIPs > 0 && len(keptAnswers) == 0 {
		IncrParentalBlock()

		if globalBlockAction == BlockActionDrop {
			if logQueries {
				catStr := ""
				if blockCat != "" {
					catStr = fmt.Sprintf(" (Category: %s, rule: %s)", blockCat, blockApex)
				}
				log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL DROP IP FILTER%s | DROP",
					protocol, clientID,
					originalQName, dns.TypeToString[r.Question[0].Qtype], catStr)
			}
			return true
		}

		blockResp := generateBlockMsg(r, blockBlockTTL)
		_ = w.WriteMsg(blockResp)
		msgPool.Put(blockResp)

		if logQueries {
			rcodeStr := getBlockActionLogStr(r.Question[0].Qtype)
			catStr := ""
			if blockCat != "" {
				catStr = fmt.Sprintf(" (Category: %s, rule: %s)", blockCat, blockApex)
			}
			log.Printf("[DNS] [%s] %s -> %s %s | PARENTAL BLOCK IP FILTER%s | %s",
				protocol, clientID,
				originalQName, dns.TypeToString[r.Question[0].Qtype], catStr, rcodeStr)
		}
		return true
	}

	// Persist the filtered arrays natively
	resp.Answer = keptAnswers
	return false
}

// ---------------------------------------------------------------------------
// DNS Rebinding Protection (SSRF Prevention)
// ---------------------------------------------------------------------------

// filterRebinding intercepts external, upstream DNS responses attempting to pivot 
// clients towards localized, private, or loopback networks. This completely 
// neutralizes malicious payloads intended to exploit local services 
// (Server-Side Request Forgery).
func filterRebinding(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, clientIP string, clientAddr netip.Addr, clientName, clientID, protocol, originalQName, originalQNameTrimmed string) bool {
	if !hasRebindingProtection || len(resp.Answer) == 0 {
		return false
	}

	bogonDetected := false
	var blockedIP string

	for _, rr := range resp.Answer {
		var addr netip.Addr
		switch rec := rr.(type) {
		case *dns.A:
			a, ok := netip.AddrFromSlice(rec.A)
			if ok {
				addr = a.Unmap()
			}
		case *dns.AAAA:
			a, ok := netip.AddrFromSlice(rec.AAAA)
			if ok {
				addr = a.Unmap()
			}
		}

		// Natively evaluate the unpacked address against the rigid bogon prefix arrays
		if addr.IsValid() {
			for _, p := range bogonPrefixes {
				if p.Contains(addr) {
					bogonDetected = true
					blockedIP = addr.String()
					break
				}
			}
		}
		if bogonDetected {
			break
		}
	}

	if bogonDetected {
		IncrRebindingBlock()
		IncrBlockedDomain(originalQNameTrimmed, "DNS Rebinding Protection")
		recordRecentBlock(clientIP, originalQNameTrimmed, "DNS Rebinding Protection")

		if globalBlockAction == BlockActionLog {
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | BLOCKED (DNS Rebinding/Bogon IP: %s) (LOG ONLY) | %s",
					protocol, clientID,
					originalQName, dns.TypeToString[r.Question[0].Qtype], blockedIP, getBlockActionLogStr(r.Question[0].Qtype))
			}
			return false 
		} else if globalBlockAction == BlockActionDrop {
			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | DROPPED (DNS Rebinding/Bogon IP: %s) | DROP",
					protocol, clientID,
					originalQName, dns.TypeToString[r.Question[0].Qtype], blockedIP)
			}
			return true
		}

		blockResp := generateBlockMsg(r, syntheticTTL)
		_ = w.WriteMsg(blockResp)
		msgPool.Put(blockResp)
		
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | BLOCKED (DNS Rebinding/Bogon IP: %s) | %s",
				protocol, clientID,
				originalQName, dns.TypeToString[r.Question[0].Qtype], blockedIP, getBlockActionLogStr(r.Question[0].Qtype))
		}
		return true
	}

	return false
}

