/*
File:    process_filters.go
Version: 2.31.0
Last Updated: 22-Oct-2026 13:35 CEST

Description:
  Verbose Deep Packet Filtering operations for Target-Names and IP Addresses.
  This file evaluates DNS response payloads deeply to prevent Server-Side 
  Request Forgery (SSRF) via DNS Rebinding, filters out blocked IP addresses 
  natively, and guarantees strict adherence to RFC 1035 QNAME syntax bounds.

Changes:
  2.31.0 - [FEAT] Propagated `ednsMAC` into `checkTargetNames` and `filterResponseIPs`
           so `CheckParental` can derive `mac:<mac>` device keys when `device`
           budget tracking is used on EDNS0 Option 65001 (`mac:`) parental routes.
  2.30.0 - [FIX] Propagated `ecsAddr` into `checkTargetNames` and `filterResponseIPs`
           so `CheckParental` can derive `ecs:<ip>` device keys when `device`
           budget tracking is used on `ecs:` parental routes.
  2.29.0 - [SECURITY/FIX] Cloned `resp.Answer` slice before mutating it in
           `filterResponseIPs`. When `transformResponse` is a no-op (both
           `flatten_cname` and `minimize_answer` are false), `resp.Answer`
           may share its backing array or RR structs with caller/cache buffers.
           Allocating a fresh slice when filtering occurs guarantees isolation.
         - [SECURITY/FIX] Added RFC 2308 negative SOA record when `filterResponseIPs`
           strips all A/AAAA records and leaves an empty Answer section (NODATA).
  2.28.0 - [FIX] Propagated `localPort` into `checkTargetNames` and `filterResponseIPs`
           so `CheckParental` can derive `port:<port>` device keys when `device`
           budget tracking is used on port-based parental routes.
  2.27.0 - [SECURITY/FIX] Added RFC 2308 negative SOA synthesis in `filterResponseIPs`
           when all A/AAAA records are stripped in `LOG` mode or when a custom-IP
           block returns a 0-answer `NOERROR` (NODATA) response.
         - [FEAT/FIX] Allowed `checkTargetNames` parental checks to run when `sk`
           or `clientGroup` is already resolved (e.g. via `port:` routes).
  2.26.0 - [SECURITY/FIX] Eradicated a critical CNAME Rebinding evasion vector within 
           `checkTargetNames`.
  2.25.0 - [DEAD-CODE/CLEANUP] Eradicated unused `clientAddr` and `clientName` 
           parameters natively from the `filterRebinding` evaluation signature.
  2.24.0 - [CLEANUP] Simplified `validQNAMEChars` instantiation matrix.
  2.23.0 - [PERF/CLEANUP] Cleaned `bogonPrefixes` initialization sequence.
  2.22.0 - [FEAT] Bypassed Domain Policy target checks when `bypassGlobal` is active.
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

var validQNAMEChars = func() [256]bool {
	var v [256]bool
	for i := '0'; i <= '9'; i++ { v[i] = true }
	for i := 'a'; i <= 'z'; i++ { v[i] = true }
	for i := 'A'; i <= 'Z'; i++ { v[i] = true }
	v['-'] = true
	v['_'] = true
	v['*'] = true
	v['/'] = true
	v['+'] = true
	v['='] = true
	return v
}()

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
			if labelLen == 0 || labelLen > 63 {
				return false
			}
			if lastChar == '-' {
				return false
			}
			labelLen = 0
			lastChar = c
			continue
		}

		if labelLen == 0 && c == '-' {
			return false
		}

		if !validQNAMEChars[c] {
			return false
		}

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

	if labelLen > 0 {
		if labelLen > 63 || lastChar == '-' {
			return false
		}
	}

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

var bogonPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "This network"
	netip.MustParsePrefix("10.0.0.0/8"),         // Private-Use (RFC 1918)
	netip.MustParsePrefix("100.64.0.0/10"),      // Shared Address Space (RFC 6598)
	netip.MustParsePrefix("127.0.0.0/8"),        // Loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // Link Local
	netip.MustParsePrefix("172.16.0.0/12"),      // Private-Use (RFC 1918)
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF Protocol Assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("192.31.196.0/24"),    // AS112-v4
	netip.MustParsePrefix("192.52.193.0/24"),    // AMT
	netip.MustParsePrefix("192.88.99.0/24"),     // 6to4 Relay Anycast
	netip.MustParsePrefix("192.168.0.0/16"),     // Private-Use (RFC 1918)
	netip.MustParsePrefix("192.175.48.0/24"),    // Direct Delegation AS112 Service
	netip.MustParsePrefix("198.18.0.0/15"),      // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),        // Multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // Reserved for Future Use

	netip.MustParsePrefix("::/128"),             // Unspecified Address
	netip.MustParsePrefix("::1/128"),            // Loopback Address
	netip.MustParsePrefix("::/96"),              // IPv4-compatible Address
	netip.MustParsePrefix("::ffff:0:0/96"),      // IPv4-mapped Address
	netip.MustParsePrefix("0100::/64"),          // Discard-Only Address Block
	netip.MustParsePrefix("64:ff9b::/96"),       // IPv4-IPv6 Translation
	netip.MustParsePrefix("64:ff9b:1::/48"),     // IPv4-IPv6 Translation Local
	netip.MustParsePrefix("2001:2::/48"),        // Benchmarking
	netip.MustParsePrefix("2001:3::/32"),        // AMT
	netip.MustParsePrefix("2001:4:112::/48"),    // AS112-v6
	netip.MustParsePrefix("2001:10::/28"),       // ORCHIDv2
	netip.MustParsePrefix("2001:20::/28"),       // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"),      // Documentation
	netip.MustParsePrefix("3ffe::/16"),          // 6bone
	netip.MustParsePrefix("fc00::/7"),           // Unique-Local
	netip.MustParsePrefix("fe80::/10"),          // Linked-Scoped Unicast
	netip.MustParsePrefix("fec0::/10"),          // Site-Local
	netip.MustParsePrefix("ff00::/8"),           // Multicast
}

// ---------------------------------------------------------------------------
// Target Name Policy Check
// ---------------------------------------------------------------------------

func checkTargetNames(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, sk, clientGroup, clientMAC, ednsMAC, clientIP string, clientAddr, ecsAddr netip.Addr, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, localPort string, bypassPolicies bool, bypassGlobal bool, originalQName string) bool {
	if !cfg.Server.TargetName {
		return false
	}

	for _, rr := range resp.Answer {
		var target string
		var targetAddr netip.Addr

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

		if !targetAddr.IsValid() && (target == "" || target == ".") {
			continue
		}

		if target != "" {
			target = lowerTrimDot(target)
			if target != "" && !isValidQNAME(target, dns.TypeA) {
				continue
			}
		}

		// 1. Evaluate against Global Domain Policies
		if target != "" && hasDomainPolicy.Load() && !bypassPolicies && !bypassGlobal {
			policyAction, policyBlocked, policyMatched, _, _, _ := walkDomainMaps(target)
			if policyBlocked {
				IncrPolicyBlock()
				RecordBlockEvent(clientIP, target, "Domain Policy Target ("+policyMatched+")")

				if policyAction == PolicyActionBlock && globalBlockAction == BlockActionLog {
					if logQueries {
						log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK TARGET (LOG ONLY) (Domain Policy (%s)) | %s",
							protocol, clientID,
							originalQName, dns.TypeToString[r.Question[0].Qtype], policyMatched, getBlockActionLogStr(r.Question[0].Qtype))
					}
					return false
				}

				dropped := writePolicyAction(w, r, policyAction)

				if logQueries {
					var actionLogStr string
					if policyAction == PolicyActionBlock {
						actionLogStr = getBlockActionLogStr(r.Question[0].Qtype)
					} else if policyAction == PolicyActionDrop {
						actionLogStr = "DROP"
					} else {
						actionLogStr = RcodeStr(policyAction)
					}

					statusMark := "POLICY BLOCK TARGET"
					if dropped {
						statusMark = "POLICY DROP TARGET"
					}

					log.Printf("[DNS] [%s] %s -> %s %s | %s (Domain Policy (%s)) | %s",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], statusMark, policyMatched, actionLogStr)
				}
				return true
			}
		}

		// 2. Evaluate against Parental Control Profiles
		if hasParental && (sk != "" || clientGroup != "" || clientMAC != "" || ednsMAC != "" || clientIP != "" || ecsAddr.IsValid() || clientName != "" || sni != "" || path != "" || localPort != "") {
			blocked, blockTTL, _, reason, cat, matchedApex := CheckParental(sk, clientGroup, clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort, target, targetAddr, true, bypassPolicies)
			if blocked {
				IncrParentalBlock()

				domainStr := target
				if domainStr == "" && targetAddr.IsValid() {
					domainStr = targetAddr.String()
				}

				RecordBlockEvent(clientIP, domainStr, reason+" (Target)")

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

func filterResponseIPs(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, sk, clientGroup, clientMAC, ednsMAC, clientIP string, clientAddr, ecsAddr netip.Addr, clientName, clientNameLower, clientID, protocol, sni, sniLower, path, pathLower, localPort string, bypassPolicies bool, bypassGlobal bool, originalQName, originalQNameTrimmed string) bool {
	if !cfg.Server.FilterIPs || len(resp.Answer) == 0 {
		return false
	}

	var keptAnswers []dns.RR
	var filteredCount int
	var totalIPs int

	var blockCat string
	var blockApex string
	var blockBlockTTL uint32
	var blockReason string

	for i, rr := range resp.Answer {
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

		if !isIP {
			if keptAnswers != nil {
				keptAnswers = append(keptAnswers, rr)
			}
			continue
		}

		totalIPs++

		blocked, blockTTL, _, reason, cat, matchedApex := CheckParental(sk, clientGroup, clientMAC, ednsMAC, clientIP, clientAddr, ecsAddr, clientName, clientNameLower, sni, sniLower, path, pathLower, localPort, "", targetAddr, true, bypassPolicies)

		if !blocked && hasDomainPolicy.Load() && !bypassPolicies && !bypassGlobal {
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
			if keptAnswers == nil {
				keptAnswers = make([]dns.RR, 0, len(resp.Answer))
				for j := 0; j < i; j++ {
					keptAnswers = append(keptAnswers, resp.Answer[j])
				}
			}
			filteredCount++
			blockCat = cat
			blockApex = matchedApex
			blockBlockTTL = blockTTL
			blockReason = reason

			ipStr := targetAddr.String()

			IncrFilteredIP(ipStr, originalQNameTrimmed)
			RecordBlockEvent(clientIP, originalQNameTrimmed, reason+" (IP Filter: "+ipStr+" rule: "+matchedApex+")")

			if globalBlockAction == BlockActionLog {
				keptAnswers = append(keptAnswers, rr)
				if logQueries {
					catStr := ""
					logPrefix := "PARENTAL"
					if strings.HasPrefix(reason, "Domain Policy") {
						logPrefix = "POLICY"
						if start := strings.Index(reason, "("); start != -1 {
							catStr = " " + reason[start:]
						}
					} else if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, rule: %s)", cat, matchedApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | %s IP FILTERED (LOG ONLY)%s | Retained %s",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], logPrefix, catStr, ipStr)
				}
			} else {
				if logQueries {
					catStr := ""
					logPrefix := "PARENTAL"
					if strings.HasPrefix(reason, "Domain Policy") {
						logPrefix = "POLICY"
						if start := strings.Index(reason, "("); start != -1 {
							catStr = " " + reason[start:]
						}
					} else if cat != "" {
						catStr = fmt.Sprintf(" (Category: %s, rule: %s)", cat, matchedApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | %s IP FILTERED%s | Removed %s",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], logPrefix, catStr, ipStr)
				}
			}
		} else {
			if keptAnswers != nil {
				keptAnswers = append(keptAnswers, rr)
			}
		}
	}

	if filteredCount > 0 {
		// Check if any terminal A/AAAA records survived in keptAnswers.
		remainingIPs := 0
		for _, rr := range keptAnswers {
			if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
				remainingIPs++
			}
		}

		if totalIPs > 0 && remainingIPs == 0 {
			if strings.HasPrefix(blockReason, "Domain Policy") {
				IncrPolicyBlock()
			} else {
				IncrParentalBlock()
			}

			if globalBlockAction == BlockActionDrop {
				if logQueries {
					catStr := ""
					logPrefix := "PARENTAL"
					if strings.HasPrefix(blockReason, "Domain Policy") {
						logPrefix = "POLICY"
						if start := strings.Index(blockReason, "("); start != -1 {
							catStr = " " + blockReason[start:]
						}
					} else if blockCat != "" {
						catStr = fmt.Sprintf(" (Category: %s, rule: %s)", blockCat, blockApex)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | %s DROP IP FILTER%s | DROP",
						protocol, clientID,
						originalQName, dns.TypeToString[r.Question[0].Qtype], logPrefix, catStr)
				}
				return true
			}

			blockResp := generateBlockMsg(r, blockBlockTTL)
			_ = w.WriteMsg(blockResp)
			msgPool.Put(blockResp)

			if logQueries {
				rcodeStr := getBlockActionLogStr(r.Question[0].Qtype)
				catStr := ""
				logPrefix := "PARENTAL"
				if strings.HasPrefix(blockReason, "Domain Policy") {
					logPrefix = "POLICY"
					if start := strings.Index(blockReason, "("); start != -1 {
						catStr = " " + blockReason[start:]
					}
				} else if blockCat != "" {
					catStr = fmt.Sprintf(" (Category: %s, rule: %s)", blockCat, blockApex)
				}
				log.Printf("[DNS] [%s] %s -> %s %s | %s BLOCK IP FILTER%s | %s",
					protocol, clientID,
					originalQName, dns.TypeToString[r.Question[0].Qtype], logPrefix, catStr, rcodeStr)
			}
			return true
		}

		resp.Answer = keptAnswers
		if len(resp.Answer) == 0 && len(r.Question) > 0 {
			SetNegativeSOA(resp, r.Question[0].Name, syntheticTTL)
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// DNS Rebinding Protection (SSRF Prevention)
// ---------------------------------------------------------------------------

func filterRebinding(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg, clientIP string, clientID, protocol, originalQName, originalQNameTrimmed string) bool {
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

		if addr.IsValid() {
			if addr.IsUnspecified() {
				continue
			}

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
		RecordBlockEvent(clientIP, originalQNameTrimmed, "DNS Rebinding Protection")

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
