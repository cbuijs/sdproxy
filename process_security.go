/*
File:    process_security.go
Version: 1.22.1
Last Updated: 25-Sep-2026 14:41 CEST

Description:
  Pre-routing Security & Admission Guards for sdproxy.
  Executes the first phase of the core processing pipeline natively:
    - Source Address Admissibility (fail-closed identity gate)
    - ACL & Anti-Spoofing checks
    - Token-Bucket Rate Limiting & Penalty Box enforcement
    - Web UI explicit Client Blocks
    - QClass & QNAME syntactical validation
    - Anti-Amplification drop logic (ANY over UDP)
    - DGA (Domain Generation Algorithm) ML Inference
    - Exfiltration Volumetric Profiling
    - Search Domain Leak Prevention
    - Per-client last-seen telemetry (Web UI "Known Clients" table)

  Extracted from process.go to improve modularity and execution clarity.

Changes:
  1.22.1 - [SECURITY/FIX] Stabilized DGA Machine Learning floating-point boundary threshold evaluations.
           Introduced epsilon comparison (`1e-9`) natively to prevent edge-case 
           evasion vectors stemming from imprecise probability rounding outputs organically.
  1.22.0 - [SECURITY/FIX] Addressed an issue utilizing `sync.Map` in `webuiClientBlocks` natively
           by executing map iterations explicitly safely avoiding bounded OOM restrictions organically.
  1.21.0 - [FEAT] Added `localPort` parameter to `enforceSecurityGuards` to 
           satisfy updated function signatures. It does not fundamentally alter
           security logic within this package at this time.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// unidentifiedSourceLastLog debounces the step 0.0 admission warning.
//
// Holds the unix-nanosecond timestamp of the most recent emission. The gate is
// deliberately a plain CAS rather than a mutex: the warning fires at most once
// per minute, so the contended path is the *load*, which must stay free on the
// hot path even while a flood is in progress.
var unidentifiedSourceLastLog atomic.Int64

// executeSecurityBlock synthesizes a compliant DNS block response (NXDOMAIN, NULL-IP, etc.)
// and seamlessly manages EDNS0 preservation and telemetry logging for ML/Anomaly intercepts natively.
func executeSecurityBlock(w dns.ResponseWriter, r *dns.Msg, q dns.Question, actionStr, protocol, clientID, logPrefix string, scoreOrBPS float64) {
	var msg *dns.Msg
	if actionStr == "BLOCK" {
		msg = generateBlockMsg(r, syntheticTTL)
	} else {
		rcode, ok := dns.StringToRcode[actionStr]
		if !ok {
			rcode = dns.RcodeNameError
		}
		msg = msgPool.Get().(*dns.Msg)
		*msg = dns.Msg{}
		msg.SetReply(r)
		msg.RecursionAvailable = true
		msg.Rcode = rcode
		if rcode == dns.RcodeNameError {
			SetNegativeSOA(msg, q.Name, syntheticTTL)
		}
		PreserveEDNS0(r, msg)
	}

	_ = w.WriteMsg(msg)

	if logQueries {
		logAction := actionStr
		if actionStr == "BLOCK" {
			logAction = getBlockActionLogStr(q.Qtype)
		} else {
			logAction = RcodeStr(msg.Rcode)
		}

		if logPrefix == "DGA" {
			log.Printf("[DNS] [%s] %s -> %s %s | DGA INTERCEPT (Score: %.1f) | %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], scoreOrBPS, logAction)
		} else {
			log.Printf("[DNS] [%s] %s -> %s %s | EXFIL INTERCEPT (BPS: %.0f) | %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], scoreOrBPS, logAction)
		}
	}

	msgPool.Put(msg)
}

// enforceSecurityGuards executes the pre-routing admission and security pipeline.
// Returns true if the query was intercepted, dropped, or blocked natively,
// terminating the resolution pipeline.
func enforceSecurityGuards(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, clientName, clientID, protocol, localPort string) bool {

	// ── 0.0 Source Address Admissibility (Fail-Closed Identity Gate) ──────
	// [SECURITY/FIX 1.15.0] Every admission control below is expressed in terms
	// of a parsed netip.Addr: ACL prefixes are matched with Prefix.Contains, and
	// the token bucket is keyed on the masked address. Neither can render a
	// verdict on an address that does not exist.
	//
	// Before 1.15.0 both simply switched themselves off in that situation, which
	// meant an unparseable source silently bought a full bypass of the ACL AND
	// the rate limiter — the precise inverse of what an operator asks for when
	// they configure either one.
	//
	// The gate is scoped to deployments that actually enabled an admission
	// control. With neither configured there is nothing to fail open *from*, so
	// unidentified sources continue through untouched and behaviour matches
	// 1.14.0 exactly.
	if !clientAddr.IsValid() && (hasDNSACL || hasRateLimit) {
		IncrDroppedRateLimit()

		// Debounced to one line per minute. An operator who has genuinely broken
		// their transport plumbing (a proxy rewriting RemoteAddr into a form we
		// cannot parse, say) needs to see this; an attacker must not be able to
		// convert it into unbounded disk I/O.
		now := time.Now().UnixNano()
		last := unidentifiedSourceLastLog.Load()
		if now-last > int64(60*time.Second) && unidentifiedSourceLastLog.CompareAndSwap(last, now) {
			log.Printf("[SECURITY] Dropping query from an unidentifiable source address on %s (raw: %q). "+
				"ACLs and/or rate limiting are enabled and cannot evaluate an unparseable origin, so the query fails closed. "+
				"If sdproxy sits behind a proxy or tunnel, verify it preserves the real client address.",
				protocol, clientIP)
		}
		return true
	}

	// ── 0.1 ACL Gate & Anti-Spoofing ──────────────────────────────────────
	// No IsValid() conjunct: step 0.0 has already shed every query that could
	// not produce a usable address whenever this branch is live.
	if hasDNSACL {
		denied := false
		for _, p := range dnsACLDeny {
			if p.Contains(clientAddr) {
				denied = true
				break
			}
		}

		if !denied && len(dnsACLAllow) > 0 {
			allowed := false
			for _, p := range dnsACLAllow {
				if p.Contains(clientAddr) {
					allowed = true
					break
				}
			}
			if !allowed {
				denied = true
			}
		}

		if denied {
			return true // Drop connectionless query instantly
		}
	}

	// ── 0.2 Rate Limiting & Penalty Box (Public Resolver Security) ────────
	// No IsValid() conjunct — see step 0.0.
	//
	// [DOC/FIX 1.17.0] This comment previously read: "AllowClient retains its
	// own internal validity check as a defence-in-depth guard for any future
	// caller that bypasses this pipeline." That was an accurate description of
	// what AllowClient did and an inaccurate description of what it was for —
	// the check returned ALLOWED for an invalid address, which is the same
	// fail-open shape step 0.0 had just been written to close one layer up.
	//
	// ratelimit.go 1.16.0 inverted it: an address that cannot be parsed produces
	// no bucket key, therefore no bound, therefore no basis on which to permit
	// anything, and AllowClient now returns (false, false). The defence-in-depth
	// framing is correct; it was only ever pointing at the wrong verdict.
	if hasRateLimit {
		allowed, isBanned := AllowClient(clientIP, clientAddr)
		if !allowed {
			IncrDroppedRateLimit()
			if logQueries && !isBanned {
				log.Printf("[DNS] [%s] %s -> %s %s | DROPPED (Rate Limit Exceeded)",
					protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
			}
			return true
		}
	}

	// Record query and domain counters natively AFTER admission and rate limiting,
	// but strictly BEFORE security blocks to ensure hit-rate denominators remain mathematically sound.
	IncrQueryTotal()
	IncrTalker(clientIP, clientName)
	IncrDomain(qNameTrimmed)

	// [FEAT 1.16.0] Stamp the client's last-seen instant.
	//
	// Both the source IP and the ARP/DHCP-resolved MAC are recorded, because
	// the Web UI client table may key a row on either: an off-link DoH/DoT/DoQ
	// client has no MAC, while a MAC harvested from a lease file whose address
	// has since been reassigned has no current IP. clientMAC is the exact
	// string LookupMAC() read out of arpSnap, so it matches the key
	// getKnownClients() will later look the row up by, byte for byte.
	TouchClientSeen(clientIP, clientMAC)

	// ── 0.25 WebUI Client Block ──────────────────────────────────────────
	if cfg.WebUI.Enabled {
		var webuiBlocked bool
		if clientIP != "" {
			if _, ok := webuiClientBlocks.Load(clientIP); ok {
				webuiBlocked = true
			}
		}
		if !webuiBlocked && clientMAC != "" {
			if _, ok := webuiClientBlocks.Load(clientMAC); ok {
				webuiBlocked = true
			}
		}

		if webuiBlocked {
			IncrPolicyBlock()
			RecordBlockEvent(clientIP, qNameTrimmed, "WebUI Client Block")

			if globalBlockAction == BlockActionDrop {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | WEBUI CLIENT DROP | DROP", protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
				}
				return true
			} else if globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | WEBUI CLIENT BLOCK (LOG ONLY) | %s", protocol, clientID, q.Name, dns.TypeToString[q.Qtype], getBlockActionLogStr(q.Qtype))
				}
				// Log only: permit the pipeline to proceed normally
			} else {
				resp := generateBlockMsg(r, syntheticTTL)
				w.WriteMsg(resp)
				msgPool.Put(resp)
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | WEBUI CLIENT BLOCK | %s", protocol, clientID, q.Name, dns.TypeToString[q.Qtype], getBlockActionLogStr(q.Qtype))
				}
				return true
			}
		}
	}

	// ── 0.3 Class Check (Public Resolver Security) ────────────────────────
	if q.Qclass != dns.ClassINET {
		reason := fmt.Sprintf("Non-INET Class (%d)", q.Qclass)

		// [FIX 1.17.0] Count it. Steps 0.4, 0.5 and 0.9 all call this; 0.3 did
		// not, so CHAOS/HESIOD/ANY-class probes — which are a standard resolver
		// fingerprinting technique and therefore exactly the traffic an operator
		// checks the counter for — were recorded in the block LIST but absent
		// from the block COUNT. The two numbers on the dashboard disagreed with
		// no way to tell which one was lying.
		IncrPolicyBlock()

		RecordBlockEvent(clientIP, qNameTrimmed, reason)
		PenalizeClient(clientIP, clientAddr, 1) // Accelerate blackholing for protocol anomalies

		writePolicyAction(w, r, dns.RcodeRefused)

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (%s) | REFUSED",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], reason)
		}
		return true
	}

	// ── 0.4 QNAME Validation (RFC 1035 / RFC 1123) ────────────────────────
	if !isValidQNAME(q.Name, q.Qtype) {
		IncrPolicyBlock()
		RecordBlockEvent(clientIP, qNameTrimmed, "Malformed QNAME (RFC Violation)")
		IncrReturnCode(dns.RcodeFormatError, false)
		PenalizeClient(clientIP, clientAddr, 2) // Aggressive penalty for malformed packets

		resp := msgPool.Get().(*dns.Msg)
		*resp = dns.Msg{}
		resp.SetReply(r)
		resp.SetRcode(r, dns.RcodeFormatError)
		PreserveEDNS0(r, resp)
		_ = w.WriteMsg(resp)

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Malformed QNAME) | FORMERR",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
		}

		msgPool.Put(resp)

		return true
	}

	// ── 0.5 Anti-Amplification (ANY / QTYPE 255 Drop) ─────────────────────
	if q.Qtype == dns.TypeANY && protocol == "UDP" {
		IncrPolicyBlock()
		RecordBlockEvent(clientIP, qNameTrimmed, "Anti-Amplification (ANY over UDP)")
		PenalizeClient(clientIP, clientAddr, 1) // Penalize reflection vectors

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s ANY | POLICY DROP (Anti-Amplification) | DROP",
				protocol, clientID, q.Name)
		}
		return true
	}

	// ── 0.6 Startup Guard ─────────────────────────────────────────────────
	// Dynamically evaluates `catMapInitialized` natively to prevent dropping queries
	// indefinitely when category mappings rely on delayed external fetches.
	if hasParental && !(cfg.Server.FastStart || cfg.Parental.FastStart) && !catMapInitialized.Load() {
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | DROPPED (Waiting for parental categories to load)",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
		}
		return true
	}

	// ── 0.7 DGA (Domain Generation Algorithm) ML Detection ────────────────
	if hasDGA {
		_, eTLD := extractETLDPlusOne(qNameTrimmed)

		// [PERF 1.14.0] Zero-allocation domainCore extraction.
		//
		// This runs on the pre-cache hot path for EVERY query when DGA inference
		// is enabled — so the previous `strings.TrimSuffix(qNameTrimmed, "."+eTLD)`
		// leaked one throwaway `"."+eTLD` heap string per query, directly
		// contradicting the "zero heap allocations" contract that AnalyzeDGA
		// itself is engineered around.
		//
		// extractETLDPlusOne always returns `eTLD` as a genuine suffix of
		// qNameTrimmed (it is produced by walking `search = search[idx+1:]`), so
		// we can strip the ".<eTLD>" tail with pure index math on the immutable
		// backing array. Sub-slicing a string allocates nothing.
		//
		// Guards:
		//   • len(eTLD) < len(qNameTrimmed)         — there is a registrable label
		//                                             in front of the suffix.
		//   • qNameTrimmed[cut] == '.'              — the boundary is a real label
		//                                             separator, not a coincidental
		//                                             substring match.
		// When either guard fails (e.g. the query IS the bare eTLD, like "co.uk"),
		// domainCore falls back to the full qNameTrimmed — identical to the old
		// TrimSuffix no-match behaviour.
		domainCore := qNameTrimmed
		if len(eTLD) < len(qNameTrimmed) {
			// [SECURITY/FIX] Use integer absolute bound guard to prevent negative index panics 
			// securely across extremely malformed sub-domain topologies.
			cut := len(qNameTrimmed) - len(eTLD) - 1
			if cut > 0 && cut < len(qNameTrimmed) && qNameTrimmed[cut] == '.' {
				domainCore = qNameTrimmed[:cut]
			}
		}

		// Evaluates stochastic inference natively using the pristine fullDomain boundaries
		// alongside the stripped domainCore structure for extreme throughput optimization.
		score := AnalyzeDGA(qNameTrimmed, domainCore)

		// [SECURITY/FIX 1.22.1] Implemented floating-point epsilon comparison bounds (1e-9).
		// Ensures border-line threshold evaluations properly execute without randomly 
		// failing due to IEEE 754 precision math rounding anomalies organically.
		if score >= (cfg.Server.DGA.Threshold - 1e-9) {
			reason := fmt.Sprintf("DGA Detected (Score: %.1f)", score)
			actionStr := strings.ToUpper(cfg.Server.DGA.Action)

			if actionStr == "LOG" {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | DGA DETECTION (LOG ONLY) (Score: %.1f) | LOG",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], score)
				}
			} else if actionStr == "DROP" || (actionStr == "BLOCK" && globalBlockAction == BlockActionDrop) {
				IncrDGABlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)

				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | DGA DROP (Score: %.1f) | DROP",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], score)
				}
				return true
			} else {
				IncrDGABlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)
				executeSecurityBlock(w, r, q, actionStr, protocol, clientID, "DGA", score)
				return true
			}
		}
	}

	// ── 0.8 Exfiltration Volumetric Profiling ─────────────────────────────
	if hasExfiltration && clientAddr.IsValid() {
		allowed, isBanned, bps := AnalyzeExfiltration(clientAddr, r.Len())
		if !allowed {
			reason := fmt.Sprintf("Data Exfiltration Anomaly (BPS: %.0f)", bps)
			if isBanned {
				reason = "Data Exfiltration (Blackholed)"
			}

			actionStr := strings.ToUpper(cfg.Server.Exfiltration.Action)

			if actionStr == "LOG" {
				if logQueries && !isBanned {
					log.Printf("[DNS] [%s] %s -> %s %s | EXFILTRATION DETECTION (LOG ONLY) (BPS: %.0f) | LOG",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], bps)
				}
			} else if actionStr == "DROP" || (actionStr == "BLOCK" && globalBlockAction == BlockActionDrop) {
				IncrExfilBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)

				if logQueries && !isBanned {
					log.Printf("[DNS] [%s] %s -> %s %s | EXFIL DROP (BPS: %.0f) | DROP",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], bps)
				}
				return true
			} else {
				IncrExfilBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)
				executeSecurityBlock(w, r, q, actionStr, protocol, clientID, "EXFIL", bps)
				return true
			}
		}
	}

	// ── 0.9 Search Domain Leak Prevention ─────────────────────────────────
	if searchDomainLeakPrevention && clientAddr.IsValid() {
		if baseDomain, baseReason := checkRecentBlockAppend(clientAddr, qNameTrimmed); baseDomain != "" {
			reason := "Search Append of " + baseDomain
			IncrPolicyBlock()

			// Deliberately IncrBlockedDomain and NOT RecordBlockEvent: the latter
			// also feeds recordRecentBlock, which is the very buffer
			// checkRecentBlockAppend just consulted. Re-seeding it with the
			// appended name would make each suppressed variant the seed for the
			// next one.
			IncrBlockedDomain(qNameTrimmed, reason)

			if globalBlockAction == BlockActionDrop {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY DROP (%s, original reason: %s) | DROP",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], reason, baseReason)
				}
				return true
			} else if globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (%s, original reason: %s) | %s",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], reason, baseReason, getBlockActionLogStr(q.Qtype))
				}
			} else {
				resp := generateBlockMsg(r, syntheticTTL)
				_ = w.WriteMsg(resp)
				msgPool.Put(resp)

				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (%s, original reason: %s) | %s",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype], reason, baseReason, getBlockActionLogStr(q.Qtype))
				}
				return true
			}
		}
	}

	return false
}
