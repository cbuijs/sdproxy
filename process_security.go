/*
File:    process_security.go
Version: 1.14.0
Last Updated: 24-Jul-2026 18:20 CEST

Description:
  Pre-routing Security & Admission Guards for sdproxy.
  Executes the first phase of the core processing pipeline natively:
    - ACL & Anti-Spoofing checks
    - Token-Bucket Rate Limiting & Penalty Box enforcement
    - Web UI explicit Client Blocks
    - QClass & QNAME syntactical validation
    - Anti-Amplification drop logic (ANY over UDP)
    - DGA (Domain Generation Algorithm) ML Inference
    - Exfiltration Volumetric Profiling
    - Search Domain Leak Prevention

  Extracted from process.go to improve modularity and execution clarity.

Changes:
  1.14.0 - [PERF] Eradicated a per-query heap allocation on the pre-cache DGA hot
           path. The domainCore extraction used
           `strings.TrimSuffix(qNameTrimmed, "."+eTLD)`, whose `"."+eTLD`
           concatenation allocated a throwaway string for EVERY query while DGA
           inference was enabled — directly undermining the zero-allocation
           contract AnalyzeDGA is built on. Since extractETLDPlusOne always returns
           eTLD as a true suffix of qNameTrimmed, the ".<eTLD>" tail is now stripped
           with pure index math (string sub-slice), allocating nothing. Behaviour is
           identical, including the bare-eTLD fallback. Header `Updated:` field also
           normalized to the mandated `Last Updated:` form.
  1.13.0 - [PERF] Aligned the `searchDomainLeakPrevention` evaluation engine to cleanly 
           pass internal zero-allocation `netip.Addr` structures natively.
  1.12.0 - [FEAT] Inserted `WebUI Client Block` enforcement boundary natively. 
           Instantly intercepts IP and MAC addresses explicitly flagged from 
           the interactive dashboard and punishes them utilizing the globally 
           configured `block_action` constraints.
  1.11.0 - [FEAT] Bypassed Search Domain Leak Prevention interceptor natively 
           if explicitly disabled in configurations.
*/

package main

import (
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

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
func enforceSecurityGuards(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, clientName, clientID, protocol string) bool {

	// ── 0.1 ACL Gate & Anti-Spoofing ──────────────────────────────────────
	if hasDNSACL && clientAddr.IsValid() {
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
	if hasRateLimit && clientAddr.IsValid() {
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
			cut := len(qNameTrimmed) - len(eTLD) - 1
			if cut > 0 && qNameTrimmed[cut] == '.' {
				domainCore = qNameTrimmed[:cut]
			}
		}

		// Evaluates stochastic inference natively using the pristine fullDomain boundaries
		// alongside the stripped domainCore structure for extreme throughput optimization.
		score := AnalyzeDGA(qNameTrimmed, domainCore)
		
		if score >= cfg.Server.DGA.Threshold {
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
		allowed, isBanned, bps := AnalyzeExfiltration(clientIP, clientAddr, r.Len())
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

