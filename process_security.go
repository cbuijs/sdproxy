/*
File:    process_security.go
Version: 1.10.0
Updated: 26-May-2026 11:04 CEST

Description:
  Pre-routing Security & Admission Guards for sdproxy.
  Executes the first phase of the core processing pipeline natively:
    - ACL & Anti-Spoofing checks
    - Token-Bucket Rate Limiting & Penalty Box enforcement
    - QClass & QNAME syntactical validation
    - Anti-Amplification drop logic (ANY over UDP)
    - DGA (Domain Generation Algorithm) ML Inference
    - Exfiltration Volumetric Profiling
    - Search Domain Leak Prevention

  Extracted from process.go to improve modularity and execution clarity.

Changes:
  1.10.0 - [SECURITY/FIX] Accelerated Penalty Box blackholing natively. 
           Injected explicit `PenalizeClient` strikes into protocol violation 
           guards (Non-INET Class, Malformed QNAME, ANY-over-UDP). Instantly 
           punishes malformed or malicious queries to accelerate isolation 
           into the lock-free Fast-Path penalty box.
  1.9.0  - [BUG/FIX] Resolved a resource leak where the synthesized blocked 
           dns.Msg was not being returned back to the msgPool on "BLOCK" action.
  1.8.0  - [REFACTOR] Unified redundant SOA synthesis and EDNS0 extraction blocks 
           by calling `SetNegativeSOA`, `PreserveEDNS0`, and `RcodeStr` centrally 
           from `process_helpers.go`, guaranteeing strict protocol compliance natively.
  1.7.0  - [REFACTOR] Consolidated DGA and Exfiltration block synthesis and 
           telemetry logging into a unified `executeSecurityBlock` helper natively. 
           Adopted the centralized `RecordBlockEvent` to align telemetry structures.
  1.6.0  - [SECURITY/FIX] Adjusted DGA invocation natively to securely pass the 
           `fullDomain` payload (`qNameTrimmed`) alongside the stripped `domainCore`. 
           This guarantees that downstream ML whitelist evaluators can accurately 
           verify infrastructure eTLDs natively.
  1.5.0  - [SECURITY/FIX] Addressed a fatal startup guard blockage (Bug 1 & 3).
           Replaced `catMap.Load() == nil` with `catMapInitialized.Load()` natively.
           Prevents the router from indefinitely dropping all queries on first boot 
           when `fast_start` is false, and ensures `fast_start: true` gracefully 
           bypasses uninitialized category maps securely.
  1.4.0  - [FEAT] Hardened the Startup Guard natively to respect the new global 
           `fast_start` configuration flag, permitting immediate resolution.
  1.3.0  - [SECURITY/FIX] Bound synthetic `SOA` record generation for DGA and Exfiltration 
           intercepts to `q.Name` natively to guarantee stub resolver compliance.
  1.2.0  - [PERF] Ingested pre-resolved `clientMAC`, `clientName`, and `clientID` 
           parameters to eliminate redundant map lookups natively.
         - [PERF] Stripped a costly string allocation (`strings.ReplaceAll`) from 
           the ML DGA Inference engine.
  1.1.0  - [SECURITY/FIX] Guaranteed EDNS0 OPT preservation on custom DGA and 
           Exfiltration RCODE interceptions to comply with RFC 6891 §6.1.1 dynamically.
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
	if hasRateLimit && clientIP != "" {
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

		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.SetRcode(r, dns.RcodeFormatError) // RCODE 1 - FORMERR
		
		PreserveEDNS0(r, resp)
		
		_ = w.WriteMsg(resp)

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Malformed QNAME) | FORMERR",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
		}
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
		domainCore := strings.TrimSuffix(qNameTrimmed, "."+eTLD)

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
	if hasExfiltration && clientIP != "" {
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
	if baseDomain, baseReason := checkRecentBlockAppend(clientIP, qNameTrimmed); baseDomain != "" {
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

	return false
}

