/*
File:    process_security.go
Version: 1.26.0
Last Updated: 25-Oct-2026 16:05 CET

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
    - Subdomain Exfiltration Profiling (Info-Stealer Defense)
    - Search Domain Leak Prevention
    - Per-client last-seen telemetry (Web UI "Known Clients" table)

Changes:
  1.26.0 - [SECURITY/FIX] Passed `clientAddr` into `AnalyzeSubdomainLimit` so
           subdomain rate limiting tracks `(client/subnet, apex)` and cannot be
           abused by one client to DoS a domain for other resolver users.
  1.25.0 - [FIX] Checked both `clientMAC` and `ednsMAC` independently against
           `webuiClientBlocks` and recorded `ednsMAC` in `TouchClientSeen`.
  1.24.0 - [SECURITY/FIX] Addressed an undeclared memory leak within the error 
           handling branches natively.
  1.23.0 - [SECURITY] Added `0.85 Subdomain Limit` organically.
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

var unidentifiedSourceLastLog atomic.Int64

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
		} else if logPrefix == "SUBDOMAIN LIMIT" {
			log.Printf("[DNS] [%s] %s -> %s %s | SUBDOMAIN LIMIT INTERCEPT | %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], logAction)
		} else {
			log.Printf("[DNS] [%s] %s -> %s %s | EXFIL INTERCEPT (BPS: %.0f) | %s",
				protocol, clientID, q.Name, dns.TypeToString[q.Qtype], scoreOrBPS, logAction)
		}
	}

	msgPool.Put(msg)
}

func enforceSecurityGuards(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, ednsMAC, clientName, clientID, protocol, localPort string) bool {

	// ── 0.0 Source Address Admissibility (Fail-Closed Identity Gate) ──────
	if !clientAddr.IsValid() && (hasDNSACL || hasRateLimit) {
		IncrDroppedRateLimit()

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
			return true
		}
	}

	// ── 0.2 Rate Limiting & Penalty Box (Public Resolver Security) ────────
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

	IncrQueryTotal()
	IncrTalker(clientIP, clientName)
	IncrDomain(qNameTrimmed)
	TouchClientSeen(clientIP, clientMAC)
	if ednsMAC != "" && ednsMAC != clientMAC {
		TouchClientSeen("", ednsMAC)
	}

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
		if !webuiBlocked && ednsMAC != "" {
			if _, ok := webuiClientBlocks.Load(ednsMAC); ok {
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

		IncrPolicyBlock()
		RecordBlockEvent(clientIP, qNameTrimmed, reason)
		PenalizeClient(clientIP, clientAddr, 1)

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
		PenalizeClient(clientIP, clientAddr, 2)

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
		PenalizeClient(clientIP, clientAddr, 1)

		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s ANY | POLICY DROP (Anti-Amplification) | DROP",
				protocol, clientID, q.Name)
		}
		return true
	}

	// ── 0.6 Startup Guard ─────────────────────────────────────────────────
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

		domainCore := qNameTrimmed
		if len(eTLD) < len(qNameTrimmed) {
			cut := len(qNameTrimmed) - len(eTLD) - 1
			if cut > 0 && cut < len(qNameTrimmed) && qNameTrimmed[cut] == '.' {
				domainCore = qNameTrimmed[:cut]
			}
		}

		score := AnalyzeDGA(qNameTrimmed, domainCore)

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

	// ── 0.85 Subdomain Limit / Info-Stealer Defense ───────────────────────
	if hasSubdomainLimit {
		allowed, actionStr := AnalyzeSubdomainLimit(clientAddr, qNameTrimmed)
		if !allowed {
			reason := "Subdomain Exfiltration Limit Exceeded"

			if actionStr == "LOG" {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | SUBDOMAIN LIMIT DETECTION (LOG ONLY) | LOG",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
				}
			} else if actionStr == "DROP" || (actionStr == "BLOCK" && globalBlockAction == BlockActionDrop) {
				IncrSubdomainBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)

				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | SUBDOMAIN LIMIT DROP | DROP",
						protocol, clientID, q.Name, dns.TypeToString[q.Qtype])
				}
				return true
			} else {
				IncrSubdomainBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)
				executeSecurityBlock(w, r, q, actionStr, protocol, clientID, "SUBDOMAIN LIMIT", 0)
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
