/*
File:    process_security.go
Version: 1.32.0
Last Updated: 10-Nov-2026 15:45 CET

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
  1.32.0 - [CLEANUP] Removed unused `localPort` parameter from `enforceSecurityGuards`.
  1.31.0 - [SECURITY/FIX] Replaced `PreserveEDNS0` with `enforceUDPDefenses` in the
           Malformed QNAME (`FORMERR`) handler so UDP responses respect the 1232B
           fragmentation ceiling, and hoisted Top-N domain/TLD/vendor tracking
           (`IncrDomain`) past the QClass, QNAME, Anti-Amplification, Startup Guard,
           and Web UI Client Block gates so rejected or malformed queries cannot
           pollute or evict valid analytics in `statTopDomains` and `statTopTLDs`.
  1.30.0 - [SECURITY/FIX] Enforced `enforceUDPDefenses` in `executeSecurityBlock`,
           WebUI Client Block, and Search Domain Leak Prevention block paths so
           large `block_ips` lists respect the 1232B UDP fragmentation ceiling (`TC=1`).
  1.29.0 - [FIX] Recorded `recordBlockMsgStats` (`IncrReturnCode` and `IncrNXDomain`)
           in `executeSecurityBlock`, WebUI Client Block, and Search Domain Leak
           Prevention block paths, and guarded `[SECURITY]` source-address log
           with `if logSystem`.
  1.28.0 - [FEAT] Added `protoEndpoint` and Simple Logging Mode (`logSimple` /
           `logQuerySimple`) support across rate limiting, Web UI client blocks,
           QClass/QNAME checks, anti-amplification drops, DGA, exfiltration,
           subdomain limits, and search-domain leak prevention.
  1.27.0 - [SECURITY/FIX] Set `msg.Authoritative = true` and synthesized RFC 2308
           negative SOA for `NOERROR` (NODATA) as well as `NXDOMAIN` RCODE actions
           in `executeSecurityBlock`.
  1.26.0 - [SECURITY/FIX] Passed `clientAddr` into `AnalyzeSubdomainLimit` so
           subdomain rate limiting tracks `(client/subnet, apex)` and cannot be
           abused by one client to DoS a domain for other resolver users.
  1.25.0 - [FIX] Checked both `clientMAC` and `ednsMAC` independently against
           `webuiClientBlocks` and recorded `ednsMAC` in `TouchClientSeen`.
  1.24.0 - [SECURITY/FIX] Addressed an undeclared memory leak within the error 
           handling branches natively.
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

func executeSecurityBlock(w dns.ResponseWriter, r *dns.Msg, q dns.Question, actionStr, protocol, protoEndpoint, clientIP, clientID, logPrefix string, scoreOrBPS float64) {
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
		msg.Authoritative = true
		msg.RecursionAvailable = true
		msg.Rcode = rcode
		if rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess {
			SetNegativeSOA(msg, q.Name, syntheticTTL)
		}
		PreserveEDNS0(r, msg)
	}

	recordBlockMsgStats(msg, lowerTrimDot(q.Name))
	enforceUDPDefenses(r, msg, protocol, netip.Addr{}, nil)
	_ = w.WriteMsg(msg)

	if logQueries {
		logAction := actionStr
		if actionStr == "BLOCK" {
			logAction = getBlockActionLogStr(q.Qtype)
		} else {
			logAction = RcodeStr(msg.Rcode)
		}

		if logSimple {
			logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), logAction, logPrefix, false)
		} else {
			if logPrefix == "DGA" {
				log.Printf("[DNS] [%s] %s -> %s %s | DGA INTERCEPT (Score: %.1f) | %s",
					protocol, clientID, q.Name, qtypeName(q.Qtype), scoreOrBPS, logAction)
			} else if logPrefix == "SUBDOMAIN LIMIT" {
				log.Printf("[DNS] [%s] %s -> %s %s | SUBDOMAIN LIMIT INTERCEPT | %s",
					protocol, clientID, q.Name, qtypeName(q.Qtype), logAction)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | EXFIL INTERCEPT (BPS: %.0f) | %s",
					protocol, clientID, q.Name, qtypeName(q.Qtype), scoreOrBPS, logAction)
			}
		}
	}

	msgPool.Put(msg)
}

func enforceSecurityGuards(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP string, clientAddr netip.Addr, clientMAC, ednsMAC, clientName, clientID, protocol, protoEndpoint string) bool {

	// ── 0.0 Source Address Admissibility (Fail-Closed Identity Gate) ──────
	if !clientAddr.IsValid() && (hasDNSACL || hasRateLimit) {
		IncrDroppedRateLimit()

		now := time.Now().UnixNano()
		last := unidentifiedSourceLastLog.Load()
		if now-last > int64(60*time.Second) && unidentifiedSourceLastLog.CompareAndSwap(last, now) {
			if logSystem {
				log.Printf("[SECURITY] Dropping query from an unidentifiable source address on %s (raw: %q). "+
					"ACLs and/or rate limiting are enabled and cannot evaluate an unparseable origin, so the query fails closed. "+
					"If sdproxy sits behind a proxy or tunnel, verify it preserves the real client address.",
					protocol, clientIP)
			}
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
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "Rate Limit", false)
				} else {
					log.Printf("[DNS] [%s] %s -> %s %s | DROPPED (Rate Limit Exceeded)",
						protocol, clientID, q.Name, qtypeName(q.Qtype))
				}
			}
			return true
		}
	}

	IncrQueryTotal()
	IncrTalker(clientIP, clientName)
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
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "WebUI Client Block", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | WEBUI CLIENT DROP | DROP", protocol, clientID, q.Name, qtypeName(q.Qtype))
					}
				}
				return true
			} else if globalBlockAction == BlockActionLog {
				if logQueries && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | WEBUI CLIENT BLOCK (LOG ONLY) | %s", protocol, clientID, q.Name, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype))
				}
			} else {
				resp := generateBlockMsg(r, syntheticTTL)
				recordBlockMsgStats(resp, qNameTrimmed)
				enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
				w.WriteMsg(resp)
				msgPool.Put(resp)
				if logQueries {
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype), "WebUI Client Block", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | WEBUI CLIENT BLOCK | %s", protocol, clientID, q.Name, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype))
					}
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
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "REFUSED", reason, false)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (%s) | REFUSED",
					protocol, clientID, q.Name, qtypeName(q.Qtype), reason)
			}
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
		enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
		_ = w.WriteMsg(resp)

		if logQueries {
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "FORMERR", "Malformed QNAME", false)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Malformed QNAME) | FORMERR",
					protocol, clientID, q.Name, qtypeName(q.Qtype))
			}
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
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, q.Name, "ANY", "DROP", "Anti-Amplification", false)
			} else {
				log.Printf("[DNS] [%s] %s -> %s ANY | POLICY DROP (Anti-Amplification) | DROP",
					protocol, clientID, q.Name)
			}
		}
		return true
	}

	// ── 0.6 Startup Guard ─────────────────────────────────────────────────
	if hasParental && !(cfg.Server.FastStart || cfg.Parental.FastStart) && !catMapInitialized.Load() {
		if logQueries {
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "Startup Guard", false)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | DROPPED (Waiting for parental categories to load)",
					protocol, clientID, q.Name, qtypeName(q.Qtype))
			}
		}
		return true
	}

	IncrDomain(qNameTrimmed)

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
				if logQueries && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | DGA DETECTION (LOG ONLY) (Score: %.1f) | LOG",
						protocol, clientID, q.Name, qtypeName(q.Qtype), score)
				}
			} else if actionStr == "DROP" || (actionStr == "BLOCK" && globalBlockAction == BlockActionDrop) {
				IncrDGABlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)

				if logQueries {
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "DGA", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | DGA DROP (Score: %.1f) | DROP",
							protocol, clientID, q.Name, qtypeName(q.Qtype), score)
					}
				}
				return true
			} else {
				IncrDGABlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)
				executeSecurityBlock(w, r, q, actionStr, protocol, protoEndpoint, clientIP, clientID, "DGA", score)
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
				if logQueries && !isBanned && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | EXFILTRATION DETECTION (LOG ONLY) (BPS: %.0f) | LOG",
						protocol, clientID, q.Name, qtypeName(q.Qtype), bps)
				}
			} else if actionStr == "DROP" || (actionStr == "BLOCK" && globalBlockAction == BlockActionDrop) {
				IncrExfilBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)

				if logQueries && !isBanned {
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "Exfiltration", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | EXFIL DROP (BPS: %.0f) | DROP",
							protocol, clientID, q.Name, qtypeName(q.Qtype), bps)
					}
				}
				return true
			} else {
				IncrExfilBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)
				executeSecurityBlock(w, r, q, actionStr, protocol, protoEndpoint, clientIP, clientID, "Exfiltration", bps)
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
				if logQueries && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | SUBDOMAIN LIMIT DETECTION (LOG ONLY) | LOG",
						protocol, clientID, q.Name, qtypeName(q.Qtype))
				}
			} else if actionStr == "DROP" || (actionStr == "BLOCK" && globalBlockAction == BlockActionDrop) {
				IncrSubdomainBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)

				if logQueries {
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "Subdomain Limit", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | SUBDOMAIN LIMIT DROP | DROP",
							protocol, clientID, q.Name, qtypeName(q.Qtype))
					}
				}
				return true
			} else {
				IncrSubdomainBlock()
				RecordBlockEvent(clientIP, qNameTrimmed, reason)
				executeSecurityBlock(w, r, q, actionStr, protocol, protoEndpoint, clientIP, clientID, "SUBDOMAIN LIMIT", 0)
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
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), "DROP", "Search Leak ("+baseDomain+")", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | POLICY DROP (%s, original reason: %s) | DROP",
							protocol, clientID, q.Name, qtypeName(q.Qtype), reason, baseReason)
					}
				}
				return true
			} else if globalBlockAction == BlockActionLog {
				if logQueries && !logSimple {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (%s, original reason: %s) | %s",
						protocol, clientID, q.Name, qtypeName(q.Qtype), reason, baseReason, getBlockActionLogStr(q.Qtype))
				}
			} else {
				resp := generateBlockMsg(r, syntheticTTL)
				recordBlockMsgStats(resp, qNameTrimmed)
				enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
				_ = w.WriteMsg(resp)
				msgPool.Put(resp)

				if logQueries {
					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), getBlockActionLogStr(q.Qtype), "Search Leak ("+baseDomain+")", false)
					} else {
						log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (%s, original reason: %s) | %s",
							protocol, clientID, q.Name, qtypeName(q.Qtype), reason, baseReason, getBlockActionLogStr(q.Qtype))
					}
				}
				return true
			}
		}
	}

	return false
}
