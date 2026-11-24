/*
File:    process_policy.go
Version: 1.13.0
Last Updated: 16-Nov-2026 15:10 CET

Description:
  Evaluates query-level policies (RType, Domain, Obsolete QTypes, Filter AAAA)
  and intercepts queries with synthetic blocks/drops natively.
  Extracted from process.go to improve modularity.

Changes:
  1.13.0 - [SECURITY/FIX] Annotated `spoofedAlias` on Obsolete QType, Filter AAAA,
           and Strict PTR log lines when a query was rewritten by an `rrs:` CNAME
           alias, matching the RType Policy log path.
  1.12.0 - [FIX] Emitted Simple Logging Mode (`logSimple: true`) audit log lines
           in `handlePolicyExits` when an `rtype_policy: "BLOCK"` rule triggers
           while `globalBlockAction == BlockActionLog`.
  1.11.0 - [FEAT] Added `protoEndpoint` and Simple Logging Mode (`logSimple` /
           `logQuerySimple`) support across RType policy, Obsolete QTypes,
           Filter AAAA, and Strict PTR policy exits.
  1.10.0 - [SECURITY/FIX] Passed `r` into `buildSynthCacheMsg` across all policy
           interception paths so cached synthetic responses preserve the client's
           `RecursionDesired` flag.
  1.9.0  - [SECURITY/FIX] Addressed an undeclared memory leak within the error 
           handling branches natively.
  1.8.0  - [LOGGING/FIX] Repaired missing telemetry increments natively across 
           RType, Obsolete QType, AAAA, and Strict PTR filters.
*/

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func handlePolicyExits(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP, clientID, protocol, protoEndpoint string, cacheKey DNSCacheKey, originalQName, originalQNameTrimmed, spoofedAlias string) bool {
	if hasRtypePolicy {
		if action, blocked := rtypePolicy[q.Qtype]; blocked {
			qStr := qtypeName(q.Qtype)
			IncrPolicyBlock()
			RecordBlockEvent(clientIP, originalQNameTrimmed, "RType Policy ("+qStr+")")

			if action == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries {
					if logSimple {
						log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY): RType Policy (%s)",
							protoEndpoint, clientIP, originalQName, qStr, qStr)
					} else {
						statusMark := "POLICY BLOCK (LOG ONLY)"
						if spoofedAlias != "" {
							statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
						}
						log.Printf("[DNS] [%s] %s -> %s %s | %s (RType Policy (%s)) | %s",
							protocol, clientID, originalQName, qStr, statusMark, qStr, getBlockActionLogStr(q.Qtype))
					}
				}
			} else {
				dropped := writePolicyAction(w, r, action)

				if cacheSynthFlag && action != PolicyActionDrop && !(action == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
					synthMsg := buildSynthCacheMsg(r, q, action)
					CacheSetSynth(cacheKey, synthMsg)
					msgPool.Put(synthMsg)
				}

				if logQueries {
					var actionLogStr string
					if action == PolicyActionBlock {
						actionLogStr = getBlockActionLogStr(q.Qtype)
					} else if action == PolicyActionDrop {
						actionLogStr = "DROP"
					} else {
						actionLogStr = RcodeStr(action)
					}

					if logSimple {
						logQuerySimple(protoEndpoint, clientIP, originalQName, qStr, actionLogStr, "RType Policy ("+qStr+")", false)
					} else {
						statusMark := "POLICY BLOCK"
						if dropped {
							statusMark = "POLICY DROP"
						}

						if spoofedAlias != "" {
							statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
						}

						log.Printf("[DNS] [%s] %s -> %s %s | %s (RType Policy (%s)) | %s",
							protocol, clientID, originalQName, qStr, statusMark, qStr, actionLogStr)
					}
				}
				return true
			}
		}
	}
	if blockUnknownQtypes {
		if _, obsolete := obsoleteQtypes[q.Qtype]; obsolete {
			qStr := qtypeName(q.Qtype)
			IncrPolicyBlock()
			RecordBlockEvent(clientIP, originalQNameTrimmed, "Obsolete QType ("+qStr+")")
			writePolicyAction(w, r, dns.RcodeNotImplemented)

			if cacheSynthFlag {
				synthMsg := buildSynthCacheMsg(r, q, dns.RcodeNotImplemented)
				CacheSetSynth(cacheKey, synthMsg)
				msgPool.Put(synthMsg)
			}

			if logQueries {
				if logSimple {
					logQuerySimple(protoEndpoint, clientIP, originalQName, qStr, "NOTIMP", "Obsolete QType ("+qStr+")", false)
				} else {
					statusMark := "POLICY BLOCK"
					if spoofedAlias != "" {
						statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
					}
					log.Printf("[DNS] [%s] %s -> %s %s | %s (Obsolete QType (%s)) | NOTIMP",
						protocol, clientID, originalQName, qStr, statusMark, qStr)
				}
			}
			return true
		}
	}
	if cfg.Server.FilterAAAA && q.Qtype == dns.TypeAAAA {
		IncrPolicyBlock()
		RecordBlockEvent(clientIP, originalQNameTrimmed, "Filter AAAA")
		writePolicyAction(w, r, dns.RcodeSuccess)

		if cacheSynthFlag {
			synthMsg := buildSynthCacheMsg(r, q, dns.RcodeSuccess)
			CacheSetSynth(cacheKey, synthMsg)
			msgPool.Put(synthMsg)
		}

		if logQueries {
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, originalQName, "AAAA", "NOERROR (NODATA)", "Filter AAAA", false)
			} else {
				statusMark := "POLICY BLOCK"
				if spoofedAlias != "" {
					statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
				}
				log.Printf("[DNS] [%s] %s -> %s %s | %s (Filter AAAA) | NOERROR",
					protocol, clientID, originalQName, qtypeName(q.Qtype), statusMark)
			}
		}
		return true
	}
	if cfg.Server.StrictPTR && q.Qtype == dns.TypePTR && !isValidReversePTR(qNameTrimmed) {
		IncrPolicyBlock()
		RecordBlockEvent(clientIP, originalQNameTrimmed, "Strict PTR")
		writePolicyAction(w, r, dns.RcodeNameError)

		if cacheSynthFlag {
			synthMsg := buildSynthCacheMsg(r, q, dns.RcodeNameError)
			CacheSetSynth(cacheKey, synthMsg)
			msgPool.Put(synthMsg)
		}

		if logQueries {
			if logSimple {
				logQuerySimple(protoEndpoint, clientIP, originalQName, "PTR", "NXDOMAIN", "Strict PTR", false)
			} else {
				statusMark := "POLICY BLOCK"
				if spoofedAlias != "" {
					statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
				}
				log.Printf("[DNS] [%s] %s -> %s %s | %s (Strict PTR) | NXDOMAIN",
					protocol, clientID, originalQName, qtypeName(q.Qtype), statusMark)
			}
		}
		return true
	}
	return false
}
