/*
File:    process_policy.go
Version: 1.10.0
Last Updated: 25-Oct-2026 15:40 CET

Description:
  Evaluates query-level policies (RType, Domain, Obsolete QTypes, Filter AAAA)
  and intercepts queries with synthetic blocks/drops natively.
  Extracted from process.go to improve modularity.

Changes:
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

func handlePolicyExits(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP, clientID, protocol string, cacheKey DNSCacheKey, originalQName, originalQNameTrimmed, spoofedAlias string) bool {
	if hasRtypePolicy {
		if action, blocked := rtypePolicy[q.Qtype]; blocked {
			IncrPolicyBlock()
			RecordBlockEvent(clientIP, originalQNameTrimmed, "RType Policy ("+dns.TypeToString[q.Qtype]+")")

			if action == PolicyActionBlock && globalBlockAction == BlockActionLog {
				if logQueries {
					log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (LOG ONLY) (RType Policy (%s)) | %s",
						protocol, clientID, originalQName, dns.TypeToString[q.Qtype], dns.TypeToString[q.Qtype], getBlockActionLogStr(q.Qtype))
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

					statusMark := "POLICY BLOCK"
					if dropped {
						statusMark = "POLICY DROP"
					}

					if spoofedAlias != "" {
						statusMark = fmt.Sprintf("SPOOFED ALIAS (%s) | %s", spoofedAlias, statusMark)
					}

					log.Printf("[DNS] [%s] %s -> %s %s | %s (RType Policy (%s)) | %s",
						protocol, clientID, originalQName, dns.TypeToString[q.Qtype], statusMark, dns.TypeToString[q.Qtype], actionLogStr)
				}
				return true
			}
		}
	}
	if blockUnknownQtypes {
		if _, obsolete := obsoleteQtypes[q.Qtype]; obsolete {
			IncrPolicyBlock()
			RecordBlockEvent(clientIP, originalQNameTrimmed, "Obsolete QType ("+dns.TypeToString[q.Qtype]+")")
			writePolicyAction(w, r, dns.RcodeNotImplemented)

			if cacheSynthFlag {
				synthMsg := buildSynthCacheMsg(r, q, dns.RcodeNotImplemented)
				CacheSetSynth(cacheKey, synthMsg)
				msgPool.Put(synthMsg)
			}

			if logQueries {
				log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Obsolete QType (%s)) | NOTIMP",
					protocol, clientID, originalQName, dns.TypeToString[q.Qtype], dns.TypeToString[q.Qtype])
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
			log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Filter AAAA) | NOERROR",
				protocol, clientID, originalQName, dns.TypeToString[q.Qtype])
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
			log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Strict PTR) | NXDOMAIN",
				protocol, clientID, originalQName, dns.TypeToString[q.Qtype])
		}
		return true
	}
	return false
}
