/*
File:    process_policy.go
Version: 1.8.0
Updated: 19-May-2026 14:20 CEST

Description:
  Evaluates query-level policies (RType, Domain, Obsolete QTypes, Filter AAAA)
  and intercepts queries with synthetic blocks/drops natively.
  Extracted from process.go to improve modularity.

Changes:
  1.8.0 - [LOGGING/FIX] Repaired missing telemetry increments natively across 
          RType, Obsolete QType, AAAA, and Strict PTR filters. Integrates 
          `IncrPolicyBlock` organically prior to dropping the payload.
  1.7.1 - [FIX] Restored missing `fmt` import needed for fallback format telemetry.
  1.7.0 - [REFACTOR] Sourced `RcodeStr` formatting logic from `process_helpers.go`.
  1.6.0 - [REFACTOR] Adopted the centralized `RecordBlockEvent` telemetry function, 
          adjusting the pipeline signature seamlessly to receive the client IP. 
          Ensures absolute coherence organically across the analytics suite natively.
  1.5.0 - [SECURITY/FIX] Integrated `originalQNameTrimmed` and `spoofedAlias` structures 
          natively to guarantee policy exits preserve telemetry clarity during CNAME spoofing.
  1.4.0 - [PERF] Passed the `clientID` parameter natively into the signature to 
          completely prevent string re-allocation overhead for the log outputs.
  1.3.0 - [FEAT] Hardened `RType Policy` intercepts to respect `globalBlockAction` 
          configurations gracefully (bypassing on `LOG ONLY`).
*/

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// handlePolicyExits checks the incoming query against configured RType and Domain 
// policies, as well as global filters (Obsolete Qtypes, AAAA filtering, Strict PTR).
// Returns true if the query was intercepted and spoofed/blocked natively.
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
				// Bypass
			} else {
				dropped := writePolicyAction(w, r, action)

				if cacheSynthFlag && action != PolicyActionDrop && !(action == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
					synthMsg := buildSynthCacheMsg(q, action)
					CacheSetSynth(cacheKey, synthMsg)
					msgPool.Put(synthMsg) // [PERF] Zero-allocation memory recycling
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
				synthMsg := buildSynthCacheMsg(q, dns.RcodeNotImplemented)
				CacheSetSynth(cacheKey, synthMsg)
				msgPool.Put(synthMsg) // [PERF] Zero-allocation memory recycling
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
			synthMsg := buildSynthCacheMsg(q, dns.RcodeSuccess)
			CacheSetSynth(cacheKey, synthMsg)
			msgPool.Put(synthMsg) // [PERF] Zero-allocation memory recycling
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
			synthMsg := buildSynthCacheMsg(q, dns.RcodeNameError)
			CacheSetSynth(cacheKey, synthMsg)
			msgPool.Put(synthMsg) // [PERF] Zero-allocation memory recycling
		}
		
		if logQueries {
			log.Printf("[DNS] [%s] %s -> %s %s | POLICY BLOCK (Strict PTR) | NXDOMAIN",
				protocol, clientID, originalQName, dns.TypeToString[q.Qtype])
		}
		return true
	}
	return false
}

