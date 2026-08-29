/*
File:    version.go
Version: 1.463.0
Last Updated: 29-Aug-2026 17:30 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.463.0 - [SECURITY/FIX] Eradicated a critical Race Condition natively within 
            the asynchronous disk serializer. Replaced deterministic `.tmp` filenames 
            with secure `os.CreateTemp` descriptors to eliminate severe data corruption 
            when multiple workers persisted analytical arrays simultaneously.
          - [FEAT/FIX] Injected `rotateAnswersInPlace` evaluation natively into 
            the `CacheGetExpired` infinite-stale fallback generator. Ensures 
            that Round-Robin permutations are rigorously preserved during 
            upstream server outages.
  1.462.0 - [SECURITY/FIX] Addressed LAN Privacy Leakage. `process_local.go` now explicitly 
            intercepts non-standard queries (HTTPS, TXT) aimed at local identities natively, 
            returning an authoritative NODATA structure to completely protect local domains 
            from leaking upstream.
          - [SECURITY/FIX] Switched `dohResponseWriter`, `doqResponseWriter`, and downstream 
            packing handlers to uniformly harness the `largeBufPool` array (64KB). Definitively 
            eradicates `dns.ErrBuf` overflows resulting in empty payloads for robust responses 
            like DNSSEC and expansive TXT records.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.463.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "29-Aug-2026 17:30 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "522"
)

