/*
File:    version.go
Version: 1.464.0
Last Updated: 03-Sep-2026 12:29 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.464.0 - [SECURITY/FIX] Upgraded DGA ML Inference engine to definitively intercept 
            modern Dictionary DGAs. Integrated `trailingDigits` bounds detection 
            to isolate stochastic domains obfuscated by valid semantic prefix words 
            followed by static integer blocks (e.g., `opsupdate5861`). Expanded 
            the DGA Safe Domains whitelist organically to natively absorb major 
            corporate platforms (e.g., Microsoft Office 365, GitHub) without triggering 
            false positives organically.
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
	BuildVersion string = "v1.464.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "03-Sep-2026 12:29 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "523"
)

