/*
File:    version.go
Version: 1.466.0
Last Updated: 04-Sep-2026 09:50 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.466.0 - [PERF/FIX] Eradicated a massive, redundant `msg.Copy()` heap allocation natively 
            within the cache-hit resolution path. `CacheGet` intrinsically unpacks 
            payloads directly from wire-format slices, ensuring absolute isolation 
            from the master memory structure. Removing the subsequent deep-clone 
            slashes Garbage Collection (GC) overhead exponentially on the hot path.
  1.465.0 - [SECURITY/FIX] Resolved a severe cache-wiping regression. Natively 
            intercepts `scanner.Err()` interrupts and explicitly aborts the 
            atomic `arpSnap.Store()` operation. Prevents the active router map 
            from being permanently overwritten by truncated OS-level descriptor streams.
          - [PERF] Overhauled `pollARP` to execute entirely via zero-allocation 
            byte scanning (`bytes.Fields`, `bytes.Equal`). Eradicates massive 
            Garbage Collection (GC) thrashing caused by dynamic string allocations 
            every 30 seconds natively.
          - [SECURITY/FIX] Eradicated a persistent zombie goroutine organically.
            The periodic ARP polling loop now explicitly listens for the global 
            `shutdownCh` multiplexer, ensuring clean resource teardowns natively.
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
	BuildVersion string = "v1.466.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "04-Sep-2026 09:50 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "525"
)
