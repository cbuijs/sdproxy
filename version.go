/*
File:    version.go
Version: 1.405.0
Last Updated: 12-Jun-2026 15:09 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.405.0 - [SECURITY/FIX] Addressed a telemetry omission anomaly within 
            the Domain Policy routing engine natively. Injected the missing 
            `IncrPolicyBlock` instruction organically prior to executing 
            the Drop/Log evaluation sequence. Guarantees that Domain 
            Policy intercepts correctly register on the global statistical 
            counters.
  1.404.0 - [PERF] Eradicated redundant client-group evaluations natively 
            across the DNS pipeline. Consolidates `resolveStateKeyAndGroup` 
            output at the apex of `ProcessDNS` and propagates it strictly 
            downstream, eliminating CPU thrashing during multi-level DPI 
            blocks and parental constraint evaluations.
          - [SECURITY/FIX] Hardened `SaveCache` against overlapping ticks 
            and OS shutdown races, preventing persistent memory structures 
            from zero-byte corruptions dynamically.
          - [PERF] Scoped `runSweeper` array allocations inward to prevent 
            `DNSCacheKey` strings from artificially evading the Garbage Collector.
*/

package main

import "sync/atomic"

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.405.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "12-Jun-2026 15:09 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "463"
)

// atomic import guard — ensures the import is used even if all atomics are
// accessed via the version/build tracker.
var _ atomic.Int64

