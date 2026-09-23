/*
File:    version.go
Version: 1.479.0
Last Updated: 23-Sep-2026 12:45 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.479.0 - [SECURITY/FIX] Hardened DNS Cache engine against Authority Section poisoning natively.
            Mitigates vulnerabilities where upstreams inject malicious NS/SOA records targeting 
            Top-Level Domains (e.g., `com.`) by enforcing strict Public Suffix isolation organically.
  1.478.0 - [PERF] Eradicated massive redundant heap allocations natively within 
            `SaveCache` and `DumpCache`. By leveraging the strict immutability of 
            the underlying packed byte arrays, deep-copies were organically bypassed, 
            drastically slashing Garbage Collection (GC) pressure and memory spikes 
            during disk flushes and Web UI introspection.
  1.477.0 - [PERF/FIX] Eradicated severe Mutex lock contention and latency spikes 
            during emergency memory evictions natively. `CheckParental` and 
            `recordRecentBlock` now utilize `TryLock` organically when scanning 
            state maps during tracker saturation floods, preventing active DNS 
            requests from deadlocking the global admission pipelines.
          - [MAINTENANCE] Upgraded Dockerfile base image natively to `golang:1.26-alpine` 
            and corrected standardized file nomenclature.
  1.476.0 - [SECURITY/FIX] Restored localAddr propagation natively across DoH and DoQ multiplexers.
            Exclusively allows precise `port:` routing rules to execute dynamically against HTTP/QUIC 
            payloads, eradicating arbitrary blind-spots where `w.LocalAddr()` previously omitted 
            bound network port contexts dynamically.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.479.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "23-Sep-2026 12:45 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "538"
)

