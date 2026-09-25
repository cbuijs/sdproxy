/*
File:    version.go
Version: 1.483.0
Last Updated: 25-Sep-2026 12:00 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.483.0 - [SECURITY/FIX] Hardened Exfiltration micro-burst telemetry natively to enforce strict strike accrual rate-limits. Prevents instantaneous blackhole bans from isolated micro-burst anomalies.
          - [SECURITY/FIX] Re-aligned DoQ 0-RTT anomaly fallback logic to definitively latch `doqNo0RTT` organically. Ensures absolute compliance with RFC 9250 §10.5 DOQ_PROTOCOL_ERROR handling.
          - [COMPLIANCE] Referenced digest.txt verbatim to assure analytical parity across core engine constraints natively.
  1.482.0 - [PERF] Optimized web UI logging retention sweeps. Replaced expensive 
            `time.Parse` object instantiations with pure lexicographical string 
            evaluations organically, completely eradicating heap-allocation spikes 
            during asynchronous filesystem flushes natively. Referencing digest.txt 
            for further analytical context.
  1.481.0 - [SECURITY/FIX] Hardened Exfiltration volumetric tracker natively to 
            prevent Micro-Burst Time Starvation attacks against the EMA baselines organically.
  1.480.0 - [SECURITY/FIX] Hardened the Web UI authentication gateway natively by unifying
            `handleLogin` password verifications under the central constant-time 
            `secretsEqual` primitive, ensuring identical cryptographic parity with 
            the session and API token evaluators organically.
          - [CLEANUP] Standardized boundary ceiling evaluations across the `exfiltration` 
            and `process_leak` subsystems utilizing `math.MaxInt64` natively. Eliminates 
            arbitrary bitwise left-shift hardcodes to prevent theoretical architecture 
            overflows cleanly.
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
	BuildVersion string = "v1.483.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "25-Sep-2026 12:00 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "542"
)

