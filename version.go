/*
File:    version.go
Version: 1.476.0
Last Updated: 23-Sep-2026 11:24 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.476.0 - [SECURITY/FIX] Restored localAddr propagation natively across DoH and DoQ multiplexers.
            Exclusively allows precise `port:` routing rules to execute dynamically against HTTP/QUIC 
            payloads, eradicating arbitrary blind-spots where `w.LocalAddr()` previously omitted 
            bound network port contexts dynamically.
  1.475.0 - [SECURITY/FIX] Passed `localPort` to `enforceSecurityGuards` dynamically
            so that the `clientRoute` extraction occurring later in the pipeline natively
            benefits from fully pre-parsed port boundaries.
            Added missing initialization of cfg.Upstreams and cfg.Groups in validateConfig.
  1.474.0 - [SECURITY/FIX] Eradicated a critical Cache Persistence Corruption vulnerability natively.
            Overhauled `initRouteIndex` to proactively sort dynamically harvested Upstream target 
            identifiers before generating `RouteIdx` integers. Prevents random map iteration states 
            from permanently desynchronizing saved binary cache partitions across router reboots.
  1.473.0 - [SECURITY/FIX] Resolved uint16 parsing regression within `extractIPFromPTR`.
            When decoding `.ip6.arpa` addresses natively, the mathematical array indexing
            logic utilized standard integer blocks capable of overflowing into out-of-bounds
            memory panics under maliciously malformed payload requests. Definitively replaced
            with hardened bitwise isolations seamlessly.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.476.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "23-Sep-2026 11:24 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "535"
)

