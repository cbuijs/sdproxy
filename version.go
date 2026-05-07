/*
File:    version.go
Version: v1.267.0
Updated: 07-May-2026 12:56 CEST

Description:
  Global version, build time, and build number constants for sdproxy.
  These variables can be overridden at link time using the Go linker flags:
  e.g., -ldflags "-X main.BuildVersion=v1.267.0 -X 'main.BuildTime=...'"

Changes:
  1.267.0 - [SECURITY/FIX] Resolved a Custom Rules evasion flaw where `CheckRules` 
            evaluated against the CNAME target rather than the original requested domain.
          - [SECURITY/FIX] Hardened RFC 2308 negative caching proofs across all 
            synthetic SOA generators (`process_spoof`, `process_cache`, `process_security`, 
            `policy.go`) to use `q.Name` instead of `.`.
  1.266.0 - [SECURITY] Implemented structural bounds on CNAME mappings and resolved 
            catastrophic NTP reverse-clock shifts within the admission controllers.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	// It is used in boot logs and the Web UI dashboards.
	BuildVersion string = "v1.267.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "07-May-2026 12:56 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "322"
)

