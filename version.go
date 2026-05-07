/*
File:    version.go
Version: v1.266.0
Updated: 07-May-2026 12:48 CEST

Description:
  Global version, build time, and build number constants for sdproxy.
  These variables can be overridden at link time using the Go linker flags:
  e.g., -ldflags "-X main.BuildVersion=v1.266.0 -X 'main.BuildTime=...'"

Changes:
  1.266.0 - [SECURITY] Implemented structural bounds on CNAME mappings and resolved 
            catastrophic NTP reverse-clock shifts within the admission controllers.
  1.265.0 - [PERF] Optimized UDP fragmentation defenses to strip redundant slice 
            reallocations natively on the hot path.
  1.264.0 - [MAINTENANCE] Synchronized versioning for the current build cycle.
  1.263.0 - [SECURITY/FIX] Addressed a telemetry bypass regression within the 
            Upstream Exchange execution sequence natively. Repositioned the 
            `responseContainsNullIP` evaluation to execute prior to `enforceUDPDefenses`.
            This guarantees UDP payloads artificially truncated by DNS Flag Day 
            defenses do not successfully hide `NULL-IP` upstream blocks from the analytics logs.
  1.262.0 - [SECURITY/FIX] Sealed a severe Volumetric Exfiltration vulnerability 
            where initial micro-bursts could permanently poison the EMA baseline 
            natively, masking sustained DNS tunneling traffic.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	// It is used in boot logs and the Web UI dashboards.
	BuildVersion string = "v1.266.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "07-May-2026 12:48 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "321"
)

