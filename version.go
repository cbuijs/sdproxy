/*
File:    version.go
Version: 1.460.0
Last Updated: 26-Aug-2026 16:30 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.460.0 - [PERF] Eradicated redundant heap slice allocations natively within 
            the background Cache Sweeper routine. Reusing slice capacities 
            prevents thousands of throwaway allocations organically across 
            the daemon lifecycle.
  1.459.0 - [SECURITY/FIX] Resolved a severe Custom Rules Routing Evasion vulnerability. 
            Proactively evaluated `ClientName` structural overrides prior to Custom Rules 
            execution, guaranteeing that globally mapped IP policies correctly identify 
            and inherit explicit Group assignments dynamically.
            [CLEANUP] Deduplicated redundant Base64 extraction layers in L7 Out-of-Band 
            discovery natively, utilizing the core `decodeBase64Flex` primitive organically.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.460.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "26-Aug-2026 16:30 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "519"
)

