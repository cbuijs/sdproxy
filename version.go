/*
File:    version.go
Version: 1.461.0
Last Updated: 28-Aug-2026 16:01 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.461.0 - [SECURITY/FIX] Enforced `SOA` authority injection natively across 
            `NOERROR` (NODATA) synthetic policy responses to guarantee RFC 2308 
            compliance and prevent client retry floods.
          - [FEAT] Restored Round-Robin permutation algorithms cleanly onto 
            stale-cache fallback payloads, preserving load-balancing bounds 
            during upstream connection outages natively.
  1.460.0 - [PERF] Eradicated redundant heap slice allocations natively within 
            the background Cache Sweeper routine. Reusing slice capacities 
            prevents thousands of throwaway allocations organically across 
            the daemon lifecycle.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.461.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "28-Aug-2026 16:01 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "520"
)

