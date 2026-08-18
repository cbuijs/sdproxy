/*
File:    version.go
Version: 1.455.0
Last Updated: 18-Aug-2026 13:48 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.455.0 - [PERF/FIX] Completely overhauled historical filesystem preservation IO schemas. 
            Deployed direct streaming structures (`json.NewEncoder`) to securely eliminate 
            large memory allocations and 100% CPU lockups previously caused by massive 
            topological metrics and `json.MarshalIndent` boundaries organically.
            Also restricted `saveSnapshot` mechanisms from issuing aggressive filesystem 
            journal commits unless dynamic budget deductibles were definitively executed.
  1.454.0 - [SECURITY/FIX] Eradicated a critical Initialization Deadlock natively.
            Moved `InitThrottle()` prior to executing `initUpstreams()` and bootstrap
            parsing operations within `main.go`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.455.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "18-Aug-2026 13:48 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "514"
)

