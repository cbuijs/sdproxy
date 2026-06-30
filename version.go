/*
File:    version.go
Version: 1.421.0
Last Updated: 30-Jun-2026 09:47 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.421.0 - [FEAT] Integrated ISO 3166-1 alpha-2 `Country` origin identifiers naturally 
            into the client profile resolution capabilities utilizing the high-performance 
            IPinfo databases natively.
  1.420.0 - [SECURITY/FIX] Addressed a persistent caching failure during ASN database restarts. 
            Replaced `netip.Addr` structures with an explicit `AsnRangeGob` string-based 
            mapping to avert silent `encoding/gob` decoding rejections. Additionally injected 
            preemptive `os.Remove` commands before atomic `os.Rename` operations to circumvent 
            OS-level file lock rejections (e.g., on Windows) that destroyed cache metadata.
  1.419.0 - [BUG/FIX] Resolved a build compilation error (`declared and not used: actionName`) natively within `init_policy.go`.
*/

package main

import "sync/atomic"

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.421.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "30-Jun-2026 09:47 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "479"
)

// atomic import guard — ensures the import is used even if all atomics are
// accessed via the version/build tracker.
var _ atomic.Int64

