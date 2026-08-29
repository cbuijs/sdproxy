/*
File:    version.go
Version: 1.462.0
Last Updated: 29-Aug-2026 10:39 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.462.0 - [SECURITY/FIX] Addressed LAN Privacy Leakage. `process_local.go` now explicitly 
            intercepts non-standard queries (HTTPS, TXT) aimed at local identities natively, 
            returning an authoritative NODATA structure to completely protect local domains 
            from leaking upstream.
          - [SECURITY/FIX] Switched `dohResponseWriter`, `doqResponseWriter`, and downstream 
            packing handlers to uniformly harness the `largeBufPool` array (64KB). Definitively 
            eradicates `dns.ErrBuf` overflows resulting in empty payloads for robust responses 
            like DNSSEC and expansive TXT records.
  1.461.0 - [SECURITY/FIX] Enforced `SOA` authority injection natively across 
            `NOERROR` (NODATA) synthetic policy responses to guarantee RFC 2308 
            compliance and prevent client retry floods.
          - [FEAT] Restored Round-Robin permutation algorithms cleanly onto 
            stale-cache fallback payloads, preserving load-balancing bounds 
            during upstream connection outages natively.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.462.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "29-Aug-2026 10:39 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "521"
)

