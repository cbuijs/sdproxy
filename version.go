/*
File:    version.go
Version: 1.533.0
Last Updated: 23-Oct-2026 17:18 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.533.0 - [SECURITY/FIX] Persisted metadata (`LastFetch`) on HTTP `304 Not Modified`
            across `identity_asn.go`, `init_policy.go`, and `parental_loader.go` so
            the 3-hour freshness TTL survives restarts; checked `scanner.Err()` on
            remote policy streams and respected `ipVersionSupport` for IP/CIDR
            entries in `init_policy.go`; invalidated stale `HTTPMeta` in
            `parental_loader.go` when a local URL cache file is missing; and verified
            local ASN file modification times before taking the cold-boot binary
            cache fast-path in `identity_asn.go`.
  1.532.0 - [FIX] Made `splitDomainPolicyKeys` (`config.go`) character-class aware
            (`[...]`) when scanning `/pattern/` regexes, and cleared stale
            `meta.HTTPMeta` entries in `pollDomainPolicies` (`init_policy.go`)
            when the raw cache file is missing on disk.
  1.531.2 - [FIX] Supported mixed comma-separated plain domains and `/pattern/`
            regex tokens on a single key in `splitDomainPolicyKeys` (`config.go`)
            and `initRRs` (`init_core.go`) without splitting commas inside regex
            quantifiers (`{1,3}`) or escaped slashes (`\/`).
  1.531.1 - [FIX] Guarded backslash escape scanning in `sanitizeYAMLRegexEscapes`
            (`config.go`) so a trailing backslash before a newline does not consume
            the newline and misalign subsequent line-start comment checks, and fixed
            missing `#` comment prefix in `full_reference_config.yaml`.
  1.531.0 - [FIX] Hardened YAML comment detection in `sanitizeYAMLRegexEscapes`
            (`config.go`) so `#` inside unquoted URLs is not mistaken for a comment,
            and fixed formatting/comment syntax in `full_reference_config.yaml`.
  1.530.0 - [FEAT/FIX] Added `sanitizeYAMLRegexEscapes` (`config.go`, `main.go`)
            and `\/` normalization in `compileDomainRegex` so double-quoted `/.../`
            regexes in YAML accept standard single-backslash escapes (`\.`, `\d`,
            `\w`, `\b`, `\-`, etc.) without YAML escape errors or double backslashes.
  1.529.3 - [FIX] Fixed `Route: v.routeName` assignment in `SaveCache`
            (`cache_persistence.go`).
  1.529.2 - [FIX] Replaced generic square-bracket syntax in `helpers_io.go`,
            `globals.go`, `cache_persistence.go`, and `parental_categories.go`
            with `loadGobInto` and typed holder structs so clipboard/markdown
            parsers cannot strip `[T any]` type parameters.
  1.529.1 - [FIX] Added `loadCompiledPolicyGob` in `helpers_io.go` and updated
            `init_policy.go` to avoid bracketed generic instantiation syntax.
  1.529.0 - [FEAT] Added regular expression matching (`/pattern/`) for DNS domains
            in `domain_policy:`, `domain_policy_files:`, `domain_policy_urls:`,
            `rrs:`, and `groups.<group>.rrs:`, including load/startup regex syntax
            validation (`config.go`, `globals.go`, `init_core.go`, `init_policy.go`,
            `policy.go`, `process_spoof.go`, `full_reference_config.yaml`).
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.533.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "23-Oct-2026 17:18 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "598"
)

