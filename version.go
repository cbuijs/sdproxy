/*
File:    version.go
Version: 1.540.0
Last Updated: 25-Oct-2026 16:45 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.540.0 - [FEAT] Added `-U` / `--update-config` command-line flag (`main.go`,
            `config.go`) to merge an existing configuration file onto the
            embedded `FullReferenceConfigYAML` AST, complementing it with all
            documentation comments and missing/new options while keeping all
            existing user options and custom entries intact.
  1.539.0 - [FEAT] Added `-C` / `--clean-config` and `-E` / `--example-config`
            command-line flags (`main.go`, `config.go`) to strip comments/default
            values from user configs and to emit the embedded full reference config.
  1.538.0 - [SECURITY/FIX] Remediated Third – Reliability and performance audit findings:
            1. Partitioned `AnalyzeSubdomainLimit` (`subdomain_limit.go`,
               `process_security.go`) by `(client/subnet, apex)` (`sdlKey`) so
               one client cannot trigger a cross-client DoS for an apex domain.
            2. Replaced the unrestricted `strings.Contains(fullDomain, "awsdns-")`
               DGA bypass in `dga.go` with `isVerifiedAWSDNS` (validating only
               authentic Route 53 `awsdns-<digits>.<org|com|net|co.uk>` nameservers)
               and converted `dgaSafeDomains` to an O(1) map suffix walk.
            3. Bounded concurrent upstream bootstrap/DDR initialization goroutines
               in `init_upstreams.go` via `upstreamInitSem`.
            4. Aligned `docker/docker-compose.yml` build context (`..`) and
               `docker/DockerFile` filename casing.
  1.537.0 - [SECURITY/FIX] Remediated Second – Cache correctness audit findings:
            1. Added per-route upstream configuration fingerprinting (`RouteHash`,
               `cacheDiskVersion = 3`) in `cache_persistence.go`.
            2. Restricted `CacheGetExpired` (`cache_rw.go`) and `runSweeper`
               (`cache.go`) so expired synthetic responses (`routeName == ""`)
               are never served indefinitely under `serve_stale_infinite`.
            3. Updated `SaveCache` (`cache_persistence.go`) to remove or clear
               the on-disk snapshot when the live in-memory cache is empty.
            4. Preserved the client's `RecursionDesired` (`RD`) flag in
               `buildSynthCacheMsg` and restored it on unpack in `CacheGet` and
               `CacheGetExpired`.
            5. Enforced strict DNSSEC cache lifetime bounds in `CacheSet`
               (`cache_rw.go`).
  1.536.0 - [SECURITY/FIX] Remediated First – Security boundaries audit findings.
  1.535.0 - [SECURITY/FIX] Hardened `splitDomainPolicyKeys` in `config.go`.
  1.534.0 - [SECURITY/FIX] Fixed `exempt:` domain matching in `subdomain_limit.go`.
  1.533.0 - [SECURITY/FIX] Persisted metadata (`LastFetch`) on HTTP `304 Not Modified`.
  1.532.0 - [FIX] Made `splitDomainPolicyKeys` (`config.go`) character-class aware.
  1.531.2 - [FIX] Supported mixed comma-separated plain domains and `/pattern/`
            regex tokens on a single key in `splitDomainPolicyKeys` (`config.go`).
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.540.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "25-Oct-2026 16:45 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "605"
)

