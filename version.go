/*
File:    version.go
Version: 1.672.0
Last Updated: 27-Nov-2026 13:30 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.672.0 - [CACHE/SECURITY/PERF] Deep DNS cache audit, RFC hardening & cleanup:
            - `cache_rw.go` (1.52.0): preserved EDNS0 Extended RCODEs (>=16),
              `EDNS0_EDE`, and `EDNS0_SUBNET` scope across cache pack/unpack via
              `sanitizeExtraForCache`; fixed `syncQuestionCasing` when Question
              casing already matches `qName`; added `CacheSetLocal` (`routeLocalTag`)
              and hit-counting in `CacheGetExpired`.
            - `cache.go` (2.60.0): upgraded `storeItem` to a 2-tier dead-first +
              hit-weighted sampled eviction policy so scan floods cannot evict hot
              entries; unified `isSyntheticRoute` helper across sweeper/UI/disk.
            - `cache_persistence.go` (2.27.0): separated `"local"` vs `""` synthetic
              restore gates in `LoadCache` and removed post-cache transforms from
              `computeUpstreamHash` to prevent unnecessary disk cache invalidations.
            - `cache_ui.go` (1.3.0): distinguished `"local"` vs `"synthetic"` origin
              and surfaced `[DO]`/`[CD]`/`[RD=0]` cache key partitions in `DumpCache`.
            - `process_local.go` (1.18.0), `process_cachehit.go` (1.40.0),
              `process_upstream.go` (1.33.0): wired `CacheSetLocal`, separated
              cached local-identity telemetry from synthetic policy blocks, and
              recorded `IncrCacheHit()` on `stale-fallback` responses.
            - `globals.go` (1.47.0), `init_core.go` (1.123.0),
              `full_reference_config.yaml` (1.133.0): removed dead `routeIdxLocal`
              symbol and corrected `serve_stale_infinite` sweeper documentation.
  1.671.0 - [SECURITY/CONCURRENCY/PERF] Full-repository consistency & hardening audit.
  1.670.0 - [SECURITY/PERF/FIX] Deep consistency, security, and performance audit.
  1.669.0 - [REFACTOR] Split `config.go` (`2.0.0`) into `config.go`,
            `config_parse.go`, `config_validate.go`, and `config_yaml.go`.
  1.668.0 - [SECURITY/FIX] Hardened `config.go` (`1.106.0`) validation, defaults,
            and YAML AST cleaning.
  1.667.0 - [SECURITY/FIX] Excluded `dns.TypeRRSIG` records from `minAnsTTL`
            and wire TTL clamping (`cache_rw.go` 1.49.0).
  1.666.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` and `CacheSetSynth`.
  1.665.0 - [SECURITY/FIX] Clamped `targetTTL` to `minAnsTTL` on non-`NOERROR`
            responses and preserved 30s stale-fallback TTLs.
  1.664.0 - [SECURITY/FIX] Clamped `ttl` on `isRcodeOnlyAfterClean` responses in
            `CacheSet` and filtered non-matching RR types during `consolidate`.
  1.663.0 - [SECURITY/FIX] Extended `applyRcodeOnlyWireTTL` and `CacheSet` to
            clamp `Answer` wire TTLs on non-`NOERROR` responses.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.672.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "27-Nov-2026 13:30 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "743"
)
