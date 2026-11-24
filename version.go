/*
File:    version.go
Version: 1.670.0
Last Updated: 23-Nov-2026 14:35 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.670.0 - [SECURITY/PERF/FIX] Deep consistency, security, and performance audit:
            - `cache.go` (2.59.0), `cache_persistence.go` (2.25.0), `cache_rw.go`
              (1.50.0): ceiling per-shard sizing, `IgnoreQnameLabels` in synthetic
              route fingerprint, authority wire-TTL capping by `targetTTL`, and
              `isSynth` returned directly from `CacheGet`.
            - `config_validate.go` (1.1.0), `config_yaml.go` (1.1.0): fail-closed
              cross-reference validation (`webui.password`, `groups`, `categories`,
              `upstreams`), DoH URL syntax validation, and empty `webui.listen`
              AST cleanup.
            - `for_sale.go` (1.19.0), `parked.go` (1.20.0), `rfc_compliance.go`
              (1.17.0), `process_cachehit.go` (1.38.0): switched to `isSynth` from
              `CacheGet` so `AA=1` upstream cache entries are inspected without
              TOCTOU shard re-locks.
            - `process_filters.go` (2.41.0), `process_security.go` (1.38.0),
              `process_spoof.go` (1.43.0), `parental_bg.go` (1.15.0): permitted
              254-byte dot-terminated FQDNs, checked Custom Rules on `target_name`,
              stripped invalidated `RRSIG`s in `filterResponseIPs`, exempted
              service/DDR names from DGA, returned `SERVFAIL` on non-UDP cold-boot
              startup guard, fixed multi-hop `spoofResponseWriter` unwrapping, and
              clamped `runDebitTicker` budgets at 0.
            - `server.go` (1.46.0), `upstream_race.go` (2.69.0): rejected <12B
              DoH/DoQ frames pre-alloc, eliminated per-call `net.ParseIP` in
              `RemoteAddr()`, and flattened cross-CDN CNAME chains in `consolidate`
              mode so merged IPs pass `CacheSet` bailiwick validation.
  1.669.0 - [REFACTOR] Split `config.go` (`2.0.0`) into `config.go`,
            `config_parse.go`, `config_validate.go`, and `config_yaml.go`.
  1.668.0 - [SECURITY/FIX] Hardened `config.go` (`1.106.0`) validation, defaults,
            and YAML AST cleaning.
  1.667.0 - [SECURITY/FIX] Excluded `dns.TypeRRSIG` records from `minAnsTTL`
            and wire TTL clamping (`cache_rw.go` 1.49.0) and derived `soaTTL`
            via `extractAuthorityTTL` (`process_spoof.go` 1.42.0).
  1.666.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` and `CacheSetSynth`
            (`cache_rw.go` 1.48.0), `buildSynthCacheMsg` (`process_cache.go`
            1.36.0), and `spoofResponseWriter.WriteMsg` (`process_spoof.go` 1.41.0).
  1.665.0 - [SECURITY/FIX] Clamped `targetTTL` to `minAnsTTL` on non-`NOERROR`
            responses (`cache_rw.go` 1.47.0) and preserved 30s stale-fallback
            TTLs (`process_upstream.go` 1.32.0).
  1.664.0 - [SECURITY/FIX] Clamped `ttl` on `isRcodeOnlyAfterClean` responses in
            `CacheSet` (`cache_rw.go` 1.46.0) and filtered non-matching RR types
            during `consolidate` merging (`upstream_race.go` 2.68.0).
  1.663.0 - [SECURITY/FIX] Extended `applyRcodeOnlyWireTTL` and `CacheSet`
            (`cache_rw.go` 1.45.0) to clamp `Answer` wire TTLs on non-`NOERROR`
            responses.
  1.662.0 - [SECURITY/FIX] Prevented `computeRcodeOnlyTTL` (`cache_rw.go` 1.44.0)
            from applying `min_ttl` or `negative_ttl` to non-negative RCODEs.
  1.661.0 - [SECURITY/FIX] Aligned `CacheSet` (`cache_rw.go` 1.43.0) positive
            answer wire-TTL clamping with `applyRcodeOnlyWireTTL`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.670.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "23-Nov-2026 14:35 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "741"
)
