/*
File:    version.go
Version: 1.671.0
Last Updated: 24-Nov-2026 14:40 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.671.0 - [SECURITY/CONCURRENCY/PERF] Full-repository consistency & hardening audit:
            - `server_init.go` (1.33.0), `webui.go` (1.69.0): restricted DoH `/`
              Web UI multiplexing strictly to `webui.listen_https` addresses and
              hardened `ForceHTTPS` redirects against missing/open-redirect hosts.
            - `cache_rw.go` (1.51.0), `cache_persistence.go` (2.26.0): fixed
              `NXDOMAIN` / negative caching for TLD/eTLD and root `"."` SOA/NSEC
              authority records, preserved `SOA.Minttl` RDATA on cache reads, and
              memoized `routeHashMemo` digests outside shard locks.
            - `idn_homograph.go` (1.10.0): closed forged-ASCII Punycode bypass
              (`xn--paypal-`) via canonical IDNA round-tripping and non-ASCII
              enforcement across all labels.
            - `upstream.go` (2.59.0), `upstream_net.go` (1.46.0), `upstream_parser.go`
              (2.60.0), `upstream_race.go` (2.70.0): blocked OS DNS fallback leaks
              on bootstrap failure, replaced per-query cancellation goroutines with
              `context.AfterFunc`, removed premature loose-consensus majority exits,
              and added throttled (10s) unhealthy recovery probes.
            - `rfc_compliance.go` (1.18.0), `process.go` (3.158.0), `process_cachehit.go`
              (1.39.0), `stats.go` (3.5.0), `stats_hourly.go` (1.10.0): isolated
              SingleFlight sub-probes, fixed `client_name` route chaining, tracked
              `statCacheLookups` for accurate hit rates, and clamped hourly deltas.
            - `config_validate.go` (1.2.0), `config_yaml.go` (1.2.0), `ddr.go` (1.14.0),
              `init_core.go` (1.122.0), `identity.go` (2.15.0), `parental.go` (3.55.0),
              `parental_bg.go` (1.16.0), `parental_io.go` (2.3.0), `exfiltration.go`
              (1.24.0), `ratelimit.go` (1.21.0), `subdomain_limit.go` (1.6.0),
              `process_leak.go` (1.9.0), `server_udp_stub.go` (1.5.0), `webui_html.go`
              (1.31.0), `webui_components.go` (1.38.0), `script.js` (1.40.0).
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
  1.662.0 - [SECURITY/FIX] Prevented `computeRcodeOnlyTTL` from applying
            `min_ttl` or `negative_ttl` to non-negative RCODEs.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.671.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "24-Nov-2026 14:40 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "742"
)
