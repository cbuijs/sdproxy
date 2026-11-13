/*
File:    version.go
Version: 1.606.1
Last Updated: 13-Nov-2026 14:20 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.606.1 - [FIX] Fixed `r.ownerZone` struct field reference in `probeParkedTarget`
            (`parked.go` 1.15.1).
  1.606.0 - [SECURITY/FIX] Treated `consensus-log(...)` responses identically to
            `consensus(...)` failure responses in `probeForSaleTarget` (`for_sale.go`
            1.14.0), `probeParkedTarget` (`parked.go` 1.15.0), and
            `backgroundRevalidate` (`process_cache.go` 1.34.0) so unverified
            consensus-failed responses in `block_action: "LOG"` mode are never
            cached by internal probes or background cache revalidators.
  1.605.0 - [SECURITY/FIX] Honored `block_action: "LOG"` on `strategy: "secure"`
            consensus validation failures (`upstream_race.go` 2.64.0,
            `process_upstream.go` 1.25.0) so audit mode logs the consensus mismatch
            and returns the best available valid response without poisoning the
            cache; and synced `clientName` / `clientGroup` in `ProcessDNS`
            (`process.go` 3.127.0) if a forced `client-name` route overrides
            `client_name` a second time.
  1.604.0 - [SECURITY/FIX] Treated `consensus(...)` failure responses from
            `group.Exchange` as probe/revalidation failures rather than valid
            DNS responses in `probeForSaleTarget` (`for_sale.go` 1.13.0),
            `probeParkedTarget` (`parked.go` 1.14.0), and `backgroundRevalidate`
            (`process_cache.go` 1.33.0), and pre-sorted `ip-sort` answers in
            `backgroundRevalidate` for parity with `serveFromUpstream`.
  1.603.0 - [SECURITY/FIX/PERF] Permitted a forced `client-name` route to override
            or merge with an initial forced route that overrode `client_name` in
            `ProcessDNS` (`process.go` 3.126.0), and cancelled `raceCtx` immediately
            upon consensus failure or loose majority completion in `exchangeSecure`
            (`upstream_race.go` 2.63.0) so remaining in-flight upstream probes
            abort immediately.
  1.602.0 - [SECURITY/FIX] Prevented synthetic consensus blocks (`consensus(<group>)`)
            from being stored in `CacheSet` and ensured `IncrPolicyBlock()` and
            `RecordBlockEvent()` are recorded across all `block_action` modes in
            `serveFromUpstream` (`process_upstream.go` 1.24.0); preserved primary
            route properties when a `client_name` override matches a forced
            `client-name` route in `ProcessDNS` (`process.go` 3.125.0); and
            normalized `*dns.AAAA` addresses with `.Unmap()` in `canonicalizeRR`
            (`upstream_race.go` 2.62.0).
  1.601.0 - [SECURITY/FIX] Fixed `force: true` scanning across `macWildRoutes`,
            `ednsMACWildRoutes`, `cidrRoutes`, and `ecsCIDRRoutes` in both
            `resolveClientRoute` (`process_routing.go` 1.24.0) and
            `ResolveStateKeyAndGroup` (`parental.go` 3.53.0) so a broader subnet
            or later glob rule with `force: true` is never skipped after an
            unforced match; and ensured `clientGroup` upstream/bypass_local
            fallback in `ProcessDNS` (`process.go` 3.124.0) runs even when a
            route with `force: true` and `upstream: ""` overrides `client_name`.
  1.600.0 - [SECURITY/FIX] Tightened Authority (`Ns`) bailiwick validation in
            `CacheSet` (`cache_rw.go` 1.34.0) to disallow child subdomain zones
            in `Ns`; fixed forced `CC:` country route evaluation in
            `resolveClientRoute` (`process_routing.go` 1.23.0) when an unforced
            higher-precedence route also matched; normalized `*dns.AAAA` addresses
            with `.Unmap()` in `applyAnswerSort` (`transform.go` 1.18.0); and
            guarded `handleApiClientBlock` capacity eviction (`webui_api.go` 1.21.0)
            when re-blocking an already-blocked client.
  1.599.0 - [SECURITY/FIX/PERF] Applied `effectiveMin` directly onto positive answer
            RRs during `CacheSet` (`cache_rw.go` 1.33.0) so DNSSEC-signed responses
            with `maxSigTTL < cfg.Cache.MinTTL` are never inflated past `maxSigTTL`
            during `CacheGet` decay; pre-sorted `ip-sort` answers before `CacheSet`
            in `serveFromUpstream` (`process_upstream.go` 1.23.0) and removed dead
            `CacheUpdateOrder`.
  1.598.0 - [SECURITY/FIX] Decayed individual record TTLs by elapsed cache time
            (`elapsed = uint32((now - item.cachedAtNano) / int64(time.Second))`)
            in `CacheGet` (`cache_rw.go` 1.32.0), removed `CacheUpdateOrder` from
            `serveFromCache` (`process_cachehit.go` 1.23.0) so decayed per-request
            TTLs are never written back into the shared cache item, and merged
            secondary `client-name` route properties in `ProcessDNS` (`process.go`
            3.123.0) when a higher-precedence route overrides `client_name`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.606.1"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "13-Nov-2026 14:20 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "675"
)
