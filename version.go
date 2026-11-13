/*
File:    version.go
Version: 1.607.0
Last Updated: 13-Nov-2026 15:00 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.607.0 - [SECURITY/FIX] Rejected NULL-IP (`0.0.0.0` / `::`) responses and
            truncated responses in `pickFallback` inside `exchangeSecure`
            (`upstream_race.go` 2.65.0) so `block_action: "LOG"` consensus-audit
            fallbacks never prefer a sinkholed NULL-IP response; and synced
            `clientName`, `clientNameLower`, and `clientID` with
            `routeCtx.clientName` after `determineRouting` in `ProcessDNS`
            (`process.go` 3.128.0).
  1.606.1 - [FIX] Fixed `r.ownerZone` struct field reference in `probeParkedTarget`
            (`parked.go` 1.15.1).
  1.606.0 - [SECURITY/FIX] Treated `consensus-log(...)` responses identically to
            `consensus(...)` failure responses in `probeForSaleTarget` (`for_sale.go`
            1.14.0), `probeParkedTarget` (`parked.go` 1.15.0), and
            `backgroundRevalidate` (`process_cache.go` 1.34.0).
  1.605.0 - [SECURITY/FIX] Honored `block_action: "LOG"` on `strategy: "secure"`
            consensus validation failures (`upstream_race.go` 2.64.0,
            `process_upstream.go` 1.25.0).
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
            (`upstream_race.go` 2.63.0).
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
            `ResolveStateKeyAndGroup` (`parental.go` 3.53.0); and ensured
            `clientGroup` upstream/bypass_local fallback in `ProcessDNS`
            (`process.go` 3.124.0) runs even when a route with `force: true` and
            `upstream: ""` overrides `client_name`.
  1.600.0 - [SECURITY/FIX] Tightened Authority (`Ns`) bailiwick validation in
            `CacheSet` (`cache_rw.go` 1.34.0) to disallow child subdomain zones
            in `Ns`; fixed forced `CC:` country route evaluation in
            `resolveClientRoute` (`process_routing.go` 1.23.0); normalized
            `*dns.AAAA` addresses with `.Unmap()` in `applyAnswerSort`
            (`transform.go` 1.18.0); and guarded `handleApiClientBlock` capacity
            eviction (`webui_api.go` 1.21.0).
  1.599.0 - [SECURITY/FIX/PERF] Applied `effectiveMin` directly onto positive answer
            RRs during `CacheSet` (`cache_rw.go` 1.33.0); pre-sorted `ip-sort`
            answers before `CacheSet` in `serveFromUpstream` (`process_upstream.go`
            1.23.0) and removed dead `CacheUpdateOrder`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.607.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "13-Nov-2026 15:00 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "676"
)
