/*
File:    version.go
Version: 1.667.0
Last Updated: 19-Nov-2026 17:15 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.667.0 - [SECURITY/FIX] Excluded `dns.TypeRRSIG` records from `minAnsTTL`
            and wire TTL clamping in `applyRcodeOnlyWireTTL`, `CacheSet`, and
            `rewriteAuthorityTTLInPlace` (`cache_rw.go` 1.49.0), capped
            Authority (`Ns`) wire TTLs by `minAnsTTL` in `applyRcodeOnlyWireTTL`
            even when no `rcode_*` / `min_ttl` / `max_ttl` options are set, and
            derived `soaTTL` via `extractAuthorityTTL(res.Ns)` in
            `spoofResponseWriter.WriteMsg` (`process_spoof.go` 1.42.0).
  1.666.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` and `CacheSetSynth`
            (`cache_rw.go` 1.48.0) on non-`NOERROR` responses containing
            `Answer` records and authoritative synthetic responses, applied
            `applyRcodeOnlyWireTTL` in `buildSynthCacheMsg` (`process_cache.go`
            1.36.0), and preserved `rcode_min_ttl` / `rcode_ttl` floors on
            synthesized negative SOA records in `spoofResponseWriter.WriteMsg`
            (`process_spoof.go` 1.41.0).
  1.665.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.47.0)
            with `CacheSet` by clamping `targetTTL` to `minAnsTTL` on non-`NOERROR`
            responses containing `Answer` records and reordered `CacheSetSynth`
            so `Answer` TTL clamping precedes `Ns` rewriting; preserved bounded
            30s RFC 8767 stale TTLs on `stale-fallback` responses in
            `serveFromUpstream` (`process_upstream.go` 1.32.0); capped negative
            SOA wire TTLs in `spoofResponseWriter.WriteMsg` (`process_spoof.go`
            1.40.0) by `minTTL` (`parentalForcedTTL` / `minAliasTTL`).
  1.664.0 - [SECURITY/FIX] Clamped `ttl` on `isRcodeOnlyAfterClean` responses in
            `CacheSet` (`cache_rw.go` 1.46.0) by the minimum `Answer` record TTL
            when CNAME/DNAME records are present, clamped terminal record TTLs
            in `spoofResponseWriter.WriteMsg` (`process_spoof.go` 1.39.0) by
            `minAliasTTL`, included `CacheUpstreamNegative` in the upstream
            route persistence fingerprint (`cache_persistence.go` 2.24.0), and
            filtered non-matching RR types during `consolidate` merging in
            `exchangeSecure` (`upstream_race.go` 2.68.0).
  1.663.0 - [SECURITY/FIX] Extended `applyRcodeOnlyWireTTL` and `CacheSet`
            (`cache_rw.go` 1.45.0) so unsigned non-`NOERROR` responses containing
            `Answer` records (e.g. `NXDOMAIN` with CNAME records) clamp both
            their `Answer` wire TTLs (`[min_ttl, max_ttl]`) and Authority (`Ns`)
            wire TTLs, allowed non-`NXDOMAIN` / non-`NOERROR` RCODE responses
            containing `Answer` records to be cached when `rcode_ttl` or
            `rcode_min_ttl` is configured, and checked `isRcodeOnly` in
            `CacheSetSynth`.
  1.662.0 - [SECURITY/FIX] Prevented `computeRcodeOnlyTTL` and `rcodeTTLBounds`
            (`cache_rw.go` 1.44.0) from applying `min_ttl` or `negative_ttl` to
            non-negative RCODEs (e.g. `SERVFAIL`, `REFUSED`), checked
            `!hasAnyRRSIG(msg)` and `msg.Rcode == dns.RcodeSuccess` in
            `applyRcodeOnlyWireTTL`, and preserved individual RR TTL clamping in
            `CacheSetSynth`.
  1.661.0 - [SECURITY/FIX] Aligned `CacheSet` (`cache_rw.go` 1.43.0) positive
            answer wire-TTL clamping with `applyRcodeOnlyWireTTL` and
            `CacheSetSynth`.
  1.660.0 - [SECURITY/FIX] Aligned `applyRcodeOnlyWireTTL` (`cache_rw.go` 1.42.0)
            with `CacheSet` and `CacheSetSynth` so unsigned positive answers
            (`len(Answer) > 0`) also have their wire TTLs clamped to
            `[min_ttl, max_ttl]` on cache misses and in `CacheSetSynth`.
  1.659.0 - [SECURITY/FIX] Preserved distinct `SOA.Hdr.Ttl` and `SOA.Minttl`
            values in `rewriteAuthorityTTLInPlace` (`cache_rw.go` 1.41.0).
  1.658.0 - [SECURITY/FIX] Fixed `rewriteAuthorityTTLInPlace` (`cache_rw.go`
            1.40.0) and decayed `soa.Minttl` alongside `rr.Header().Ttl`
            in `CacheGet` and `CacheGetExpired`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.667.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "19-Nov-2026 17:15 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "738"
)
