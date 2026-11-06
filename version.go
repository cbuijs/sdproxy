/*
File:    version.go
Version: 1.592.0
Last Updated: 06-Nov-2026 08:15 CET
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.592.0 - [SECURITY/FIX] Preserved authority SOA TTL bounds on cached negative
            responses when `remaining >= rr.Header().Ttl` (`cache_rw.go` 1.29.0)
            and synchronized `clientName` / `clientID` before step 1.6 `rrs:`
            evaluation when a client route specifies a `client_name` override
            (`process.go` 3.119.0).
  1.591.0 - [SECURITY/FIX] Enforced `enforceUDPDefenses` on Malformed QNAME
            (`FORMERR`) responses and moved `IncrDomain` past the QClass, QNAME,
            Anti-Amplification, Startup Guard, and Web UI Client Block gates in
            `enforceSecurityGuards` (`process_security.go` 1.31.0), and validated
            `isValidQNAME` on `rrs:` CNAME targets in `handleSpoofedRecords`
            (`process_spoof.go` 1.32.0).
  1.590.0 - [CRITICAL/FIX] Separated `handshakeTimeout` (5s) from `idleTimeout` (15s/30s)
            on `tlsHandshakeListener` (`server_init.go` 1.32.0, `webui.go` 1.68.0) and
            eliminated a mutex/atomic ordering race in `tlsHandshakeConn.ensureHandshake`
            where `SetReadDeadline` / `SetWriteDeadline` ran outside `tc.mu` after
            `tc.hsDone.Store(true)`, and hardened `ProcessDNS` (`process.go` 3.118.0)
            to re-evaluate `CheckParental` on CNAME-aliased `PTR` queries.
  1.589.0 - [CRITICAL/FIX] Fixed post-handshake idle read deadline fallback in
            `tlsHandshakeConn.ensureHandshake` (`server_init.go` 1.31.0) when
            `dns.Server` queries `ConnectionState()` before setting its read
            deadline on DoT connections, added HTTP security headers to DoH and
            `.well-known` endpoints (`server.go` 1.45.0, `server_init.go` 1.31.0),
            and rejected zero-length DoQ messages (`server.go` 1.45.0).
  1.588.0 - [CRITICAL/FIX] Set a 5-second initial read deadline on newly accepted
            TCP sockets directly in `keepAliveListener.Accept` (`server_init.go`
            1.30.0) without a connection wrapper.
  1.587.0 - [CRITICAL/FIX] Removed `initialDeadlineConn` from `keepAliveListener`
            (`server_init.go` 1.29.0) so `dns.Server` and `http.Server` manage
            read and idle deadlines without wrapper interference, enforced RFC 7873
            §5.2.2 length and hex-character validation on received `EDNS0_COOKIE`
            options (`upstream.go` 2.55.0), and updated `handleSpoofedRecords`
            (`process_spoof.go` 1.31.0, `process.go` 3.117.0) to update existing
            `spoofResponseWriter` targets in place on chained CNAME rewrites.
  1.586.0 - [CRITICAL/FIX] Added `initialDeadlineConn` in `keepAliveListener`
            (`server_init.go` 1.28.0), fixed SOA-less DNSSEC negative response
            caching in `CacheSet` (`cache_rw.go` 1.28.0), recorded `IncrReturnCode`
            on local `PTR` and `NODATA` responses (`process_local.go` 1.15.0), and
            evaluated `originalQNameTrimmed` alongside CNAME-rewritten targets
            in `for_sale.go` (1.12.0) and `parked.go` (1.13.0).
  1.585.0 - [CRITICAL/FIX] Replaced `closer.Close()` with `client.CloseIdleConnections()`
            in `exchangeHTTP` (`upstream_net.go` 1.42.0), fixed post-handshake
            deadline restoration in `tlsHandshakeConn.ensureHandshake`
            (`server_init.go` 1.27.0), and enforced unconditional
            `inspectRRSIGBounds` and nil `packedData` guards in `CacheGet` /
            `CacheGetExpired` (`cache_rw.go` 1.27.0).
  1.584.0 - [CRITICAL/FIX] Hardened `tlsHandshakeConn.ensureHandshake` post-handshake
            read deadline fallback (`server_init.go`), and swept `h3Client` /
            `h3ClientNoECH` idle sessions in `SweepUpstreamConns` (`upstream.go`).
  1.583.1 - [FIX] Fixed `c.Server.RateLimit.PenaltyBox.StrikeThreshold` field
            path in `CleanConfigYAML` (`config.go`).
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.592.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "06-Nov-2026 08:15 CET"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "660"
)
