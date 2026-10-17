/*
File:    version.go
Version: 1.500.0
Last Updated: 17-Oct-2026 19:54 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.500.0 - [SECURITY/FIX] Bound `shutdownCh` teardown hooks to TCP, DoT, DoH, DoH3,
            and Web UI HTTP/HTTPS listeners (`server_init.go`, `webui.go`), moved
            `activeDoQConns` outside the DoQ retry closure, and isolated `doh3TLS`
            clones with explicit `h3` ALPN.
          - [SECURITY/FIX] Added `customRulesMinLabels` floor bound and normalized
            rule `Action` values in `rules.go` and `webui_api.go` (`handleApiRulesSet`),
            and wired `shutdownCh` into `/api/logs` SSE streams.
  1.499.0 - [SECURITY/FIX] Wrapped UDP listeners (`server_udp_linux.go`, `server_udp_stub.go`)
            in `superviseListener` and bound their teardown to `shutdownCh`, eliminating
            runtime `log.Fatalf` calls that could crash all other active transports.
          - [SECURITY/FIX] Added RFC 2308 negative SOA record synthesis in
            `filterResponseIPs` (`process_filters.go`) when IP filtering produces
            an empty Answer section (NODATA).
          - [FIX] Fixed header date typo in `full_reference_config.yaml`.
  1.498.0 - [FIX] Propagated `localPort` through `queryCtx`, `process_cachehit.go`,
            `process_upstream.go`, `process_filters.go`, and `parental.go` (`CheckParental`)
            so port-based parental routes in `device` budget tracking mode consistently
            resolve `port:<port>` device keys across all pipeline stages.
          - [FIX] Stripped residual Markdown hyperlink formatting from
            `full_reference_config.yaml` (`rrs:` and `upstreams:` examples).
  1.497.0 - [SECURITY/FIX] Injected `http.LocalAddrContextKey` via `ConnContext` on
            `http3.Server` in `server_init.go` so DoH3 requests preserve the bound
            local address/port for `port:` routing and DDR local-IP fallbacks.
          - [SECURITY/FIX] Added missing `User-Agent` header on DoH/DoH3 DDR probes
            and checked `io.ReadAll` errors in `upstream_ddr.go`.
          - [FIX] Made `sni:`, `path:`, and `port:` route prefix parsing
            case-insensitive, preserved root path `"/"`, and unmapped `rkIP` keys
            in `routes.go`, `init_routing.go`, `process_routing.go`, and `parental.go`.
  1.496.0 - [FEAT/FIX] Added `port:` and `force-and` compound routing support to
            `parental.go` (`InitParental`, `ResolveStateKeyAndGroup`) and propagated
            `localPort` in `process.go` so port-based and compound parental group
            rules are enforced.
          - [SECURITY/FIX] Fixed `filterResponseIPs` in `process_filters.go` so
            responses where all terminal A/AAAA records are stripped but CNAMEs
            remain are properly treated as fully blocked instead of returning an
            un-flattened dangling CNAME chain.
          - [SECURITY/FIX] Hardened `ddr.go` (`handleDDR`) to avoid advertising
            broken `HTTPS` SVCB records when `ddrDoHPort == 0` and to attach
            RFC 2308 negative SOA records on NODATA responses.
  1.495.0 - [SECURITY/FIX] Preserved `key.RecursionDesired` in `process_cache.go`
            (`backgroundRevalidate`) so `RD=0` cache entries are not revalidated
            with `RD=1`.
          - [SECURITY/FIX] Added missing `User-Agent` header and gzip decompression
            overflow abort in `identity_asn.go` (`pollASN`, `parseAndCompile`).
          - [SECURITY/FIX] Aborted saving and ingesting partial blocklists on
            scanner/size-limit errors in `parental_loader.go` (`loadAllCategoryLists`).
          - [FIX] Sanitized accidental markdown hyperlink formatting in
            `full_reference_config.yaml`.
  1.494.0 - [SECURITY/FIX] Removed destructive `closer.Close()` in `upstream_net.go`
            (`exchangeHTTP`) which permanently broke `*http3.Transport` after a single
            retry, and added a zero-progress read guard (`maxZeroReads = 64`) on
            upstream HTTP responses.
          - [SECURITY/FIX] Fixed multi-hop CNAME flattening and minimum TTL tracking
            in `transform.go` (`flattenCNAME`).
          - [SECURITY/FIX] Fixed SOA zone corruption and shared RR pointer mutation
            in `process_spoof.go` (`spoofResponseWriter.WriteMsg`).
          - [SECURITY/FIX] Hardened `webui_html.go` with POST-only `/logout` enforcement
            and strike-preserving sampled eviction for `loginStates`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.500.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "17-Oct-2026 19:54 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "559"
)

