/*
File:    version.go
Version: 1.488.0
Last Updated: 25-Sep-2026 14:31 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.488.0 - [PERF] Eradicated `fmt.Sprintf` heap allocations natively within `RcodeStr` inside `process_helpers.go`.
            Utilizes the zero-allocation `itoa64` numeric formatter to completely neutralize Garbage Collection (GC) 
            thrashing when parsing unknown/custom RCODE telemetry representations.
  1.487.0 - [BUG/FIX] Corrected `quic.Connection` and `quic.EarlyConnection` usages to `*quic.Conn` natively across `upstream_net.go` and `upstream_parser.go` to securely satisfy the struct signature requirements of `quic-go` (versions >= 0.40.0) natively.
  1.486.0 - [BUG/FIX] Corrected parameter usage when instantiating `quic.DialAddrEarly` and `quic.DialAddr` in QUIC/DoQ implementations.
            `quic-go` (versions >= 0.40.0) requires precisely 3 arguments (`ctx`, `addr`, `tlsConf`, `quicConf`) for DialAddr and DialAddrEarly.
            For `http3.Server.Dial` and `http3.Transport.Dial` signatures, `quic.EarlyConnection` is the expected return type.
            Ensured all dialing interfaces natively comply with the strict signature array structurally to fix compilation errors.
  1.485.0 - [SECURITY/FIX] Resolved issues utilizing `TryLock` evaluation loops organically. 
            Ensures proper instantiation of the timestamp comparison baseline (time.Time zero value) 
            and pointers are securely preserved during client iteration to prevent arbitrary panics 
            when performing memory evictions cleanly. Addressed strict OOM bounds tracking linearly 
            for `sync.Map` in `webuiClientBlocks`.
  1.484.0 - [FIX] Restored proper initialization of `cfg.Groups` to prevent nil 
            map assignment panics when configuring router profiles organically.
          - [FIX] Re-added missing map declarations (`compoundRouteMap`, `compoundRouteMappings`)
            in `globals.go` to solve build failures when processing Compound Routes natively.
          - [FIX] Pruned dead code related to `responseContainsNullIP` natively across the pipeline, 
            which was causing undeclared reference errors.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.488.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "25-Sep-2026 14:31 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "547"
)

