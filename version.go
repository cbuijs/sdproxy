/*
File:    version.go
Version: 1.439.0
Last Updated: 24-Jul-2026 18:20 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.439.0 - [SECURITY/FIX + PERF] Two targeted hardening/optimization fixes.
              * upstream_race.go 2.49.0 - [SECURITY/FIX] Closed the long-standing
                KNOWN-OPEN strict-consensus item (previously carried in this trail).
                exchangeSecure strict mode treated a plain peer timeout
                (context.DeadlineExceeded) as a consensus *validation failure* and
                synthesized a block, letting a single dead/slow upstream suppress
                valid, matching answers from healthy peers and pinning strict-mode
                latency to the slowest peer up to the 2500ms safety-net ceiling.
                DeadlineExceeded is now forgiven and skipped exactly like the
                already-handled context.Canceled path. Poison detection is unchanged
                (mismatched RCODE/answer data still fails closed) and the
                `len(evalResults) == 0` guard still blocks when no peer answered, so
                the strategy continues to fail closed on genuine no-consensus.
              * process_security.go 1.14.0 - [PERF] Removed a per-query heap
                allocation on the pre-cache DGA hot path. The `"."+eTLD`
                concatenation inside strings.TrimSuffix allocated a throwaway string
                for every query while DGA inference was enabled; domainCore is now
                stripped with zero-allocation index math (eTLD is always a true
                suffix of the qname), restoring the intended zero-alloc contract.
            The KNOWN-OPEN note that appeared in the 1.437.0/1.438.0 trails is
            resolved by this release and intentionally not repeated below.
  1.438.0 - [DEAD-CODE/BLOAT] Removed two redundant "atomic import guard" blank
            declarations surfaced by a package-wide regression/dead-code/bloat
            re-sweep. Two files touched:
              * version.go 1.438.0 - Dropped `import "sync/atomic"` together with
                its `var _ atomic.Int64` guard. The package was imported *solely*
                to satisfy that blank var, whose own comment claimed to keep the
                import alive - a self-referential loop that compiled to nothing.
                version.go references no atomics at all, so both lines were pure
                bloat. Removal is strictly behaviour-preserving.
              * throttle.go 2.5.0 - Dropped the trailing `var _ atomic.Int64`
                guard. Unlike version.go, throttle.go genuinely uses sync/atomic
                (the throttler struct fields are atomic.Int32 / atomic.Int64), so
                the import itself stays live; only the redundant blank guard was
                excised. Header date field also normalized from `Updated:` to the
                mandated `Last Updated:` form.
            Dead-code re-sweep otherwise came back clean: the only zero-reference
            symbols in the package are interface-satisfying methods
            (yaml.Unmarshaler's UnmarshalYAML, and dns.ResponseWriter's
            TsigStatus / TsigTimersOnly / Hijack) which are dispatched via
            reflection / interface and MUST NOT be pruned by non-type-aware
            scanners. KNOWN-OPEN (deliberately unchanged, design decision still
            pending): exchangeSecure in strict mode classifies a plain upstream
            timeout (context.DeadlineExceeded) as a consensus validation failure
            and synthesizes a block, so one dead peer can suppress otherwise-valid
            answers and strict-mode latency tracks the slowest peer up to the
            2500ms ceiling.
  1.437.0 - [AUDIT/BUGFIX/PERF] Regression, dead-code and optimization sweep across
            the package. Four files touched:
              * upstream_ddr.go 2.50.0 - [BUGFIX/RESOURCE] Removed a defer-inside-loop
                in the DoH branch of fetchDDRParams(). `defer tr.CloseIdleConnections()`
                sat inside the `range targets` probe loop, so each probed target stacked
                another *http.Transport teardown that only ran at function unwind rather
                than per iteration. Teardown is now explicit on both case exit paths,
                mirroring the existing tr.Close() in the sibling "doh3" branch.
              * exfiltration.go 1.15.0 - [DEAD-CODE] Excised a provably unreachable
                clamp from the Micro-Burst Projection cold-start path
                (`threshold > threshold*5.0` can never hold). Bit-for-bit behaviour
                preserving.
              * upstream_race.go 2.48.0 - [PERF] equalRRs no longer allocates two
                throwaway lowercase strings per comparison; owner-name and CNAME-target
                checks migrated to allocation-free strings.EqualFold. equalRRs runs
                O(n^2) over the answer set under the "consolidate" preference, so this
                removes real GC pressure on large merged RRsets.
              * parental_consolidation.go 1.0.0 - [HOUSEKEEPING] Added the standard
                file header; it was the only Go source in the package with no Version,
                Last Updated or Changes trail.
            Header date fields on all touched files normalized from `Updated:` to the
            mandated `Last Updated:` form. Package-wide dead-code re-sweep came back
            clean apart from the exfiltration clamp above - note that generic helpers
            such as loadGob[T] are live and must not be flagged by non-generic-aware
            scanners. KNOWN-OPEN (deliberately not changed here, design decision
            pending): exchangeSecure in strict mode classifies a plain upstream
            timeout (context.DeadlineExceeded) as a consensus validation failure and
            synthesizes a block, so one dead peer can suppress otherwise-valid answers
            and strict-mode latency tracks the slowest peer up to the 2500ms ceiling.
  1.436.0 - [DEAD-CODE/CLEANUP] Retired the orphaned readConfigListURL helper in
            init_core.go (no remaining callers; remote-list loading is owned by
            init_policy.go and parental_loader.go). Dropped the now-unused fmt /
            io / net/http imports from that file. No behavioural change — pure
            dead-code removal. Full dead-code / unused-symbol sweep otherwise
            came back clean across the package.
  1.435.0 - [SECURITY/FIX] Hardened synthesized DNS block responses natively. 
            Injected the `Authoritative = true` (AA) bit into all generated 
            `generateBlockMsg` payloads to prevent strict OS stub resolvers 
            from discarding the block as an unverified cache-injection and 
            bypassing the firewall via secondary resolvers.
  1.434.0 - [PERF] Eliminated massive string-allocation overheads on the query hot-path natively. 
            Rate Limiter, Exfiltration tracking, and Leak Prevention modules now execute completely 
            using zero-allocation `netip.Addr` structures as map hashes.
  1.433.0 - [TIER 2] Source consolidation batch 2. identity_asn.go, init_policy.go,
            cache_persistence.go, parental_categories.go, parental_loader.go,
            parental_io.go, rules.go, stats.go, webui_logs.go and webui_state.go
            migrated onto helpers_io.go. syncDirForFile removed from init_core.go.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.439.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "24-Jul-2026 18:20 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "498"
)

