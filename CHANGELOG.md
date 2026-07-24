# sdproxy — Changelog

Consolidated history. Per-file headers keep only their last 3 entries; everything
older lives here. Newest first within each subsystem.

---

## Unreleased — v1.432.0 (22-Jul-2026)

### Source consolidation (Tier 1/2/3)
- **[TIER 1]** Removed filler adverbs and code-restating comments across the tree.
  No documentation, examples, RFC references or security rationale were dropped.
- **[TIER 1]** Per-file `Changes:` trails trimmed to the last 3 entries; the full
  history now lives in this file.
- **[TIER 2]** New `helpers_io.go` — consolidates `syncDirForFile`, the
  `.tmp` → fsync → rename → dir-sync atomic write pattern (was duplicated ~10×),
  and buffered gob load/save (was duplicated ~6×).
- **[TIER 2]** `cache_rw.go` — extracted `stripOPTRecords()`; the RFC 6891
  OPT-stripping block was previously copy-pasted in `CacheSet`, `CacheSetSynth`
  and `CacheUpdateOrder`.
- **[TIER 2]** `ddr.go` — the three near-identical SVCB builders (DoH/DoT/DoQ)
  collapsed into one table-driven loop.
- **[TIER 3]** `upstream_exchange.go` — the four duplicated ECH-fallback ladders
  (DoT, DoH, DoH3, DoQ) unified behind `runWithECHFallback()`. Backoff schedule
  extracted to `echBackoff()` and shared with the DoH3 downgrade path.

### Behaviour changes introduced by the above (review these)
- `atomicWrite` no longer calls `os.Remove(path)` before `os.Rename`. POSIX
  `rename(2)` replaces atomically; the pre-remove opened a crash window in which
  the old file was gone and the new one not yet in place. The pre-remove existed
  as a Windows/locked-FS guard — sdproxy targets Linux/BSD.
- TCP/DoT ECH fallback now retries **all** dial addresses with ECH before
  downgrading to plaintext SNI. Previously a single dead IP could force the whole
  upstream onto plaintext for the remaining addresses.

---

## Cache

- 2.48.0 `cache.go` — `BypassGlobal` folded into `DNSCacheKey` and shard hashing to
  stop cross-cache contamination between policy-bound and bypassed clients.
- 2.47.0 `cache.go` — background sweeper listens on `shutdownCh`; zombie goroutine fixed.
- 2.46.0 `cache.go` — `toDelete` scoped inside the shard loop so key strings detach
  immediately and the GC can reclaim them mid-tick.
- 2.45.0 `cache.go` — corrected `hasPrefetch` docs: it gates background revalidation,
  not the Web UI hit counters.
- 2.44.0 `cache.go` — split into cache.go / cache_rw.go / cache_persistence.go / cache_ui.go.
- 1.6.0 `cache_persistence.go` — `syncDirForFile` added so atomic renames survive power loss.
- 1.5.0 `cache_persistence.go` — clearer `dec.Decode` diagnostics for stale/corrupt `dns_cache.bin`.
- 1.4.0 `cache_persistence.go` — `runtime.Gosched()` between shard extractions so the
  disk flush cannot starve UDP workers at 50k+ entries.
- 1.3.0 `cache_persistence.go` — `saveCacheMu` added; fixed race between the polling
  tick and synchronous shutdown flush.
- 1.2.0 `cache_persistence.go` — flush/sync/close errors now abort the rename instead of
  letting a 0-byte file overwrite valid data.
- 1.1.0 `cache_rw.go` — bailiwick validation closure hoisted to `isValidBailiwickName`
  to kill per-write heap allocations.

## DNS pipeline

- 3.86.0 `process.go` — client-route resolution moved earlier so `bypass_global` can skip
  global RRS and policies.
- 3.85.0 `process.go` — no new IP string allocated unless unmapping or zone-cleansing
  actually changed the address.
- 3.84.0 `process.go` — `ResolveStateKeyAndGroup` hoisted; state key and group resolved once.
- 3.83.0 `process.go` — SingleFlight primary takes ownership of the unpacked payload
  instead of copying it.
- 1.19.0 `process_defense.go` — `extRcode` restored to `uint16` for `SetExtendedRcode()`.
- 2.22.0 `process_filters.go` — `bypassGlobal` honoured in target-name checks.
- 1.13.0 `process_helpers.go` — IPv6 `.ip6.arpa` decoded via O(1) index math into `[16]byte`;
  no more `strings.Split` on reverse floods.
- 1.12.0 `process_helpers.go` — `Qclass` folded into the SingleFlight key.

## Upstreams

- 2.46.0 `upstream.go` — `MaxSecureUpstreams` added to `UpstreamGroup`.
- 2.45.0 `upstream.go` — `echDomain` support for `?echdomain=`.
- 2.44.0 `upstream.go` — zero-allocation slice filtering in `SweepUpstreamConns`.
- 2.43.0 `upstream.go` — background idle-connection sweeper added; FD leak fixed.
- 2.42.0 `upstream.go` — 15s hard ceiling in `newUpstreamCtx` when `upstream_timeout_ms` is 0.
- 2.41.0 `upstream_exchange.go` — context-death guards across all transport fallback chains.
- 1.30.0 `upstream_net.go` — pooled-conn slice clears its tail pointer before truncation.
- 1.28.0 `upstream_net.go` — context-expiry guards on DoH/DoH3/DoQ retries.
- 2.49.0 `upstream_ddr.go` — `echDomain` probing split from the `_dns.resolver.arpa` probe.
- 2.46.0 `upstream_ddr.go` — L7 out-of-band ECH discovery via `/.well-known/origin-svcb`
  and legacy `/.well-known/ech`.
- 2.47.0 `upstream_race.go` — `secure` strategy fan-out capped by `MaxSecureUpstreams`.
- 2.45.0 `upstream_race.go` — consensus safety-net no longer overwritten by an unbounded
  parent deadline.

## DDR / TLS / ECH

- 1.7.0 `ddr.go` — `PreserveEDNS0` and `RcodeStr` applied to deduplicate telemetry.
- 1.6.0 `ddr.go` — DDR intercepts bound to `logDDR` rather than `logQueries`.
- 1.12.0 `tls.go` — raw 32-byte X25519 ECH seeds no longer corrupted by `bytes.TrimSpace`.
- 1.10.0 `tls.go` — non-wildcard leaf-cert names exported to `tlsAuthorizedNames` for DDR.

## Identity / ASN

- 2.13.0 `identity.go` — poll loop bound to `shutdownCh`.
- 2.12.0 `identity.go` — file parsing loops unified behind one helper closure.
- 2.10.0 `identity.go` — deleted hosts/lease files now purge stale mappings.
- 1.38.0 `identity_asn.go` — `syncDirForFile` on ASN cache renames.
- 1.37.0 `identity_asn.go` — fixed `[]AsnRange` vs `[]AsnRangeGob` assertion that made the
  gob decoder discard every valid binary cache.
- 1.36.0 `identity_asn.go` — 3-hour local freshness TTL bypasses HTTP polling.
- 1.35.0 `identity_asn.go` — fixed `.raw.bin` vs `.bin` path typo that permanently missed the cache.

## Parental control

- 3.38.0 `parental.go` — `countryToGroup` wired into `ResolveStateKeyAndGroup`.
- 3.37.0 `parental.go` — parsed `targetAddr` forwarded to `categoryOf`; no second parse.
- 3.35.0 `parental.go` — `UNTRIGGER` expiry locked inside the debounce block so repeat hits
  can't roll the window forward forever.
- 2.12.0 `parental_categories.go` — `.bin` decode errors bound to `logParental` with clearer text.
- 2.11.0 `parental_categories.go` — category cache migrated from JSON to gob.
- 1.25.0 `parental_loader.go` — `syncDirForFile` on category cache renames.
- 1.24.0 `parental_loader.go` — 3-hour freshness TTL on remote list fetches.

## Security subsystems

- 1.13.0 `exfiltration.go` — sweeper bound to `shutdownCh`.
- 1.12.0 `exfiltration.go` — defaulted `MaxTrackedIPs` written back to `cfg`; fast-path
  penalty box was silently disabled when the key was omitted.
- 1.10.0 `exfiltration.go` — IPv4-in-IPv6 tracker bypass closed.
- 1.14.0 `ratelimit.go` — sweeper bound to `shutdownCh`.
- 1.13.0 `ratelimit.go` — same `MaxTrackedIPs` default write-back fix.
- 1.11.0 `dga.go` — O(1) pre-flight byte check before the safe-domain suffix walk.
- 1.10.0 `dga.go` — `math.Log2` replaced with a precomputed table in the entropy loop.
- 1.8.0 `dga.go` — whitelist evaluated against the full domain, not the stripped core.

## Web UI

- 1.9.0 `webui_api.go` — client sort no longer re-parses IPs per comparison.
- 1.8.0 `webui_api.go` — randomized/private MAC detection (`isRandomizedMAC`).
- 1.7.0 `webui_api.go` — `/api/clients` filters out public IPs via `bogonPrefixes`.
- 1.12.0 `webui.go` — `/api/clients` and `/api/clients/block` routes registered.
- 1.11.0 `webui.go` — `http.MaxBytesReader` (32KB) on `handleLogin` and `handleSet`.
- 1.22.0 `webui_html.go` — `subtle.ConstantTimeCompare` on the password check.

## Server / transport

- 1.356.0 `server.go` — deep-copy isolation of pooled buffers before `Unpack` on DoH/DoQ.
- 1.35.0 `server.go` — 5s write deadline on DoQ streams.
- 1.34.0 `server.go` — 5s read deadline on DoQ streams.
- 1.18.0 `server_init.go` — `/.well-known/origin-svcb` registered on DoH/DoH3 listeners.
- 1.16.0 `server_init.go` — DoQ connection counter moved inside the listener loop.
- 1.4.0 `server_udp_linux.go` — SO_RCVBUF/SO_SNDBUF sized as a pool-wide budget divided by
  worker count, not per-socket.

