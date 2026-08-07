/*
File:    version.go
Version: 1.450.0
Last Updated: 07-Aug-2026 18:05 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.450.0 - [FIX] Shipped the browser half of the 1.449.0 "Last Seen" column,
            which that release documented as delivered but which was never
            written. script.js remained at 1.29.0 the whole time, so the
            changelog entry below describing "script.js 1.30.0" and a "30s
            browser ticker" was, until now, a description of code that did not
            exist. The 1.449.0 text is left intact rather than corrected — the
            drift itself is the record worth keeping.

            The user-visible consequence was severe and easy to miss in review,
            because the first paint was correct:
              • refreshClientsUI() emitted FOUR <td> per row against
                buildClientsHTML()'s five-column header. On the first /api/clients
                poll — 60 seconds after load, or immediately on a manual refresh
                or any block/unblock — the Last Seen column disappeared and the
                Action button slid under the "Last Seen" heading. The feature
                worked exactly once per page load.
              • The empty-state placeholder still used colspan="4" where the Go
                builder had moved to colspan="5".
              • No age ticker existed, so a rendered label sat frozen until the
                next full navigation.
              • style.css (1.21.0, untouched) had no rule for the emitted
                `.client-lastseen` span.
            Fixed in script.js 1.30.0 (fmtLastSeenAgo/lastSeenCell/tickLastSeen,
            thresholds mirroring stats_lastseen.go so the label never jumps when
            JS takes over) and style.css 1.22.0 (dimmed, nowrap, tabular figures
            — the last of those stops the column twitching as the in-place
            rewrite changes digit widths every 30s).

          - [SECURITY/FIX] Restored a quorum floor to `mode: strict` (S-A,
            upstream_race.go 2.51.0). 1.446.0's abstention fix was correct in
            principle — a peer that produced no DNS payload has abstained, not
            disagreed — but it left `len(evalResults) == 0` as the ONLY
            remaining gate, and that gate is satisfied by exactly one peer. A
            five-server secure group whose other four upstreams were blackholed,
            slow, restarting or simply outraced would therefore serve a single
            uncorroborated answer while still reporting itself as strict.
            Nothing was compared; nothing said so.
            exchangeSecure now requires minStrictConsensus (2) upstreams to have
            returned MATCHING payloads whenever the fan-out held more than one
            server, and fails closed below that. Deliberately no new config
            knob: `mode: strict` is already the opt-in, and an operator who
            wants an answer on the strength of one reachable upstream is asking
            for `mode: loose`. A tunable floor would mostly be a supported way
            to configure strict mode back into this hole.
            Loose mode, poison detection and the abstention semantics are all
            untouched — a DISAGREEING peer still short-circuits to a block inside
            evaluateResult() long before the new guard, so it only ever fires on
            insufficient evidence, never on conflicting evidence.

          - [SECURITY/FIX] AllowClient now fails closed on an unidentifiable
            source address (S-B, ratelimit.go 1.16.0). It returned "allowed" for
            any addr whose netip.Addr was invalid — the same fail-open shape
            1.444.0 spent a release closing one layer up, and which
            process_security.go 1.15.0 then went on to describe, incorrectly, as
            a defence-in-depth guard. A token bucket is keyed on an identity;
            with no parseable address there is no key, no bucket and therefore
            no bound. Unreachable in the intact pipeline (step 0.0 sheds these
            first whenever an admission control is enabled), which is precisely
            why it needed to hold the right line for the day something starts
            reaching it.

          - [SECURITY/FIX] Guarded three unchecked 16-bit DNS length prefixes
            (S-C, server.go 1.39.0, upstream_net.go 1.31.0, upstream_ddr.go
            2.51.0). All three framed a payload with a bare
            `uint16(len(packed))`, so a message over 65.535 bytes announced its
            length modulo 65.536 and then wrote the full body behind it.
            The failure is not a dropped answer but a DESYNCHRONISED STREAM: the
            peer consumes the announced octet count and parses the remainder as
            the start of the next framed message, so every later exchange on
            that stream is read from the wrong offset. On a shared QUIC
            connection that is indistinguishable from an on-path attacker
            splicing responses — and a hostile upstream can deliberately
            manufacture the oversized answer we would relay.
            Remedies differ by direction, on purpose. Inbound (server.go): the
            oversized reply is re-emitted as an empty TC=1 answer, the signal
            DNS already defines for "retry me on a transport that can carry
            this"; a bare error would have left the client with no response and
            no explanation. Outbound (upstream_net.go): the dial is refused as
            an ordinary upstream failure, so the racing engine falls through to
            the next server and the client is still served. The DDR probe site
            is defensive rather than reactive — a locally built SVCB question
            cannot realistically approach 64 KB — but is fixed anyway, because
            leaving one of three identical bugs in place is how it becomes the
            one nobody remembers.
  1.449.0 - [FEAT] "Last Seen" column added to the Web UI Known Clients &
            Blocking table. New file stats_lastseen.go (1.0.0) implements a
            sharded, bounded, per-client last-seen tracker; the pipeline stamps
            it once per admitted query (process_security.go 1.16.0); it is
            persisted through the existing webui_stats.json lifecycle
            (stats.go 3.1.0) and pruned on the hourly tick
            (stats_hourly.go 1.7.0); /api/clients exposes it as `last_seen`
            (webui_api.go 1.13.0) and it is rendered server-side plus
            re-rendered on a 30s browser ticker (webui_components.go 1.33.0,
            script.js 1.30.0).

            Design decisions worth recording:
              • NOT derived from the existing top-talkers tracker. topTracker
                bins into HOURLY buckets and stores only counters, so the finest
                "last seen" it could reconstruct is "some time during hour X" —
                an hour of granularity for a field whose entire job is to answer
                "is this device on the network right now".
              • NOT derived from arpSnap either. The kernel neighbour table goes
                stale within minutes on a quiet host, expires entries wholesale,
                and knows nothing at all about DoH/DoT/DoQ clients reaching the
                resolver from off-link. It answers "is there an L2 adjacency",
                not "did this client resolve anything".
              • Bounded at 8192 identities with oldest-first eviction. On a
                publicly reachable resolver the key space is attacker-controlled
                — every spoofed source would otherwise mint a permanent map
                entry — so the ceiling turns an unbounded growth vector into a
                fixed ~1 MB cost, and evicts the quietest addresses first, which
                is the ordering a last-seen view wants regardless.
              • The stamp is taken AFTER the ACL and rate-limit gates (a source
                we refuse to serve must not be able to write into the tracker)
                but BEFORE the WebUI/policy/DGA/exfiltration blocks (a device
                that IS blocked must still show a truthful last-seen instant,
                or it silently ages out of the very table an operator is
                watching it in).
              • Retention is 30 days, deliberately NOT retentionHours(). Tying
                the client table to the graph retention would evict a device
                that last spoke 25 hours ago on the default 24h window —
                precisely the record the column exists to show.
              • Timestamps cross the API as raw epochs, formatted in the
                browser, so ages tick between the 60s polls and absolute
                tooltips land in the viewer's timezone rather than the server's.
  1.448.0 - [REFACTOR] Split process.go (1.031 lines) into focused stages:
            process_query.go (the queryCtx state carrier), process_cachehit.go
            (cache key derivation and the cache-hit path), process_upstream.go
            (SingleFlight coalescing and the upstream exchange) and
            process_status.go (shared log-status annotation). process.go drops
            to 488 lines of pure orchestration.
            The new file is named process_upstream.go, NOT process_exchange.go:
            that name belonged to the dead 406-line duplicate removed in
            1.443.0, and reusing it would suggest the duplicate returned.
          - [FIX] Two latent defects surfaced during the extraction, both caused
            by the cache-hit and upstream paths carrying separate copies of the
            same log annotation (process_status.go 1.0.0):
              1. A parentalReason of "UNTRIGGER" rendered as
                 "(PARENTAL UNTRIGGER: ...)" when the answer came from cache and
                 "(UNTRIGGERED BYPASS: ...)" when it came from upstream —
                 identical policy state, two different strings, depending purely
                 on whether the record happened to be cached. Unified on the
                 upstream wording.
              2. The ACTIVATING_UNTRIGGER and UNTRIGGER_SOURCE verdicts were
                 handled ONLY on the upstream path. CheckParental runs BEFORE
                 the cache lookup, so both reach a query that then hits cache —
                 in which case the window-expiry timer was never armed and the
                 client never received the "UNTRIGGER WINDOW ENDED" notice at
                 all. Both verdicts are now handled identically on both paths.
  1.447.0 - [PERF/FIX] Removed the per-cache-hit repack caused by
            `answer_sort: round-robin` (P-02). Rotation never converges, so
            applyAnswerSort reported "changed" on every hit and CacheUpdateOrder
            ran a msg copy, OPT strip, 64KB pool round-trip, PackBuffer, heap
            allocation, shard lock and atomic store on the hottest path in the
            daemon, per query. Rotation now comes from a per-entry counter
            applied at unpack time and the packed bytes are never rewritten
            (cache.go 2.51.0, cache_rw.go 1.3.0, process.go 3.89.0). ip-sort was
            never affected — being deterministic it converges after one
            write-back.
          - [FIX] IncrUpstream is no longer counted for coalesced queries (N-06).
            It ran before sfGroup.Do, so every SingleFlight participant
            incremented the per-route upstream counter although only one dialled,
            inflating the figure by exactly the coalescing factor — worst under
            the heavy load where it is most closely watched.
          - [SECURITY/FIX] Hardened the DoH POST body reader against a CPU spin
            (N-01). A reader returning (0, nil) — legal per io.Reader, and
            produced in practice by HTTP/2/3 flow control between DATA frames —
            advanced no loop term, pinning a core until the connection died.
            Added a bounded zero-progress counter; a genuinely stalled body is
            now penalised as the slow-read attack it is (server.go 1.38.0).
          - [PERF] Removed the O(N*M) nested MAC scan from getKnownClients
            (P-03) — the same complexity class 1.441.0 fixed elsewhere, still
            present in the identity-reconciliation step and paid on every
            dashboard poll. Now a single MAC index, O(N+M) (webui_api.go 1.12.0).
          - [WONTFIX] N-02 (recordRecentBlock re-parsing its ipStr argument) is
            deliberately not addressed. netip.ParseAddr does not heap-allocate
            for v4 or for v6 without a zone — netip.Addr is a value type — so the
            "massive string-allocation overhead" framing in process_leak.go 1.3.0
            was overstated and the real cost is a few tens of nanoseconds, on
            blocked queries only, only when leak prevention is enabled. Threading
            the parsed address through would change RecordBlockEvent's signature
            across 24 call sites in 6 files. Deferred to a refactor that touches
            those files for other reasons.
  1.446.0 - [SECURITY/FIX] Completed the strict-consensus repair (S-04). 2.49.0
            forgave only context.Canceled and context.DeadlineExceeded, leaving
            ECONNREFUSED, EOF, EHOSTUNREACH, TLS handshake failures, DoH 5xx and
            QUIC resets all still able to synthesise a block for the entire
            query on the strength of one flaky peer. The predicate is now
            "did this peer produce a DNS payload at all" — an abstention is not
            a disagreement. Poison detection and the fail-closed
            `len(evalResults) == 0` guard are untouched
            (upstream_race.go 2.50.0).
          - [PERF] Repaired the equalRRs fallback (P-01), which 2.48.0 changed
            from 2 allocations to 4 plus two deep RR clones while claiming an
            allocation win — in a function that runs O(n^2) under
            `preference: consolidate`. Restored a 2-allocation fast path with
            the TTL-insensitive comparison confined to the mismatch path.
          - [PERF/FIX] storeItem no longer evicts a blindly random cache entry
            (N-05). It samples 8 and evicts the earliest staleNano. Matters most
            under `serve_stale_infinite: true`, where runSweeper disables itself
            by design and eviction is consequently the cache's ONLY reclamation
            path — blind eviction there discards hot live records while
            long-dead ones persist (cache.go 2.50.0).
          - [SECURITY/FIX] generateBlockMsg embedded live elements of
            globalBlockIPv4 / globalBlockIPv6 into synthesised responses (N-08).
            net.IP is a slice, so every block answer aliased operator
            configuration state that is then handed to the response filters,
            transforms and the cache packer. Now copied (policy.go 1.9.0).
          - [ROBUSTNESS] writePolicyAction guarded its r.Question[0] access
            (N-04); generateBlockMsg already did, and the inconsistency was the
            bug. Corrected a materially misleading prefetch-gate comment in
            backgroundRevalidate (N-07, process_cache.go 1.23.0).
  1.445.0 - [SECURITY/FIX] Bounded DoQ stream fan-out (S-02). handleDoQConnection
            spawned an unbounded goroutine per accepted QUIC stream, so the only
            ceiling was MaxIncomingStreams (1000) x max_tcp_connections (250) —
            a theoretical 250.000 concurrent handlers, each allocating its stack,
            a dns.Msg and the payload buffer BEFORE AcquireQuery could reject
            anything, leaving the adaptive throttler structurally unable to
            defend the transport. Added a per-connection cap (64) and a
            process-wide semaphore sized at 4x max_tcp_connections, both
            non-blocking so excess streams are reset rather than queued behind
            head-of-line blocking (server.go 1.37.0). QUIC ceilings retuned to
            match: DoQ 1000 -> 64, DoH3 1000 -> 256 (server_init.go 1.19.0).
          - [SECURITY/FIX] Removed log.Fatalf from every listener serve loop
            (S-03). Eight call sites treated any post-bind serve return as fatal,
            so one transient failure on a single DoH socket terminated the whole
            process — UDP, TCP, DoT and DoQ included. Listeners now run under
            superviseListener(), which rebinds with exponential backoff (1s to a
            30s ceiling, 10 attempts) and then retires that one listener with an
            unconditional CRITICAL log while the rest keep serving. First-attempt
            bind failures stay fatal: a busy port or missing capability is an
            operator error and fail-fast at boot is correct there. The DoQ accept
            loop additionally escalates after 20 consecutive accept errors rather
            than spinning against a dead descriptor forever, and its shutdown
            watcher is now scoped per attempt so restarts cannot leak goroutines.
  1.444.0 - [SECURITY/FIX] Closed a fail-open admission hole (S-01). Both the
            DNS ACL gate and the token-bucket rate limiter were guarded by
            `&& clientAddr.IsValid()`, so any query whose source address could
            not be parsed skipped BOTH controls and proceeded into the pipeline
            unpoliced. Reachable through every stream transport, because
            handleTCP/handleDoT fell back to an empty string on a failed
            *net.TCPAddr assertion and handleDoH fell back to the raw,
            port-bearing r.RemoteAddr. Admission now fails closed whenever an
            admission control is actually configured (process_security.go
            1.15.0), and the source-address extraction itself was rewritten to
            be type-agnostic rather than to silently yield nothing
            (server.go 1.36.0, server_udp_linux.go 1.5.0,
            server_udp_stub.go 1.3.0). Deployments with neither an ACL nor rate
            limiting configured are behaviourally unchanged.
          - [SECURITY/FIX] Closed an unbounded-growth path in the Search Domain
            Leak Prevention tracker (L-01). Its only reclaimer was launched from
            InitCache, which returns early when `cache.enabled: false` — so
            running with the cache off left rbShards accumulating one record per
            distinct source address for the process lifetime. The launch moved
            to InitRecentBlocks() (process_leak.go 1.4.0), called from main.go
            1.242.0 once the feature flag is known; cache.go 2.49.0 no longer
            owns it. A hard per-shard ceiling with pseudo-random eviction was
            also added, because a 10-minute prune tick is not a bound against a
            spoofed-source flood allocating between ticks.
  1.443.0 - [SECURITY/FIX] Reverted the 1.442.0 SingleFlight "ownership"
            optimisation in process.go — it was a data race. `shared` is
            returned to every participant of a coalesced group INCLUDING the
            dialing goroutine, so handing the dialer the raw shared payload let
            it mutate that object (answer sorting, response transforms, UDP
            defenses, TTL capping, transaction-ID write) while the waiting
            goroutines were concurrently copying it. Predicate restored to a
            plain `if shared`. Costs nothing: the uncoalesced path (`shared ==
            false`) was already zero-copy before 1.442.0.
          - [DEAD-CODE/FIX] Deleted process_exchange.go (406 lines, zero
            callers). It held a stale duplicate of the upstream-exchange stage
            and was the ONLY enforcement site for `server.qname_min_labels` /
            `server.qname_max_labels`, which were therefore parsed and
            validated at boot but never applied to a single query. The guard,
            the per-group `ignore_qname_labels` opt-out and the parental
            UNTRIGGER window-expiry timer are now on the live path in
            process.go; `untriggerLogTimers` moved to globals.go.
  1.442.0 - [PERF/FIX] Resolved a severe SingleFlight heap allocation 
            regression within the core DNS pipeline natively. The primary 
            dialing goroutine now properly takes ownership of the network 
            payload without redundant copying (`if shared && !didUpstream`).
            [SUPERSEDED BY 1.443.0 — introduced a data race; see above.]
  1.441.0 - [PERF] Optimized webuiClientBlocks eviction logic inside 
            handleApiClientsBulkBlock. Extracted O(N) map range operations 
            outside the client iteration loop, eliminating an O(N^2) CPU 
            complexity spike during massive bulk assignment events natively.
  1.440.0 - [FEAT] Added Bulk Client Block functionality for Unidentified and 
            Privacy MAC clients natively. The web UI dashboard now provides 
            a dedicated control to atomically block or unblock all clients 
            using randomized MAC addresses or lacking hostnames. Evaluates 
            and clearly displays block state dynamically using `.blocked-row`.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.450.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "07-Aug-2026 18:05 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "509"
)



