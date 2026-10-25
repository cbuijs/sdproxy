# Upstream Selection & Routing Strategies in sdproxy

`sdproxy` is engineered to provide edge-router performance with enterprise-grade reliability. A critical component of this is how it selects, monitors, and routes DNS requests to external resolvers (Upstreams).

The upstream execution engine operates in two phases: **Initialization (Bootstrapping)** at startup, and **Strategy Execution** at query time.

## 1. Multiple IPs: Group-Level vs. Member-Level

It is crucial to understand how `sdproxy` handles multiple IPs, as it dictates how you should write your `config.yaml`.

### Member-Level Fallback (Single Entry)

If you specify multiple IPs on a single line using the `#ip1,ip2` syntax, `sdproxy` treats that entire entry as **one upstream member**.
When the routing algorithm selects this member, the underlying network dialer (TCP/UDP/QUIC) will attempt to connect to the first IP. If the socket connection fails, it instantly falls back to the second IP.

```yaml
upstreams:
  secure:
    strategy: "fastest" # Won't balance between .9 and .112!
    servers:
      - "doh://dns.quad9.net/dns-query#9.9.9.9,149.112.112.112"
```

### Group-Level Load Balancing (Multiple Entries)

If you want `sdproxy`'s advanced algorithms (like `round-robin` or `fastest`) to evaluate and load-balance *between* those IPs, you must split them into distinct list entries. This forces `sdproxy` to treat them as independent servers within the group.

```yaml
upstreams:
  secure:
    strategy: "fastest" # Will track RTT and balance between .9 and .112!
    servers:
      - "doh://dns.quad9.net/dns-query#9.9.9.9"
      - "doh://dns.quad9.net/dns-query#149.112.112.112"
```

*Note:* `sdproxy` features a built-in safety constraint. If an upstream group yields 1 or fewer unique endpoint IPs across all its members, it will ignore `random`, `fastest`, `secure`, and `round-robin` and automatically fall back to the `stagger` strategy, as load-balancing algorithms are useless without redundancy.

## 2. Configuration Options

You can define a global default strategy, and optionally override it per-group.

### Global Configuration

Located under the `server` block, this dictates the fallback behavior for all upstream groups that do not explicitly define a strategy. If omitted, the system defaults to `stagger`.

```yaml
server:
  upstream_selection: "fastest"
  upstream_stagger_ms: 0
  upstream_timeout_ms: 0
  max_secure_upstreams: 5
```

### Per-Group Configuration

Located under the `upstreams` block, you can use an expanded object structure to assign unique strategies, preferences, ECS rules, and label constraints per group.

```yaml
upstreams:
  kids:
    strategy: "round-robin"
    servers:
      - "tls://1.1.1.3:853"
      - "tls://1.0.0.3:853"
```

## 3. The Five Routing Strategies

When a cache miss occurs, `sdproxy` uses the assigned strategy to execute the query against the group's members. All non-`secure` strategies use the unified racing engine: when `server.upstream_stagger_ms > 0`, probes are staggered in parallel; when `0`, members are tried sequentially in the order produced by the strategy.

### `stagger` (Parallel Racing / Sequential Failover)

**Best for:** Lowest latency and deterministic primary/backup failover.

1. Fires the query at the **first** upstream in the list.
2. When `upstream_stagger_ms > 0`, waits for that duration (e.g., `15ms`). If no response arrives within that window, fires a parallel query to the **next** upstream.
3. The first upstream to return a valid response wins, and losing in-flight connections are immediately canceled.
4. *Health Optimization:* If a preceding upstream has accumulated 3 or more consecutive failures (`unhealthy`), `sdproxy` skips the stagger delay and fires the next upstream immediately.

### `round-robin` (Sequential Cyclic Load Balancing)

**Best for:** Deterministic, even distribution across independent endpoints.

1. Increments a lock-free atomic counter and rotates the server list by `Counter % Total_Servers`.
2. Executes the rotated list through the unified sequential/staggered racing engine.

### `random` (Stochastic Distribution)

**Best for:** Entropy-driven load distribution without rigid patterns.

1. Picks a random starting index via `math/rand/v2` and rotates the server list from that offset.
2. Executes the rotated list through the unified sequential/staggered racing engine.

### `fastest` (Epsilon-Greedy Algorithmic Routing)

**Best for:** Dynamically adapting to network congestion and ISP routing changes.

1. Tracks the Response Time (RTT) of every upstream transaction in nanoseconds using an Alpha-Smooth Exponential Moving Average (EMA: 70% historical, 30% latest sample). Unprobed servers start with a neutral `50ms` ranking baseline so they are tested early without displacing proven sub-50ms servers.
2. Sorts members primarily by **health tier** (healthy servers with `< 3` consecutive failures always precede unhealthy ones) and secondarily by lowest EMA latency.
3. *Epsilon-Greedy Exploration:* On 5% of queries, `sdproxy` picks a random non-leading server (`1 .. N-1`) and promotes it to the front of the queue. This continuous exploration discovers when a previously slow or penalized pathway has recovered. If an upstream fails, its EMA is doubled (up to a 60s cap).

## 4. Secure Strategy Consensus & Consolidation

The `"secure"` strategy provides multi-resolver verification and consensus validation.

### Fan-Out Selection (`max_secure_upstreams`)

To prevent outbound query storms on large upstream lists, `sdproxy` caps simultaneous dials at `server.max_secure_upstreams` (default `5`). Participants are selected **healthy-first** while preserving configured order within each health tier.

### Consensus Modes (`mode`)

1. `sdproxy` fires the query to the selected upstreams in the group simultaneously (bounded by a 2500ms consensus timeout or the parent exchange deadline).
2. Responses are validated as they arrive:
   * **`mode: loose`** (Default): Ignores connection errors, timeouts, and any RCODE other than `NOERROR` or `NXDOMAIN`. Short-circuits immediately once a strict majority of expected healthy servers agree.
   * **`mode: strict`**: Forgives peers that abstain due to transport errors/timeouts, but requires a minimum quorum of **2 agreeing responses** (`minStrictConsensus = 2`) whenever more than one server is queried. Deep-inspects answer fingerprints (IP sets, CNAMEs, MX/SRV/TXT/HTTPS records) to guarantee every responding peer returned identical end-answers.
3. In both modes, `NOERROR` responses with answers cannot be mixed with empty `NOERROR` (NODATA) responses, and any `NULL-IP` (`0.0.0.0` or `::`) immediately voids consensus and triggers a synthesized block/drop.

### Payload Preference (`preference`)

* **`fastest`** (Default): Returns the first validated response that arrived.
* **`ordered`**: Returns the response belonging to the first configured server in the group (if it participated in the valid consensus).
* **`consolidate`**: Merges and deduplicates all `Answer` records across all valid responses into a single combined reply.

#### The CNAME Consolidation Paradox & Automatic Flattening
Under **RFC 2181**, having multiple conflicting CNAME records for a single owner name is prohibited. If multiple upstream resolvers return different regional CNAME chains, presenting them un-flattened violates protocol specifications.

To preserve compliance:
* Configuring `strategy: "secure"` with `preference: "consolidate"` **automatically forces `server.flatten_cname: true`** at startup.
* Before the merged payload is written to the client, `sdproxy` collapses CNAME chains into terminal `A`/`AAAA` records using the minimum TTL across the chain.

## 5. Initialization & Bootstrapping (Phase 1)

Before any routing strategy can execute, `sdproxy` resolves the physical IP addresses of upstream hostnames at boot to prevent DNS resolution deadlocks.

### Scenario A: Per-URL Bootstrap

If IPs are appended to the URL with `#`, global bootstrap servers and the OS resolver are bypassed for that upstream:

```yaml
upstreams:
  default:
    - "doh://cloudflare-dns.com/dns-query#1.1.1.1,1.0.0.1"
```

* `sdproxy` validates each IP with `netip.ParseAddr` (filtering by `support_ip_version`) and dials `1.1.1.1:443` (falling back to `1.0.0.1:443`) while verifying the TLS certificate and SNI against `cloudflare-dns.com`.

### Scenario B: Global Bootstrap

If no `#ip` fragment is appended to a hostname-based upstream:

```yaml
upstreams:
  default:
    - "dot://dns.quad9.net:853"
```

* `sdproxy` queries `server.bootstrap_servers` (which may be plain IPs or encrypted URLs with `#ip` bootstrap addresses).
* If `use_upstream_ech` or `upgrade_doh3` is enabled, `sdproxy` also probes `HTTPS` and `_dns.resolver.arpa` `SVCB` records (and L7 `.well-known` endpoints) to extract IP hints, ALPN `h3` support, and ECHConfigLists.
* If the first bootstrap server returns an error, NXDOMAIN, or empty answer for an address family, `sdproxy` automatically falls through to the next configured bootstrap server.

## 6. Execution Scenario Example

**Configuration:**

```yaml
server:
  upstream_selection: "stagger"
  upstream_timeout_ms: 2000 # 2-second hard deadline per exchange

upstreams:
  secure:
    strategy: "secure"
    preference: "ordered"
    mode: "strict"
    servers:
      - "dot://dns.quad9.net:853#9.9.9.9"
      - "doh3://security.cloudflare-dns.com/dns-query+get#1.1.1.2"
```

**Trace:**

1. **Boot:** `sdproxy` assigns `9.9.9.9:853` as the DoT dial target for Quad9 and `1.1.1.2:443` as the QUIC dial target for Cloudflare. The `secure` group detects 2 unique endpoints and activates the `secure` strategy.
2. **Query:** A client requests `github.com A`. A cache miss occurs.
3. **Execution:** The group fires parallel queries to Quad9 and Cloudflare.
4. **Validation:** Cloudflare responds in `14ms`, Quad9 responds in `22ms`. `mode: strict` verifies that at least 2 peers responded, neither returned a NULL-IP, both returned `NOERROR`, and both produced identical sorted `A` record fingerprints.
5. **Resolution:** Because `preference: "ordered"` is set, `sdproxy` selects Quad9's response (the first server in `servers:`), caches it, and writes it to the client.

