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
    strategy: "fastest" # Won't balance between .1 and .2!
    servers:
      - "doh://dns.quad9.net/dns-query#9.9.9.9,149.112.112.112"
```

### Group-Level Load Balancing (Multiple Entries)

If you want `sdproxy`'s advanced algorithms (like `round-robin` or `fastest`) to evaluate and load-balance *between* those IPs, you must split them into distinct list entries. This forces `sdproxy` to treat them as independent servers within the group.

```yaml
upstreams:
  secure:
    strategy: "fastest" # Will track RTT and balance between .1 and .2!
    servers:
      - "doh://dns.quad9.net/dns-query#9.9.9.9"
      - "doh://dns.quad9.net/dns-query#149.112.112.112"
```

*Note:* `sdproxy` features a built-in safety constraint. If an upstream group yields 1 or fewer unique IPs across all its members, it will ignore `random`, `fastest`, `secure`, and `round-robin` and automatically fall back to the `stagger` strategy, as load-balancing algorithms are useless without redundancy.

## 2. Configuration Options

You can define a global default strategy, and optionally override it per-group.

### Global Configuration

Located under the `server` block, this dictates the fallback behavior for all upstream groups that do not explicitly define a strategy. If omitted, the system defaults to `stagger`.

```yaml
server:
  upstream_selection: "fastest"
```

### Per-Group Configuration

Located under the `upstreams` block, you can use an expanded object structure to assign unique strategies per group.

```yaml
upstreams:
  kids:
    strategy: "round-robin"
    servers:
      - "tls://1.1.1.3:853"
      - "tls://1.0.0.3:853"
```

## 3. The Five Routing Strategies

When a cache miss occurs, `sdproxy` uses the assigned strategy to execute the query against the group's members.

### `stagger` (Parallel Racing)

**Best for:** Absolute lowest latency regardless of bandwidth efficiency.

1. The router fires the query at the **first** upstream in the list.

2. It waits for the duration of `server.upstream_stagger_ms` (e.g., `10ms`).

3. If no response arrives within that window, it fires a second parallel query to the **second** upstream.

4. The first upstream to return a valid response wins. The losing connections are instantly torn down.
   *Health Optimization:* If the first upstream suffers 3 consecutive failures, `sdproxy` marks it "unhealthy" and bypasses the stagger timer, firing queries simultaneously to avoid artificial latency penalties.

### `round-robin` (Sequential Cyclic Load Balancing)

**Best for:** Deterministic, perfectly even distribution across many independent endpoints.

1. `sdproxy` increments a lock-free atomic counter.

2. It calculates the index using modulo math (`Counter % Total_Servers`).

3. The query is routed to the selected server. If that server times out or fails, it falls through and sequentially attempts the remaining servers in the group.

### `random` (Stochastic Distribution)

**Best for:** Entropy-driven load distribution without rigid patterns.

1. Employs `math.rand` to stochastically pick an upstream index.

2. Routes the query to the chosen server, falling back sequentially to the others upon failure.

### `fastest` (Epsilon-Greedy Algorithmic Routing)

**Best for:** Dynamically adapting to network congestion and ISP routing changes.

1. `sdproxy` tracks the Response Time (RTT) of every upstream transaction natively in nanoseconds using an Alpha-Smooth Exponential Moving Average (EMA).

2. It evaluates the active RTT of all members and routes traffic to the endpoint currently yielding the lowest latency.

3. *Epsilon-Greedy Logic:* 5% of all queries are deliberately diverted to a random upstream member rather than the absolute fastest. This continuous exploration ensures that alternative upstreams are routinely tested to capture real-time network state changes, naturally "discovering" when a previously slow connection becomes fast again. If an upstream fails or times out, its perceived RTT is aggressively doubled to punish it in the ranking.

### `secure` (Strict Consensus Validation)

**Best for:** Environments demanding maximum integrity, anti-tampering, and upstream validation.

1. `sdproxy` fires the query at **all** upstreams in the group simultaneously.
2. It waits for every upstream to return a response (or fail).
3. *Consensus Validation:*
   * The `mode` setting strictly dictates the tolerance for failures and the depth of payload inspection:
     * `loose` (Default): Connection failures, timeouts, and any RCODEs other than `NOERROR` or `NXDOMAIN` are actively disregarded. Consensus is built flexibly from the pool of healthy, valid responses. It validates that the remaining healthy answers are uniformly empty or non-empty (NODATA checks).
     * `strict`: Demands 100% participation. All upstreams *must* successfully respond without timeouts or network errors. It then deep-inspects the answer payload to ensure that the end-answers (specifically the final IP addresses returned in a CNAME chain for A/AAAA queries) are mathematically identical across all upstreams. Safely ignores RR-set order variations or upstream-specific CNAME differences.
   * In both modes, all evaluated upstreams must return the exact same DNS Return Code (RCODE).
   * **No** evaluated response may contain a NULL-IP (`0.0.0.0` or `::`).
4. If all validations pass, the response is returned based on the group's `preference`:
   * `fastest` (Default): Returns the response that arrived first with the lowest latency.
   * `ordered`: Returns the response from the primary upstream (the first server listed in the group's `servers:` array), providing predictable logs and routing consistency while still enforcing validation against the others.
   * If any validation fails, the query is actively dropped/rejected to protect the client.

## 4. Initialization & Bootstrapping (Phase 1)

Before any routing strategy can execute, `sdproxy` must resolve the physical IP addresses of the upstream providers at boot. This prevents "chicken-and-egg" DNS deadlocks.

### Scenario A: Per-URL Bootstrap

If IPs are appended to the URL with `#`, local OS resolvers and global bootstrap servers are completely bypassed.

```yaml
upstreams:
  default:
    - "doh://cloudflare-dns.com/dns-query#1.1.1.1,1.0.0.1"
```

* `sdproxy` extracts `1.1.1.1` and `1.0.0.1`.

* It injects these into a custom HTTP `DialContext`. When the DoH query fires, the underlying TCP/QUIC dialer connects directly to `1.1.1.1:443`, while validating the TLS SNI against `cloudflare-dns.com`.

### Scenario B: Global Bootstrap

If no IPs are appended, `sdproxy` must resolve the hostname.

```yaml
upstreams:
  default:
    - "dot://dns.quad9.net:853"
```

* `sdproxy` looks at `server.bootstrap_servers` (defaults to `1.1.1.1` and `9.9.9.9`).

* It fires a synchronous, plain-UDP A/AAAA query to the bootstrap server at boot.

* The returned IPs are injected into the upstream's dialer pool, identical to Scenario A.

* If bootstrapping fails, it leaves the hostname intact, forcing the underlying Go `net.Dialer` to use the host router's OS resolver (e.g., `/etc/resolv.conf`) as a last resort at query time.

## 5. Execution Scenario Example

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

1. **Boot:** `sdproxy` assigns `9.9.9.9` as the TCP dial target for Quad9. It assigns `1.1.1.2` as the QUIC dial target for Cloudflare. The `secure` group detects 2 unique IPs and activates the `secure` routing module natively.

2. **Query:** A client requests `github.com`. A cache miss occurs.

3. **Execution:** The module instantly fires queries simultaneously towards Quad9 and Cloudflare.

4. **Validation:** Cloudflare responds in `14ms`. Quad9 responds in `22ms`. The module deep-inspects the Answer sections of both packets (`mode: strict`). Both returned the exact same `github.com` A-record IP endpoints (ignoring their order), successfully passing the tight consensus validation gate.

5. **Resolution:** Since the preference was explicitly set to `ordered`, the algorithm waits to verify both, but returns the specific message payload belonging to the Quad9 stream because it was listed first in the `config.yaml` array, yielding highly predictable response behavior. The response is cached and written to the client.

