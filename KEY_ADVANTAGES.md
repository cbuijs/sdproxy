# Key Advantages of sdproxy

## Introduction & Alternative Comparison

`sdproxy` is engineered as a lean, high-performance edge security proxy designed specifically for resource-constrained router hardware. When evaluated against traditional network alternatives like **Pi-hole**, **AdGuard Home**, and **smartdns**, `sdproxy` targets a fundamentally different operational threshold:

* **Feature Trade-offs:** Traditional alternatives focus on consumer-facing network infrastructure conveniences, offering built-in DHCP configuration daemons, standalone local DNSSEC zone validation chains, and verbose web-based list editors. `sdproxy` skips these infrastructure tasks—instead scraping existing local daemon lease files—to dedicate its computational overhead strictly to high-performance security enforcement, automated cryptographic upgrade paths, and behavioral analysis.
* **Resource Optimization:** Conventional options rely heavily on high-overhead runtime text matching and write-intensive on-disk query logging (e.g., SQLite), which can cause high CPU utilization and wear down flash storage on low-power routers. `sdproxy` optimizes performance for these environments by storing tracking data in an encrypted, sharded, in-memory architecture and using wait-free scheduling loops.
* **Behavioral Threat Mitigation:** While alternative tools depend entirely on static, text-based domain blocklists, `sdproxy` stands out by actively defending against zero-day threats through automated, zero-allocation machine learning models and volumetric client profiling directly on the query path.

---

## Architectural & Functional Advantages

### 1. High-Performance Lock-Free Architecture
Traditional DNS servers face significant multi-threaded performance bottlenecks on multi-core hardware due to global mutex contention. `sdproxy` completely eliminates this overhead through distributed, lock-free micro-sharding:
* **256-Sharded Rate Limiting:** The Token Bucket rate limiter is distributed across 256 distinct shards via cryptographic mapping (`hash/maphash`), eliminating lock contention among concurrent workers.
* **256-Sharded Exfiltration Tracking:** Volumetric profiling metrics are stored in a 256-sharded array to scale under intense query velocity.
* **32-Sharded Cache System:** Memory storage for DNS lookups is divided into 32 independent shards utilizing stack-comparable struct keys for zero-allocation cache mapping.
* **32-Sharded Top-N Analytical Trackers:** Frequency counters for real-time dashboard telemetry are segmented into 32 buckets binned chronologically by hour to avoid mutex saturation and enforce strict retention horizons.

### 2. Wait-Free Adaptive Admission Control
Instead of fixed query maximums that artificially throttle performance, `sdproxy` monitors real-time hardware constraints to protect system stability:
* **Wait-Free Admission Gates:** `AcquireQuery` and `AcquireUpstream` utilize O(1) constant-time atomic XADD operations and rollbacks rather than CPU-intensive `CompareAndSwap` spin-loops, preventing CPU starvation under extreme DDoS volumetric surges.
* **Blended Resource Signaling:** Adjusts execution ceilings via an AIMD loop driven by a combined resource pressure score: 85% derived from non-STW runtime metrics of physical heap usage, and 15% derived from upstream fan-out ratios.

### 3. Zero-Allocation Hot-Path Machine Learning
`sdproxy` moves beyond static signature lists by running predictive threat modeling directly on incoming DNS packets:
* **Stack-Allocated Inference Engine:** The Domain Generation Algorithm (DGA) classifier utilizes an O(n) Logistic Regression model executing entirely within stack memory with absolutely zero heap allocations, ensuring threat isolation without triggering Garbage Collection (GC) pauses.
* **Advanced Mathematical Extraction:** Uniquely isolates the core domain from infrastructural eTLD boundaries and extracts Shannon Entropy, phonetic vowel/consonant ratios, and consecutive consonant anomaly chains to intercept stochastic botnet C2 nodes.

### 4. Behavioral Data Exfiltration & Tunneling Defense
Malicious software frequently utilizes port 53 to exfiltrate private data via stealthy DNS tunneling:
* **Alpha-Smoothed EMA Bandwidth Profiling:** Tracks client and subnet throughput continuously over a lock-free Exponential Moving Average (EMA).
* **Micro-Burst Projection Heuristics:** Extrapolates accumulated payload bytes over microscopic timeframes (down to a 1ms floor) to intercept aggressive data leaks before standard 1-second interval clocks expire.
* **Lock-Free Fast-Path Penalty Box:** Offloads abusive or compromised hosts to a lock-free `sync.Map` Penalty Box that terminates connections at connect-time, completely shielding the core router loops from log-storms and socket exhaustion.

### 5. Advanced Cryptographic Modernity & ECH
`sdproxy` provides native integration for modern encrypted transport parameters to ensure traffic privacy:
* **Inbound ECH Server Decryption:** Acts as a full Encrypted Client Hello (ECH) server, decrypting public SNI parameters natively across DoH, DoT, and DoQ listeners using raw 32-byte X25519 seeds.
* **Outbound ECH Auto-Discovery:** Interrogates upstream `HTTPS` and `SVCB` records dynamically during bootstrapping to extract ECH configuration arrays completely autonomously.
* **Designated Resolver Discovery (DDR):** Synthesizes RFC 9462 and RFC 9461 compliant `_dns.resolver.arpa` SVCB payloads natively, enabling downstream client devices to automatically discover and upgrade plain UDP traffic to encrypted lines without manual profiling.

### 6. Enterprise-Grade Consensus Validation
Upstream connection groups enforce strict operational integrity rather than forwarding queries blindly:
* **Strict Cross-Upstream Consensus:** Queries all group members simultaneously and runs a multi-party deep-packet verification loop to guarantee RCODE parity and mathematical answer-identity equivalence.
* **NULL-IP Integrity Protections:** Automatically voids consensus and synthesizes secure block drops if any individual upstream yields a hijacked or poisoned sentinel IP (`0.0.0.0` or `::`).
* **Epsilon-Greedy Explorer Strategy:** Tracks nanosecond latency per connection using an EMA, executing a 5% exploration rate to stochastically query non-dominant pools and dynamically discover when a previously slow pathway has recovered.

### 7. Deep Packet Firewall Defenses
The routing pipeline includes strict multi-layered verification filters to protect downstream infrastructure:
* **DNS Rebinding Prevention (SSRF Guard):** Deeply inspects upstream answer payloads to intercept external domains resolving to private, unroutable, or loopback network spaces, excluding safe unspecified ad-block sinkholes.
* **Rigid Bailiwick Verification:** Bounds CNAME chain traversal to exactly 16 steps and audits historical ownership bounds to prevent rogue upstreams from poisoning memory cache shards.
* **Anti-Amplification Mitigations:** Drops large `ANY` queries stateless over UDP and enforces strict DNS Flag Day 2020 1232-byte packet truncation constraints to prevent participation in reflection attacks.

### 8. Granular Accumulative Screen-Time Management
Unlike typical "on or off" schedule blocks, `sdproxy` acts as a precise, minute-by-minute parental quota engine:
* **Forced DNS Heartbeat TTLs:** Rewrites record TTLs to a short heartbeat duration (e.g., 60s) for categorized targets, forcing clients to continuously re-query and keep usage metrics updated.
* **Idle-Pause Session Windows:** Monitored categories feature automated session pauses if no active queries arrive within a specific window, ensuring that screen-time metrics are accumulative rather than running continuously.
* **Isolated Client Cache Partitioning:** Incorporates `ClientName` signatures natively into the `DNSCacheKey` and SingleFlight key hashes when upstreams utilize dynamic `{client-name}` templates, preventing cross-client policy bleeding completely.

### 9. Operational Flexibility: Scaling Comfortably to a Hardened Public DNS Proxy
Due to its sharded architecture, integrated behavioral protection layers, and memory tracking ceilings, `sdproxy` possesses the unique flexibility to scale comfortably beyond residential environments and operate safely as an open public DNS forwarder:
* **Public Forwarder Capability:** Subsystems such as the lock-free 256-sharded rate limiter, wait-free admission control gates, volumetric data exfiltration shielding, anti-amplification rules, and lock-free automated fast-path penalty box mapping allow the engine to comfortably sustain the harsh, high-concurrency demands of the public internet.
* **Autonomous System Number (ASN) Mapping:** Hardened public routing tracking is fortified by lock-free IPinfo ASN database mapping. Client requests can be dynamically quarantined, categorized, or routed to discrete upstream consensus blocks based on the originating provider's ASN profile, with complete audit telemetry appended natively to logs.
* **Disclaimer & Infrastructure Mandate:** When leveraging `sdproxy` as a public forwarder, the overall quality of the underlying host infrastructure, physical compute cores, memory allocation bandwidth, and raw network interface resources becomes vastly more critical than when running on a local residential home router. While the micro-architecture is heavily optimized to preserve low-power environments, public deployments introduce un-spoofed concurrency depths that shift the primary operational bottleneck from software efficiency onto the physical network pipe, host routing fabric, and compute hardware limits. This elastic dual-use capability allows operators to comfortably deploy the exact same compiled binary as a lightweight home filter or an enterprise-grade public gateway.

