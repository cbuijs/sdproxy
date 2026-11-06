# sdproxy

A DNS proxy that gives you real control over your home network.

---

# Intro

I spent years as a consultant in the "big boy" networking and security "arena". DNS security was/is my daily work, but also a favorite hobby to tinker with. Because I have kids now, and need to be a responsible parent, I took it on myself to filter the big bad internet for them. So I built **sdproxy** (Simple DNS Proxy). It brings enterprise/big-boy protections/methods/precision to the home network level (kind of).

The proxy is written in Go and compiles to a lean binary for cheap routers. There are **NO** cloud subscriptions or monthly fees. It speaks every flavor of DNS and includes adaptive admission control to stay stable. It is just lean (kind of), mean, Dutch-engineered precision for the living room. Just you, one executable and a yaml file.

And remember... It's always DNS!

---

**Note:** The `full_reference_config.yaml` in this repository (also embedded in the binary via `sdproxy --example-config`) is always more up to date than this README. When in doubt, check there.

---

DNS is the phonebook of the internet - every device on your network looks up a name before it connects anywhere.

**sdproxy** sits in the middle of that, on your router, and lets you decide what happens next: cache it, block it, route it to a different resolver, apply advanced ML security models, or enforce time limits per child. No cloud subscription, no monthly fee, no external service that goes down.

It's written in Go, compiles to a single binary, and is lean enough to run on cheap home routers (OpenWrt on a TP-Link, GL.iNet or NetGear, pfSense, OPNsense or just a plain Linux box).

See `KEY_ADVANTAGES.md` for key advantages vs alternatives.

---

## What it does

### Speaks every flavour of DNS & Auto-Upgrades
Plain old UDP/TCP (port 53), encrypted DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ).
* **Dynamic DoH3 Upgrades:** `sdproxy` natively parses `Alt-Svc` headers and SVCB/HTTPS ALPN parameters to seamlessly upgrade standard DoH streams to high-performance HTTP/3 (QUIC) connections on the fly.

### Encrypted Client Hello (ECH) & DDR Auto-Discovery
Protects your browsing from ISP deep-packet inspection by encrypting the TLS Server Name Indication (SNI).
* **Inbound ECH:** `sdproxy` acts as a full ECH server, decrypting client hellos and natively broadcasting its own keys to your local network via DDR (`_dns.resolver.arpa` SVCB/HTTPS) and `/.well-known/origin-svcb` / `/.well-known/ech` HTTPS endpoints.
* **Outbound ECH Auto-Discovery:** When talking to upstream providers, `sdproxy` actively interrogates their `HTTPS`/`SVCB` records (and L7 `.well-known` fallbacks), extracts their ECH keys, and secures the TLS handshake completely autonomously.

### Machine Learning DGA Detection
A native, zero-allocation Logistic Regression ML inference engine runs on the hot path. It extracts Shannon entropy, vowel/consonant skew, trailing digit patterns, and consonant chains to instantly detect and block Algorithmically Generated Domains (DGA) used by botnets, malware, and C2 infrastructure.

### RFC 10023 `_for-sale.` & Parked Domain Detection
* **RFC 10023 `_for-sale.` Detection (`server.for_sale`):** Probes `_for-sale.<qname>` and `_for-sale.<apex>` for valid RFC 10023 TXT records (`v=FORSALE1;`) using a 64-shard verdict cache, full parent-chain cache walks, and SingleFlight coalescing. Supports `disabled`, `BLOCK`, `DROP`, `LOG`, or any standard DNS RCODE.
* **Parked Domain Detection (`server.parked`):** Detects parked domains, intermediate parent domains, and `eTLD+1` apexes by actively probing and passively inspecting authoritative `NS`, `SOA`, `TXT`, `CNAME`, and `A`/`AAAA` records for common domain-parking and aftermarket monetization providers (Sedo, Bodis, ParkingCrew, Above.com, Dan.com, Afternic, CashParking, HugeDomains, Squadhelp/Atom, Uniregistry, ParkLogic, RookMedia, etc.).

### Data Exfiltration, Tunneling & Info-Stealer Defense
* **Volumetric Profiling:** Tracks the Alpha-Smoothed Exponential Moving Average (EMA) of bytes transferred per-client or per-subnet. Detects sudden, anomalous bursts of data exiting the network over DNS and blackholes the client in a lock-free Penalty Box.
* **Subdomain Rate Limiting:** Tracks unique subdomains queried per `(client/subnet, apex domain)` within a configurable time window (with optional `exempt_shared_hosting`) to intercept slow-and-low DNS tunneling and info-stealer exfiltration without allowing cross-client denial of service.

### Domain Policies & Spoofed Records (`rrs:`) with Regex Support
* **Domain & RType Policies:** Block, drop, or return custom RCODEs for specific DNS record types (`rtype_policy`), domain suffixes, IPs/CIDRs, or regular expressions (`/pattern/`) via inline config, local files, or remote URLs.
* **Spoofed Records (`rrs:`):** Override global or per-group domains (exact or `/pattern/` regex) with static IPv4/IPv6 addresses or transparent recursive CNAME aliases (e.g., enforcing SafeSearch).

### Enterprise Routing & Consensus Validation
`sdproxy` does not just forward queries blindly; it evaluates upstreams dynamically.
* **Secure Consensus:** Queries up to `max_secure_upstreams` (default 5) healthy servers in a group simultaneously. Deep-inspects canonical RRset fingerprints (CNAME chains, final IP endpoints, SVCB/HTTPS, DNSSEC state) with support for `fastest`, `ordered`, and `consolidate` (merged answer set) preferences. In `strict` mode, 100% participation and answer equivalence are enforced; in `loose` mode, a majority of healthy responders is used. Drops or blocks the response if upstreams disagree or return a poisoned NULL-IP.
* **Fastest EMA:** Tracks the nanosecond latency of every upstream. Uses an Epsilon-Greedy algorithm to stick to the fastest healthy resolver while reserving 5% of queries for random exploration to discover recovering network paths.
* **SingleFlight Coalescing:** Identical concurrent cache-miss queries are seamlessly coalesced into a single outbound execution, eliminating Thundering Herd spikes.

### Caches aggressively
Answered something recently? Serve it from cache. `sdproxy` utilizes 32 cryptographically seeded memory shards with optional crash-safe disk persistence across reboots (including route configuration fingerprinting). If a record expires while still popular, `sdproxy` triggers a **background prefetch** so your devices never notice a cache miss. It fully supports RFC 8767 Stale-Serving, strict DNSSEC `RRSIG` expiration bounds, and `serve_stale_infinite` outage fallbacks.

### Knows your local network
Point it at your DHCP lease files and `/etc/hosts` and it will answer local name lookups (your NAS, your printer, your Pi) without bothering an upstream resolver or leaking LAN queries upstream. Works with dnsmasq, ISC DHCP, Kea, and odhcpd.

### Routes different devices differently
Map a device's identity to a different upstream resolver group or parental profile.
* **Identifiers:** Physical ARP MAC exact, MAC glob masking, EDNS0 Option 65001 MAC (`mac:<mac>` and `mac:<glob>`), IP / CIDR, EDNS0 Client Subnet (`ecs:<ip>` and `ecs:<cidr>`), ASN (`ASxxxx`), Country Code (`CC:XX` via IPinfo), Client-name, TLS SNI (`sni:`), HTTP DoH Paths (`path:`), and Listener Ports (`port:`).
* **Trusted Forwarder Boundary (`server.trusted_proxies`):** Restricts client-supplied EDNS0 Option 65001 (`mac:`) and EDNS0 Client Subnet (`ecs:`) identity assertions to authorized local forwarders (such as `dnsmasq --add-mac` / `--add-subnet`, defaulting to loopback `127.0.0.0/8` and `::1/128`).
* **Compound Intersection Rules:** Combine multiple identifiers with `force-and: true` (e.g., Subnet AND Listener Port).
* **Instant Sinkholes & Bypasses:** Bind an explicit DNS Return Code (`rcode: REFUSED`, `NXDOMAIN`, `BLOCK`, `DROP`) or `bypass_local` / `bypass_global` flags directly to a routing rule.

### Parental controls - per child, per category
Set up a profile per child, assign their devices, and configure:
* **Schedules** - Different hours for school days vs weekends.
* **Time Budgets** - Accumulative minute-by-minute tracking (`group` or per-`device`). Supports `ALLOW`, `BLOCK`, `FREE`, `LOG`, `UNLIMITED`, and temporary `UNTRIGGER` window overrides.
* **Category blocks** - Loaded dynamically from public repos or local files (Domains, Hosts, AdBlock/uBlock, and IP/CIDR lists) with pre-compiled binary disk caching.
* **State Tracking:** Time tracking runs via DNS heartbeat TTLs and snapshots to disk to survive reboots.

### Web admin panel
Optional, password-protected browser-based UI (HTTP/HTTPS, or multiplexed on DoH port 443) for live operations.
* Instantly flip a device group to **ALLOW**, **BLOCK**, **FREE**, or **LOG** with optional countdown timers.
* **Known Clients & Blocking:** View discovered LAN and EDNS0-MAC clients (IP, MAC, DHCP name, randomized MAC badge, and live Last Seen timestamps) and one-click block/unblock individual devices or all unknown/privacy-MAC clients in bulk.
* **Custom Rules & Cache Inspector:** Manage live per-group or global domain allow/block rules and inspect/search live cached DNS records directly from the browser.
* View live, streaming query logs (SSE) and 24-hour Ring-Buffer performance charts.

### Protects against DNS Rebinding & Search Domain Leaks
Drops any upstream response containing private or bogon IPs (RFC1918, loopbacks, link-local, ULAs) to prevent Server-Side Request Forgery (SSRF) and browser pivoting attacks, and intercepts OS stub resolvers that append local search domains to recently blocked queries.

---

## Quick start

~~~bash
git clone https://github.com/cbuijs/sdproxy
cd sdproxy
go build -o sdproxy .
./sdproxy --config config.yaml
~~~

Requires Go 1.26+. No CGo.

### Command-line options

~~~text
  -c, --config <file>    Path to YAML configuration file (default: config.yaml)
  -t, --test             Test the configuration file for syntax/logic errors and exit
  -C, --clean-config     Clean the configuration file (strip comments and default values) to stdout and exit
  -U, --update-config    Update/complement the configuration file with all comments and missing options to stdout and exit
  -E, --example-config   Print the full documented default/reference configuration to stdout and exit
  -f, --force-refresh    Force fetching/loading fresh copies of all external lists and databases on startup
  -4, --ipv4             Limit resource loading and listeners to IPv4 only
  -6, --ipv6             Limit resource loading and listeners to IPv6 only
  -v, --version          Show current sdproxy version and exit
  -h, --help             Show this help message
~~~

### Minimal config

~~~yaml
server:
  listen_udp: ["0.0.0.0:53"]

cache:
  enabled: true
  size: 1024

upstreams:
  default:
    - "udp://1.1.1.1:53"
    - "udp://9.9.9.9:53"
~~~

### Build for your router

~~~bash
# OpenWrt MIPS (TP-Link, Netgear, etc.)
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags="-s -w" -o sdproxy .

# OpenWrt ARM (Linksys, Asus, etc.)
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o sdproxy .

# OpenWrt x86_64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o sdproxy .
~~~

The `-s -w` flags strip debug symbols - saves 30-40% binary size, which matters on small flash storage.

---

## Configuration

Everything lives in one YAML file. The `full_reference_config.yaml` in this repo documents every single option inline - that file is the manual. You can also generate it at any time with `./sdproxy -E > config.yaml`, strip defaults with `./sdproxy -C -c config.yaml`, or upgrade an existing config file with new options and comments using `./sdproxy -U -c config.yaml`.

---

## Log output

~~~text
2026/05/01 14:23:01 [DNS] [DoH3+ECH] 192.168.1.42 (alice-iphone) -> google.com. A | ROUTE: kids (CLIENT-NAME) | UPSTREAM: [ECH] cloudflare-dns.com (1.1.1.1) (kids) | OK | NOERROR
2026/05/01 14:23:02 [DNS] [UDP] 192.168.1.42 (alice-iphone) -> google.com. A | ROUTE: kids (CLIENT-NAME) | CACHE HIT | NOERROR
2026/05/01 14:23:05 [DNS] [DoQ] 192.168.1.10 -> nas.lan. A | ROUTE: default (DEFAULT) | LOCAL | NOERROR
2026/05/01 14:23:10 [DNS] [UDP] 192.168.1.42 (alice-iphone) -> dga-domain-xzq1.com. A | DGA INTERCEPT (Score: 98.2) | NXDOMAIN
2026/05/01 14:23:12 [DNS] [UDP] 192.168.1.42 (alice-iphone) -> parked-example.com. A | FOR-SALE BLOCK (_for-sale.parked-example.com TXT "v=FORSALE1;") | NOERROR (NULL-IP)
2026/05/01 14:23:15 [DNS] [UDP] 192.168.1.42 (alice-iphone) -> sedo-domain.com. A | PARKED BLOCK (sedo-domain.com: NS Sedo (ns1.sedoparking.com)) | NOERROR (NULL-IP)
~~~

