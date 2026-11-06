# sdproxy - Docker Deployment Guide

This guide outlines how to build, deploy, and manage `sdproxy` using Docker and Docker Compose. Containerization provides a clean, isolated environment while maintaining the native high-performance characteristics of the DNS proxy.

## Prerequisites
* **Docker** installed on your host system.
* **Docker Compose** (v2 recommended).
* A valid `config.yaml` file prepared in the `docker/` directory.

---

## 1. Quick Start (Docker Compose)

The easiest way to deploy `sdproxy` is via `docker/docker-compose.yml`, which builds from the parent repository root (`context: ..`) using `docker/DockerFile`.

1. Place your customized `config.yaml` inside the `docker/` directory alongside `docker-compose.yml` and `DockerFile` (you can generate a full reference configuration using `sdproxy --example-config > docker/config.yaml`).
2. From the `docker/` directory, build and start the container in detached mode:

~~~bash
cd docker
docker compose up -d --build
~~~

3. Check the logs to verify successful initialization natively:

~~~bash
docker compose logs -f
~~~

---

## 2. Networking & Client Identity Tracking (Important)

By default, Docker uses a bridge network and NAT (Network Address Translation) to route traffic into the container. This causes all incoming DNS queries to appear as if they are coming from the Docker gateway IP (e.g., `172.17.0.1`), masking the actual client IP and physical ARP MAC addresses.

**If you use features that require exact client IP or MAC tracking:**
* Rate Limiting & Penalty Box
* Data Exfiltration (DNS Tunneling) & Per-Client Subdomain Limiters
* IP / CIDR / MAC / ASN / Country (`CC:`) Routing & Parental Controls
* Web UI Known Clients & Blocking

You have two options to preserve true client identities:

### Option A: Host Networking (Recommended on Linux)
To enable host networking, modify `docker/docker-compose.yml` to remove the `ports:` section and add `network_mode: "host"`:

~~~yaml
services:
  sdproxy:
    build:
      context: ..
      dockerfile: docker/DockerFile
    container_name: sdproxy
    restart: unless-stopped
    network_mode: "host" # Bypasses Docker NAT to preserve true client IPs and /proc/net/arp visibility
    volumes:
      - ./config.yaml:/etc/sdproxy/config.yaml:ro
      - sdproxy_data:/var/lib/sdproxy
      - sdproxy_certs:/etc/sdproxy/certs
~~~

*Note: Host networking is only supported on Linux Docker hosts.*

### Option B: Trusted Forwarder with EDNS0 MAC / ECS
If `sdproxy` runs in a bridged container behind a local forwarder on your router (such as `dnsmasq` configured with `--add-mac` and `--add-subnet=32,128`), you can authorize the Docker bridge gateway or forwarder IP in `config.yaml` using `server.trusted_proxies` and route clients via `mac:` and `ecs:` rules:

~~~yaml
server:
  trusted_proxies:
    - "127.0.0.0/8"
    - "172.17.0.0/16"
    - "192.168.1.1"
~~~

---

## 3. Persistent Storage (Volumes)

`sdproxy` requires persistent storage to survive container restarts and upgrades natively without losing historical analytics, cache data, or parental quota snapshots.

The `docker-compose.yml` maps two critical volumes:
1. `/var/lib/sdproxy`: Stores the DNS memory cache (`dns_cache.bin`), parental control snapshots and compiled category caches (`parental-catcache.bin`), Top-N trackers, hourly ring buffers, custom rules (`custom-rules.json`), and dynamically downloaded ASN/Domain Policy databases (`policy-compiled.bin`).
2. `/etc/sdproxy/certs`: Directory for persisting your TLS certificates (`cert.pem`, `key.pem`) and Encrypted Client Hello (ECH) keys.

Your configuration file is mounted as read-only (`:ro`) to prevent the container from accidentally modifying your master configuration:
`- ./config.yaml:/etc/sdproxy/config.yaml:ro`

---

## 4. Resource Constraints

`sdproxy` is engineered to be highly efficient. The provided `docker-compose.yml` applies a hard memory ceiling of `256M` natively to the container.

If you are running on heavily constrained hardware (like an embedded router or Raspberry Pi Zero) and have configured a lower `memory_limit_mb` in your `config.yaml` (e.g., `64`), you can safely lower the Docker deployment limit to match:

~~~yaml
    deploy:
      resources:
        limits:
          memory: 128M
~~~

---

## 5. Configuration Management & Updating

You can validate, clean, or upgrade your `config.yaml` directly via the container image:

~~~bash
# Validate config syntax and logic
docker compose run --rm sdproxy --test --config /etc/sdproxy/config.yaml

# Upgrade your config.yaml with all new options and documentation comments
docker compose run --rm sdproxy --update-config --config /etc/sdproxy/config.yaml > config.updated.yaml
~~~

When a new version of `sdproxy` is released, or if you modify the Go source code locally, rebuild and apply the changes cleanly:

~~~bash
docker compose up -d --build --force-recreate
~~~

