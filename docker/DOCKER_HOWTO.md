# sdproxy - Docker Deployment Guide

This guide outlines how to build, deploy, and manage `sdproxy` using Docker and Docker Compose. Containerization provides a clean, isolated environment while maintaining the native high-performance characteristics of the DNS proxy.

## Prerequisites
* **Docker** installed on your host system.
* **Docker Compose** (v2 recommended).
* A valid `config.yaml` file prepared in your deployment directory.

---

## 1. Quick Start (Docker Compose)

The easiest way to deploy `sdproxy` is via `docker-compose.yml`. 

1. Ensure your `Dockerfile`, `docker-compose.yml`, and `config.yaml` are in the same directory.
2. Build and start the container in detached mode:
   ```bash
   docker compose up -d --build
   ```
3. Check the logs to verify successful initialization natively:
   ```bash
   docker compose logs -f
   ```

---

## 2. Networking & IP Tracking (Important)

By default, Docker uses a bridge network and NAT (Network Address Translation) to route traffic into the container. This causes all incoming DNS queries to appear as if they are coming from the Docker gateway IP (e.g., `172.17.0.1`), masking the actual client IP addresses.

**If you use features that require exact client IP tracking:**
* Rate Limiting & Penalty Box
* Data Exfiltration (DNS Tunneling) Anomaly Detection
* IP/CIDR/MAC/ASN Routing & Parental Controls

**You MUST use Host Networking.**
To enable host networking, modify your `docker-compose.yml` to remove the `ports:` section and add `network_mode: "host"`:

```yaml
services:
  sdproxy:
    build: .
    container_name: sdproxy
    restart: unless-stopped
    network_mode: "host" # Bypasses Docker NAT to preserve true client IPs
    volumes:
      - ./config.yaml:/etc/sdproxy/config.yaml:ro
      - sdproxy_data:/var/lib/sdproxy
      - sdproxy_certs:/etc/sdproxy/certs
```

*Note: Host networking is only supported on Linux Docker hosts.*

---

## 3. Persistent Storage (Volumes)

`sdproxy` requires persistent storage to survive container restarts and upgrades natively without losing historical analytics, cache data, or rate-limiting strike states.

The `docker-compose.yml` maps two critical volumes:
1. `/var/lib/sdproxy`: Stores the DNS memory cache (`dns_cache.bin`), parental control snapshots, Top-N trackers, hourly ring buffers, and dynamically downloaded ASN/Domain Policy databases.
2. `/etc/sdproxy/certs`: Directory for persisting your TLS certificates (`cert.pem`, `key.pem`) and Encrypted Client Hello (ECH) keys.

Your configuration file is mounted as read-only (`:ro`) to prevent the container from accidentally modifying your master configuration:
`- ./config.yaml:/etc/sdproxy/config.yaml:ro`

---

## 4. Resource Constraints

`sdproxy` is engineered to be highly efficient. The provided `docker-compose.yml` applies a hard memory ceiling of `256M` natively to the container. 

If you are running on heavily constrained hardware (like an embedded router or Raspberry Pi Zero) and have configured a lower `memory_limit_mb` in your `config.yaml` (e.g., `64`), you can safely lower the Docker deployment limit to match:

```yaml
    deploy:
      resources:
        limits:
          memory: 128M
```

---

## 5. Updating the Container

When a new version of `sdproxy` is released, or if you modify the Go source code locally, you can rebuild and apply the changes cleanly:

```bash
docker compose up -d --build --force-recreate
```


