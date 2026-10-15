# Upstreams that support ECH

Below are examples of upstream DNS servers that support ECH, formatted for `sdproxy`.
Ensure `server.use_upstream_ech` is set to `"try"` or `"strict"` in `config.yaml` for outbound ECH discovery to activate.

---
# Cloudflare
```text
doh3://cloudflare-dns.com/dns-query?echdomain=cloudflare-ech.com#1.1.1.1,1.0.0.1
```
---
# Cloudflare Security
```text
doh3://security.cloudflare-dns.com/dns-query?echdomain=cloudflare-ech.com#1.1.1.2,1.0.0.2
```
---
# Cloudflare Security + Family
```text
doh3://family.cloudflare-dns.com/dns-query?echdomain=cloudflare-ech.com#1.1.1.3,1.0.0.3
```
---
