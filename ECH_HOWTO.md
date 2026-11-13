# ECH Key-Pair Generation & sdproxy Configuration

## 1. Prerequisites
Ensure BoringSSL (`bssl`) or OpenSSL (with ECH/HPKE support) is installed in your environment.

## 2. Generate the ECH Key-Pair
Create a directory and generate the Encrypted Client Hello (ECH) keys using `bssl`.

```bash
mkdir -p /etc/sdproxy/ech
cd /etc/sdproxy/ech
bssl generate-ech \
  -out-ech-config-list ech_config_list.bin \
  -out-ech-config ech_config.bin \
  -out-private-key ech.key \
  -public-name "dns.home.arpa" \
  -config-id 1
```

* `ech_config_list.bin`: The public configuration payload advertised to clients via DDR (SVCB/HTTPS records) and HTTP `.well-known` endpoints.
* `ech.key`: The private key used by sdproxy to decrypt incoming TLS client hellos (supports both raw 32-byte X25519 seeds from `bssl` and PEM-encoded PKCS#8 private keys).
* `ech_config.bin`: The single ECH config (unused directly, as the list format is required for DNS records).

## 3. Configure sdproxy (Inbound Server ECH)
Edit your `config.yaml` to include the absolute paths to the generated ECH files under the `server:` block.

```yaml
server:
  # ... existing server configuration ...

  # Encrypted Client Hello (ECH) — Inbound Listeners (DoT, DoH, DoH3, DoQ)
  ech_config_list: "/etc/sdproxy/ech/ech_config_list.bin"
  ech_key: "/etc/sdproxy/ech/ech.key"
```

When configured, `sdproxy` automatically:
1. Binds the ECH keys to all TLS/QUIC listeners (DoT, DoH, DoH3, DoQ).
2. Advertises the `ech=` parameter in `_dns.resolver.arpa` and resolver-hostname DDR responses.
3. Serves the public ECH configuration over HTTPS at `/.well-known/origin-svcb` (JSON per `draft-ietf-tls-wkech`) and `/.well-known/ech` (`application/echconfig-list`).

## 4. Configure Outbound Upstream ECH (Optional)
To enable ECH when `sdproxy` connects to upstream encrypted resolvers:

```yaml
server:
  # Options: "disable" (default), "try" (fallback to plaintext SNI on failure), "strict"
  use_upstream_ech: "try"

  # SVCB target validation mode: "strict" (default), "loose", "apex", "any"
  hostname_ech: "strict"
```

## 5. Apply Changes
Restart `sdproxy` to load the credentials.

