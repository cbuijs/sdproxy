# ECH Key-Pair Generation & sdproxy Configuration

## 1. Prerequisites
Ensure BoringSSL (`bssl`) is compiled and accessible in your environment.

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

* `ech_config_list.bin`: The public configuration payload advertised to clients via DDR (SVCB/HTTPS records).
* `ech.key`: The raw 32-byte X25519 private seed used by sdproxy to decrypt incoming TLS client hellos.
* `ech_config.bin`: The single ECH config (often unused directly, as the list format is required for DNS records).

## 3. Configure sdproxy
Edit your `config.yaml` to include the absolute paths to the generated ECH files under the `server:` block.

```yaml
server:
  # ... existing server configuration ...

  # Encrypted Client Hello (ECH)
  ech_config_list: "/etc/sdproxy/ech/ech_config_list.bin"
  ech_key: "/etc/sdproxy/ech/ech.key"
```

## 4. Apply Changes
Restart `sdproxy` to load the credentials. The server will automatically bind the ECH keys to the TLS listeners (DoH/DoT/DoQ) and broadcast the public `ech_config_list` natively to clients requesting `_dns.resolver.arpa`.

