# Enforcing SafeSearch using Spoofed Records (`rrs:`)

The `rrs:` (Spoofed Records) engine allows you to natively map domains to static CNAME targets. Because sdproxy handles CNAME flattening and recursive resolution transparently, you can use this to forcefully alias standard search engines to their "SafeSearch" endpoints.

This configuration can be applied globally in the main `rrs:` block, or selectively assigned to specific routing profiles (e.g., inside the `kids` group) to restrict adult content dynamically.

```yaml
# =============================================================================
# SAFESEARCH SPOOFED RECORDS (rrs:)
# =============================================================================

rrs:
  # -----------------------------------------------------------------------
  # Google SafeSearch
  # Forces all Google searches to use the strict SafeSearch engine.
  # (Tip: Add regional TLDs like google.co.uk or google.de if utilized)
  # -----------------------------------------------------------------------
  "www.google.com": "forcesafesearch.google.com"
  "www.google.fr": "forcesafesearch.google.com"
  "www.google.nl": "forcesafesearch.google.com"

  # -----------------------------------------------------------------------
  # YouTube Restricted Mode
  # Hides potentially mature videos and comments.
  # Targets:
  #   - restrict.youtube.com (Strict Mode)
  #   - restrictmoderate.youtube.com (Moderate Mode)
  # -----------------------------------------------------------------------
  "www.youtube.com": "restrict.youtube.com"
  "m.youtube.com": "restrict.youtube.com"
  "youtubei.googleapis.com": "restrict.youtube.com"
  "youtube.googleapis.com": "restrict.youtube.com"
  "www.youtube-nocookie.com": "restrict.youtube.com"

  # -----------------------------------------------------------------------
  # Bing SafeSearch
  # Forces Bing to strictly filter adult text, images, and videos.
  # -----------------------------------------------------------------------
  "www.bing.com": "strict.bing.com"

  # -----------------------------------------------------------------------
  # DuckDuckGo SafeSearch
  # Forces DuckDuckGo to use its safe search portal.
  # -----------------------------------------------------------------------
  "duckduckgo.com": "safe.duckduckgo.com"
  "start.duckduckgo.com": "safe.duckduckgo.com"
  "www.duckduckgo.com": "safe.duckduckgo.com"
```

