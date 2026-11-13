# Enforcing SafeSearch using Spoofed Records (`rrs:`)

The `rrs:` (Spoofed Records) engine allows you to natively map exact domain names or regular expressions (`/pattern/`) to static IP addresses or CNAME targets. Because `sdproxy` handles CNAME flattening and recursive resolution transparently, you can use this to forcefully alias standard search engines to their "SafeSearch" endpoints.

This configuration can be applied globally in the top-level `rrs:` block, or selectively assigned to specific parental/routing profiles (under `groups.<group>.rrs:`) to restrict adult content dynamically for kids while leaving adult devices unrestricted.

## 1. Exact & Regex Global SafeSearch (`rrs:`)

You can specify exact domains (comma-separated if desired) or slash-delimited regular expressions (`/.../`) to cover all regional country-code TLDs in a single rule:

~~~yaml
# =============================================================================
# SAFESEARCH SPOOFED RECORDS (rrs:)
# =============================================================================

rrs:
  # -----------------------------------------------------------------------
  # Google SafeSearch
  # Forces all Google searches across regional TLDs to use the strict
  # SafeSearch engine via a single regex rule (or explicit domain keys).
  # -----------------------------------------------------------------------
  "/^(www\.)?google\.(com|ad|ae|al|am|as|at|az|ba|be|bf|bg|bi|bj|bs|bt|by|ca|cat|cd|cf|cg|ch|ci|cl|cm|cn|co\.ao|co\.bw|co\.ck|co\.cr|co\.id|co\.il|co\.in|co\.jp|co\.ke|co\.kr|co\.ls|co\.ma|co\.mz|co\.nz|co\.th|co\.tz|co\.ug|co\.uk|co\.uz|co\.ve|co\.vi|co\.za|co\.zm|co\.zw|com\.af|com\.ag|com\.ai|com\.ar|com\.au|com\.bd|com\.bh|com\.bn|com\.bo|com\.br|com\.bz|com\.co|com\.cu|com\.cy|com\.do|com\.ec|com\.eg|com\.et|com\.fj|com\.gh|com\.gi|com\.gt|com\.HK|com\.hk|com\.jm|com\.kh|com\.kw|com\.lb|com\.ly|com\.mm|com\.mt|com\.mx|com\.my|com\.na|com\.ng|com\.ni|com\.np|com\.om|com\.pa|com\.pe|com\.pg|com\.ph|com\.pk|com\.pr|com\.py|com\.qa|com\.sa|com\.sb|com\.sg|com\.sl|com\.sv|com\.tj|com\.tr|com\.tw|com\.ua|com\.uy|com\.vc|com\.vn|cv|cz|de|dj|dk|dm|dz|ee|es|fi|fm|fr|ga|ge|gg|gl|gm|gp|gr|gy|hn|hr|ht|hu|ie|im|iq|is|it|je|jo|kg|ki|kz|la|li|lk|lt|lu|lv|md|me|mg|mk|ml|mn|ms|mu|mv|mw|ne|nl|no|nr|nu|org|pl|pn|ps|pt|ro|rs|ru|rw|sc|se|sh|si|sk|sm|sn|so|sr|st|td|tg|tk|tl|tm|tn|to|tt|vg|vu|ws)$/": "forcesafesearch.google.com"

  # -----------------------------------------------------------------------
  # YouTube Restricted Mode
  # Hides potentially mature videos and comments.
  # Targets:
  #   - restrict.youtube.com (Strict Mode)
  #   - restrictmoderate.youtube.com (Moderate Mode)
  # -----------------------------------------------------------------------
  "www.youtube.com, m.youtube.com, youtubei.googleapis.com, youtube.googleapis.com, www.youtube-nocookie.com": "restrict.youtube.com"

  # -----------------------------------------------------------------------
  # Bing SafeSearch
  # Forces Bing to strictly filter adult text, images, and videos.
  # -----------------------------------------------------------------------
  "www.bing.com, bing.com": "strict.bing.com"

  # -----------------------------------------------------------------------
  # DuckDuckGo SafeSearch
  # Forces DuckDuckGo to use its safe search portal.
  # -----------------------------------------------------------------------
  "duckduckgo.com, start.duckduckgo.com, www.duckduckgo.com": "safe.duckduckgo.com"

  # -----------------------------------------------------------------------
  # Pixabay SafeSearch
  # -----------------------------------------------------------------------
  "pixabay.com": "safesearch.pixabay.com"
~~~

## 2. Per-Group SafeSearch (`groups.<name>.rrs:`)

To enforce SafeSearch only for specific devices (e.g., children's devices assigned to the `kids` group), place the `rrs:` block inside the group definition:

~~~yaml
groups:
  kids:
    upstream: "kids"
    rrs:
      "/^(www\.)?google\.(com|nl|de|fr|co\.uk)$/": "forcesafesearch.google.com"
      "www.youtube.com, m.youtube.com, youtubei.googleapis.com, youtube.googleapis.com, www.youtube-nocookie.com": "restrict.youtube.com"
      "www.bing.com, bing.com": "strict.bing.com"
      "duckduckgo.com, start.duckduckgo.com, www.duckduckgo.com": "safe.duckduckgo.com"
~~~

