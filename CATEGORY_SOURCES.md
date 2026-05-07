## How sdproxy uses these category sources/lists

Drop a URL or local file path into a `source:` field under
`parental.categories.<n>` in `config.yaml`. sdproxy fetches, caches, and
reloads remote lists on the configured interval — no manual downloading needed.
Local files are re-read from disk on every reload cycle.

Use categories not just for blocking but also for **metering** (time-of-day
rules, per-device quotas) and **monitoring** (logging/alerting which categories
a device hits).

Supported input formats (auto-detected per line — files may freely mix):
- **DOMAIN** — one bare domain per line (`example.com`)
- **HOSTS** — standard `/etc/hosts` format (`0.0.0.0 example.com`)
- **ADBLOCK/uBlock** — basic `||domain^` syntax (subdomains auto-included)

**Note:** If `server.support_ip_version` is set to `ipv4` or `ipv6`, any IP addresses 
or subnets in these lists that do not match the setting will be ignored during loading.

---

## The main categorised collections

These repos ship dozens of ready-made categories in one place.
Pick only the sub-lists you need to keep memory footprint small.

### cbuijs DNS Blocklists  ★ preferred
- **GitHub** : [https://github.com/cbuijs](https://github.com/cbuijs)
- Highly curated, cleaned, deduped, and wildcard-optimised lists.
  Several repos are processed versions of upstream sources (UT1),
  making them better suited for DNS firewall and sdproxy use than
  the raw upstream files.
- **Key repos** :

| Repo | URL | Notes |
|---|---|---|
| `accomplist` | [https://github.com/cbuijs/accomplist](https://github.com/cbuijs/accomplist) | Combined curated master list across many categories |
| `ut1` (processed) | [https://github.com/cbuijs/ut1](https://github.com/cbuijs/ut1) | Cleaned, wildcard-optimised UT1 - preferred over raw olbat mirror |

- Raw domain files follow the plain one-per-line format.
  Browse each repo's directory tree for per-category files.
- **Raw base URL for cbuijs/ut1 categories** (template - not clickable):
  `https://raw.githubusercontent.com/cbuijs/ut1/master/<category>/domains`

---

### UT1 Blacklists - Université Toulouse 1 Capitole  (olbat mirror, fallback)
- **Official site** : [https://dsi.ut-capitole.fr/blacklists/](https://dsi.ut-capitole.fr/blacklists/)
- **GitHub mirror** : [https://github.com/olbat/ut1-blacklists](https://github.com/olbat/ut1-blacklists)
- **Raw domain base URL** (template - not clickable):
  `https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/<category>/domains`
- Use the cbuijs/ut1 repo above when possible; fall back to olbat if a
  specific category is not yet present in the cbuijs mirror.
- One of the oldest academic categorisation projects, ~100 categories,
  updated regularly. Format: plain domain list, one per line.

**Notable categories for parental use** (substitute `<category>` in either base URL above):

> ⚠️ Use the exact slugs from the table below - some common names differ from
> what you might expect. In particular: streaming is `audio-video` (not
> `video_streams`), and drugs is `drogue` (the French UT1 slug).

| Category slug | What it covers |
|---|---|
| `adult` | Pornographic content |
| `agressif` | Violent or gore content |
| `audio-video` | YouTube, Twitch, Netflix, streaming platforms |
| `chat` | Messaging apps and web-chat platforms |
| `dating` | Dating and hook-up sites |
| `drogue` | Drug-related content |
| `forums` | Reddit, Discord forums, imageboards |
| `gambling` | Betting, casinos, poker |
| `games` | Online gaming sites and platforms |
| `hacking` | Exploit tools, hacking tutorials |
| `malware` | Malware distribution |
| `manga` | Manga / anime reading sites |
| `phishing` | Known phishing domains |
| `publicite` | Advertising networks |
| `redirector` | URL shorteners and redirect services |
| `sect` | Cult / extremist ideology sites |
| `shopping` | E-commerce - useful for screen-time rules |
| `social_networks` | Facebook, Instagram, TikTok, Snapchat, X/Twitter, etc. |
| `warez` | Piracy, cracked software |
| `webmail` | Webmail services |

---

## Security-focused (malware, phishing, ads)

| Name | URL | Format | Notes |
|---|---|---|---|
| Hagezi Light | [https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/light-onlydomains.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/light-onlydomains.txt) | Plain | Safest tier for constrained routers |
| OISD small | [https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_small.txt](https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_small.txt) | Plain | Conservative, very low false-positive rate |
| Peter Lowe | [https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0) | Hosts | Compact, stable, low false-positive rate |
| Phishing Army | [https://phishing.army/download/phishing_army_blocklist.txt](https://phishing.army/download/phishing_army_blocklist.txt) | Plain | Phishing-focused, daily refresh |
| StevenBlack unified | [https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | Hosts | Classic amalgamation: ads + malware |
| URLhaus | [https://urlhaus.abuse.ch/downloads/hostfile/](https://urlhaus.abuse.ch/downloads/hostfile/) | Hosts | Updated multiple times/day - use short poll interval (`6h`) |

---

## DoH / resolver bypass block

Prevents clients from side-stepping sdproxy by using hardcoded DoH resolvers.

| Name | URL | Format |
|---|---|---|
| Hagezi - DoH/VPN/Bypass | [https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt) | Plain |
| NextDNS - DoH list | [https://raw.githubusercontent.com/nextdns/dns-bypass-methods/refs/heads/main/encrypted-dns](https://raw.githubusercontent.com/nextdns/dns-bypass-methods/refs/heads/main/encrypted-dns) | Plain |

---

## Chat & messaging

| Name | URL | Format | Notes |
|---|---|---|---|
| cbuijs/ut1 - chat | [https://raw.githubusercontent.com/cbuijs/ut1/master/chat/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/chat/domains) | Plain | Web-chat and IM platforms |

---

## Adult, gambling & other sensitive categories

| Category | Source URL | Format |
|---|---|---|
| Adult / porn | [https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/adult-themed/optimized.black.domain.list](https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/adult-themed/optimized.black.domain.list) | Plain |
| Adult / porn (supplement) | [https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/nsfw-onlydomains.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/nsfw-onlydomains.txt) | Plain |
| Dating | [https://raw.githubusercontent.com/cbuijs/ut1/master/dating/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/dating/domains) | Plain |
| Drugs / narcotics | [https://raw.githubusercontent.com/cbuijs/ut1/master/drogue/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/drogue/domains) | Plain |
| Gambling | [https://raw.githubusercontent.com/cbuijs/ut1/master/gambling/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/gambling/domains) | Plain |
| Gambling (supplemental) | [https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts) | Hosts |
| Hacking tools | [https://raw.githubusercontent.com/cbuijs/ut1/master/hacking/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/hacking/domains) | Plain |
| Viiolence | [https://raw.githubusercontent.com/cbuijs/ut1/master/agressif/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/agressif/domains) | Plain |
| Warez / piracy | [https://raw.githubusercontent.com/cbuijs/ut1/master/warez/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/warez/domains) | Plain |

> Note: UT1 does not have a separate `alcohol` category. For alcohol-related
> filtering, use `drogue` (which covers broader substance-related sites) or
> add specific alcohol sites manually via the `add:` list in your category
> config.

---

## Suggested parental-monitoring category map

A practical starting setup — map these category names in `config.yaml`
and point each to the source URLs above. Use `meter` policy for categories
where you want logging/quota enforcement rather than hard-blocking.

```yaml
parental:
  categories:
    # (Online) Games
    games:
      source: "[https://raw.githubusercontent.com/cbuijs/ut1/master/games/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/games/domains)"

    # Social Networks
    social:
      source:
        - "[https://raw.githubusercontent.com/cbuijs/ut1/master/social_networks/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/social_networks/domains)"
        - "[https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/social-onlydomains.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/social-onlydomains.txt)"

    # Audo / Video streaming services
    streaming:
      source:
        - "[https://raw.githubusercontent.com/cbuijs/ut1/master/audio-video/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/audio-video/domains)"
        - "[https://raw.githubusercontent.com/cbuijs/ut1/master/manga/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/manga/domains)"
        - "[https://raw.githubusercontent.com/cbuijs/ut1/master/radio/domains](https://raw.githubusercontent.com/cbuijs/ut1/master/radio/domains)"

    # Adult / NSFW
    adult:
      source: "[https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/adult-themed/optimized.black.domain.list](https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/adult-themed/optimized.black.domain.list)"

    # Ads, Malware and Trackers
    ads_malware:
      source: "[https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/pro-onlydomains.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/pro-onlydomains.txt)"

    # Native trackers, IoT, TV's, etc
    native:
      source:
        # Amazon Devices / Alexa / etc
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/alexa](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/alexa)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-amazon/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-amazon/domains)"

        # Apple
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/apple](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/apple)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-apple/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-apple/domains)"

        # Huawei
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/huawei](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/huawei)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-huawei/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-huawei/domains)"

        # LG-Electronics, TV's, IoT, etc
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-lgwebos/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-lgwebos/domains)"

        # Oppo
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-oppo-realme/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-oppo-realme/domains)"

        # Roku
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/roku](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/roku)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-roku/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-roku/domains)"

        # Samsung
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/samsung](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/samsung)"

        # Sonos
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/sonos](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/sonos)"

        # TikTok
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-tiktok/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-tiktok/domains)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-tiktok-extended/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-tiktok-extended/domains)"

        # Vivo
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-vivo/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-vivo/domains)"

        # Microsoft / Office / Windows
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/windows](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/windows)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-winoffice/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-winoffice/domains)"

        # Xiaomi
        - "[https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/xiaomi](https://raw.githubusercontent.com/nextdns/native-tracking-domains/refs/heads/main/domains/xiaomi)"
        - "[https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-xiaomi/domains](https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/native-xiaomi/domains)"
      session_window: "5m"

    # Local custom list — plain domain, hosts, or adblock format (auto-detected):
    custom:
      source: "/etc/sdproxy/custom-domains.txt"


