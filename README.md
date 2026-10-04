# edl-aggregator

Merge public threat feeds (IP addresses, domains and URLs) and service ranges and serve them as **External
Dynamic Lists** (EDLs) for your firewall. A lightweight replacement for the most common use of Palo Alto
**MineMeld** (discontinued), in one Python file with no dependencies beyond the standard library.

Works with Palo Alto IP / domain / URL EDLs, pfSense/OPNsense URL table aliases, FortiGate external threat feeds,
or anything that can poll a URL for a list.

## Features

- **IP sources**: Spamhaus DROP (v4/v6) and ASN-DROP (expanded to announced ranges), DShield, Emerging Threats,
  CINS Army, IPsum, GreenSnow, blocklist.de, abuse.ch Feodo and ThreatFox C2, Tor exits (v4/v6), AbuseIPDB and
  CrowdSec (accounts), Team Cymru bogons, AWS / Cloudflare / Google / Google Cloud / GitHub / Fastly /
  Microsoft 365 / UptimeRobot ranges - or any plain-text, CSV or JSON list.
- **Domain and URL sources**: abuse.ch URLhaus (URLs + domains) and ThreatFox (URLs + domains), OpenPhish, Phishing Army, Hagezi
  Threat Intelligence, Microsoft 365 domains - plain, hosts-file or JSON. URLs are published in Palo Alto URL-EDL
  form (no scheme).
- **Dynamic lists**: add or remove entries at runtime through an authenticated API, with optional expiry - for
  scripts, Home Assistant, fail2ban/CrowdSec bouncers, or a quick manual block.
- **Access control**: HTTP Basic auth and client allow-lists, globally or per feed.
- **Live config reload**: edits apply within a minute; an invalid file is rejected and the running config stays.
- **IPv6 throughout**: every source that publishes IPv6 is used, plus a compact IPv6 bogon list (7 entries).
- **Feeds**: merge sources, subtract allow-lists, filter by family and confidence, collapse to the fewest CIDRs.
  Three kinds: `block`, `allow` (service ranges) and `bogon`.
- **Safe by default**:
  - a source that fails, returns fewer than `min_entries`, or shrinks by more than `max_shrink_percent` keeps
    its last good copy;
  - `[safety] never_block` ranges (your own networks) are removed from every block feed;
  - a feed over `max_entries` keeps serving its previous build instead of a list your firewall would reject;
  - webhook alerts (e.g. Apprise) after repeated source failures, oversize feeds, and recoveries.
- **Efficient**: per-source refresh intervals, conditional downloads (ETag / If-Modified-Since), and `304 Not
  Modified` to firewalls that send `If-None-Match`.
- **Observable**: `/status` (JSON), `/metrics` (Prometheus), `/lookup?ip=` ("why is this IP blocked?").
- **MineMeld-compatible URLs**: `/feeds/<name>`, query strings like `?tr=1&v=panosurl` are ignored, and feeds can
  have **aliases** for old MineMeld feed names.

## Run

```bash
docker run -d --name edl-aggregator \
  -p 80:80 -p 443:443 \
  -v /path/to/config:/config -v /path/to/data:/data \
  ghcr.io/davidcoulson/edl-aggregator:latest
```

On first start the example config is written to `/config/config.toml`. Edit it and restart the container.
Pass API keys as environment variables (e.g. `-e ABUSEIPDB_API_KEY=...`) and reference them as `${NAME}`.

| Path | What |
|---|---|
| `/` | index of feeds by kind and type, with entry counts |
| `/feeds/<name>` | the list, one CIDR per line (`.txt` suffix optional); ETag/Last-Modified, 304 support |
| `/status`, `/healthz` | JSON status of every source and feed; HTTP 503 if a required source has no data |
| `/metrics` | Prometheus metrics: entries per feed/source, source up/failures/last success, overflow |
| `/lookup?ip=` / `?domain=` / `?url=` | which feeds and sources contain it, and whether it is protected by `never_block` |
| `/api/dynamic/<list>` | dynamic list API (bearer token; see below) |

| Environment | Default | |
|---|---|---|
| `CONFIG` | `/config/config.toml` | config file |
| `DATA_DIR` | `/data` | cache of last good source data, generated TLS cert |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | `0` disables a listener |
| `TLS_CERT` / `TLS_KEY` | `/data/tls/cert.pem`, `key.pem` | created self-signed if missing |
| `TICK_SECONDS` | `60` | how often due sources are checked |
| `LOG_LEVEL` | `INFO` | |

## Configure

See [`config.example.toml`](config.example.toml): it documents every option and ships ready-made sources and
feeds. In short:

```toml
refresh_minutes = 60

[safety]
max_shrink_percent = 50
never_block = ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.10"]   # your networks

[alerts]
webhook_url = "http://apprise:8000/notify/edl"
after_failures = 3

[sources.spamhaus_drop_v6]
url = "https://www.spamhaus.org/drop/drop_v6.json"
format = "spamhaus-json"

[sources.github_hooks]
url = "https://api.github.com/meta"
format = "json"
paths = ["hooks[]"]

[feeds.threat-ipv6]
sources = ["spamhaus_drop_v6"]
family = "ipv6"

[feeds.github-hooks]
kind = "allow"
sources = ["github_hooks"]
```

Source formats: `plain`, `hosts` (hosts-file), `csv` (`column`, optional `min_column`/`min_value` threshold),
`spamhaus-json`, `spamhaus-asn-json`, `dshield`, `aws-json` (`service`, `region`), and `json` with `paths`
(`"prefixes[].ipv6Prefix"`, `"[].ips[]"`; `[]` iterates a list) and an optional `where` filter. Entries may be IPs,
CIDRs, `a-b` ranges, `[v6]:port` or `v4:port`.

## ASN expansion

`expand_asns = true` (automatic for `format = "spamhaus-asn-json"`) treats a source's entries as AS numbers and
publishes every range those networks announce, using an ip2asn-style database - by default the free
[iptoasn.com](https://iptoasn.com) combined IPv4/IPv6 table (about 9 MB, re-downloaded daily and cached; a failed
download keeps using the cached copy). Override with `asn_database` / `asn_database_refresh_minutes`.

## Sources that need an account

Everything in the example config works without an account except these, which ship disabled:

| Source | Account | What to set |
|---|---|---|
| AbuseIPDB (`abuseipdb_v4`, `abuseipdb_v6`) | free account at abuseipdb.com -> API key. Free tier: 5 blacklist downloads/day (the example refreshes every 6 h), 10,000 IPs per list | `ABUSEIPDB_API_KEY` env var; `enabled = true` |
| CrowdSec (`crowdsec_blocklist`) | free CrowdSec Console account -> create a *Blocklist integration* (firewall integration) and subscribe it to blocklists | `CROWDSEC_BLOCKLIST_URL` and `CROWDSEC_BASIC_AUTH` (base64 of `user:password`); `enabled = true` |

No account needed: Spamhaus DROP / ASN-DROP (free under Spamhaus' DROP terms), abuse.ch URLhaus / ThreatFox /
Feodo (bulk exports), DShield, Emerging Threats, CINS, IPsum, GreenSnow, blocklist.de, Tor, Team Cymru,
OpenPhish (community feed), Phishing Army, Hagezi, iptoasn.com, and all cloud/service ranges.

## Domain and URL feeds

Set `type = "domain"` or `type = "url"` on a source; a feed's type follows its sources (all must match).
Domains are lower-cased with trailing dots and any scheme/path removed (`*.` wildcards are kept). URLs lose their
scheme and fragment (Palo Alto URL-EDL format; set `strip_scheme = false` to keep it) and entries over 255
characters are skipped.

`[safety] never_block_domains` protects your domains: they and their subdomains never appear in a domain block
feed. In URL feeds only bare-host entries (`example.com/`) are removed, so a specific malicious URL on a shared host
(`s3.amazonaws.com/...`, `raw.githubusercontent.com/...`) is still blocked. A feed's own `exclude` domain source
removes every URL on those hosts.

`/lookup?domain=a.b.example` matches parent-domain entries; `/lookup?url=...` checks URL feeds and the URL's host
against domain feeds.

## Dynamic lists (API)

```toml
[api]
token = "${EDL_API_TOKEN}"

[dynamic.manual_block_ip]
type = "ip"

[feeds.manual-block-ip]
sources = ["manual_block_ip"]
```

```bash
TOKEN=...   # value of EDL_API_TOKEN
# block for 2 hours
curl -X POST http://edl/api/dynamic/manual_block_ip -H "Authorization: Bearer $TOKEN" \
  -d '{"entries": ["198.51.100.7", "2001:db8::bad"], "ttl_minutes": 120, "comment": "ssh brute force"}'
# list / remove
curl -H "Authorization: Bearer $TOKEN" http://edl/api/dynamic/manual_block_ip
curl -X DELETE -H "Authorization: Bearer $TOKEN" "http://edl/api/dynamic/manual_block_ip?entry=198.51.100.7"
```

Entries are validated for the list's type, persisted in `/data/dynamic/`, expire automatically, and the feeds are
rebuilt immediately. `never_block` still applies, so an API call can't block your own networks. Without a token the
API is disabled.

## Access control

```toml
[server]
allow_clients = ["10.2.0.0/16"]                                  # all feeds, /status, /metrics, /lookup, API
basic_auth = { username = "edl", password = "${EDL_FEED_PASSWORD}" }   # all feeds

[feeds.private-list]
sources = ["..."]
allow_clients = ["10.2.1.1/32"]                                  # per-feed override
```

## Config reload and validation

The config file is checked every minute; a changed file is loaded and validated first and only then replaces the
running config (cached data and dynamic lists carry over). A broken edit is logged, alerted, and ignored. Validate
before saving with:

```bash
docker exec edl-aggregator python /app/edl_aggregator.py --check
```

## Bogon feeds

`bogons-v4` / `bogons-v6` publish Team Cymru's *full bogons*; `bogons-v6-compact` is everything outside global
unicast `2000::/3` plus documentation/benchmarking space (7 entries). Full bogons include RFC 1918,
`100.64.0.0/10` (CGNAT, also Tailscale), loopback and multicast, so use bogon feeds **only as a source match on
internet-facing zones**, never on internal zones or as a destination. `never_block` is deliberately not applied
to bogon feeds; use `[sources.bogon_exceptions]` to carve ranges out.

Size: `bogons-v4` is about 3,000 prefixes, but `bogons-v6` is about 150,000, which exceeds the per-list limit of many
firewalls (Palo Alto EDLs are typically capped around 50,000 IP entries per list, varying by model). Prefer
`bogons-v6-compact` unless you know your platform's limit.

## Migrating from MineMeld

The example config reproduces the classic MineMeld inbound setup (Spamhaus DROP/EDROP + DShield → aggregator →
`inboundfeedhc`/`mc`/`lc`) and an AWS S3 output. Give the container MineMeld's old IP address, keep the firewall's
EDL URLs, and add aliases for any custom output node names.

MineMeld feeds used confidence levels; sources here default to confidence 100, so `*mc`/`*lc` feeds are empty
unless you give a source a lower `confidence`.

## Develop

```bash
python -m unittest discover -s tests -v
python edl_aggregator.py --config config.example.toml --data /tmp/edl --once --print threat-ipv6
```

Images are built for `linux/amd64` and `linux/arm64` by GitHub Actions (with SBOM and provenance attestations),
signed with Sigstore cosign (keyless), and published to `ghcr.io/davidcoulson/edl-aggregator` (`latest`, version
tags, and `sha-<commit>`). A weekly rebuild picks up base-image security updates; Dependabot keeps actions and the
base image current. Verify a signature with:

```bash
cosign verify ghcr.io/davidcoulson/edl-aggregator:latest \
  --certificate-identity-regexp 'https://github.com/davidcoulson/edl-aggregator/.github/workflows/docker.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## License

MIT
