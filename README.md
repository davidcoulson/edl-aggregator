# edl-aggregator

Merge public IP threat feeds and service ranges and serve them as **External Dynamic Lists** (EDLs) for your
firewall. A lightweight replacement for the most common use of Palo Alto **MineMeld** (discontinued), in one
Python file with no dependencies beyond the standard library.

Works with Palo Alto EDLs, pfSense/OPNsense URL table aliases, FortiGate external threat feeds, or anything
that can poll a URL for a list of networks.

## Features

- **Sources**: Spamhaus DROP (v4/v6), DShield, Emerging Threats, CINS Army, IPsum, GreenSnow, blocklist.de,
  abuse.ch Feodo, Tor exits (v4/v6), AbuseIPDB (API key), Team Cymru bogons, AWS / Cloudflare / Google /
  Google Cloud / GitHub / Fastly / Microsoft 365 / UptimeRobot ranges - or any plain-text or JSON list.
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
| `/` | index of feeds by kind, with entry counts |
| `/feeds/<name>` | the list, one CIDR per line (`.txt` suffix optional); ETag/Last-Modified, 304 support |
| `/status`, `/healthz` | JSON status of every source and feed; HTTP 503 if a required source has no data |
| `/metrics` | Prometheus metrics: entries per feed/source, source up/failures/last success, overflow |
| `/lookup?ip=<addr>` | which feeds and sources contain an address, and whether it is in `never_block` |

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

Source formats: `plain`, `spamhaus-json`, `dshield`, `aws-json` (`service`, `region`), and `json` with `paths`
(`"prefixes[].ipv6Prefix"`, `"[].ips[]"`; `[]` iterates a list) and an optional `where` filter. Entries may be IPs,
CIDRs, `a-b` ranges, `[v6]:port` or `v4:port`.

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

Images are built for `linux/amd64` and `linux/arm64` by GitHub Actions (with SBOM and provenance attestations) and
published to `ghcr.io/davidcoulson/edl-aggregator` (`latest`, version tags, and `sha-<commit>`). A weekly rebuild
picks up base-image security updates; Dependabot keeps actions and the base image current.

## License

MIT
