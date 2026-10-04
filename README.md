# edl-aggregator

Merge public IP threat feeds and serve them as **External Dynamic Lists** (EDLs) for your firewall.
A lightweight replacement for the most common use of Palo Alto **MineMeld** (discontinued), in one
Python file with no dependencies beyond the standard library.

- Sources: **Spamhaus DROP** (JSON; EDROP is merged into DROP), **DShield** block list, **Team Cymru full bogons**,
  **AWS ip-ranges.json** (filter by service/region), any **plain-text** list (IPs, CIDRs, `a-b` ranges, comments),
  or inline entries.
- Feeds: merge any sources, subtract allow-lists, filter by IP family and confidence, collapse to the fewest CIDRs.
- Safe by default: a source that fails to download, or returns fewer than `min_entries`, keeps its last good copy,
  so an upstream outage never silently empties your block list.
- Serves plain text over HTTP and HTTPS (self-signed certificate generated on first start, or bring your own).
- MineMeld-compatible URLs: `/feeds/<name>`, query strings like `?tr=1&v=panosurl` are accepted and ignored, and
  feeds can have **aliases** so a firewall pointed at old MineMeld feed names keeps working.

Works with Palo Alto EDLs, pfSense/OPNsense URL table aliases, FortiGate external threat feeds, or anything
that can poll a URL for a list of networks.

## Run

```bash
docker run -d --name edl-aggregator \
  -p 80:80 -p 443:443 \
  -v /path/to/config:/config -v /path/to/data:/data \
  ghcr.io/davidcoulson/edl-aggregator:latest
```

On first start an example config is written to `/config/config.toml`. Edit it and restart the container.

| Path | What |
|---|---|
| `/` | index of feeds with entry counts |
| `/feeds/<name>` | the list, one CIDR per line (`.txt` suffix optional) |
| `/status`, `/healthz` | JSON status of every source and feed; HTTP 503 if a required source has no data |

| Environment | Default | |
|---|---|---|
| `CONFIG` | `/config/config.toml` | config file |
| `DATA_DIR` | `/data` | cache of last good source data, generated TLS cert |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | `0` disables a listener |
| `TLS_CERT` / `TLS_KEY` | `/data/tls/cert.pem`, `key.pem` | created self-signed if missing |
| `LOG_LEVEL` | `INFO` | |

## Configure

See [`config.example.toml`](config.example.toml). In short:

```toml
refresh_minutes = 60

[sources.spamhaus_drop_v4]
url = "https://www.spamhaus.org/drop/drop_v4.json"
format = "spamhaus-json"
min_entries = 100

[sources.dshield]
url = "https://feeds.dshield.org/block.txt"
format = "dshield"

[sources.allowlist]
entries = ["203.0.113.0/24"]

[feeds.inbound-block-v4]
sources = ["spamhaus_drop_v4", "dshield"]
exclude = ["allowlist"]
family = "ipv4"
aliases = ["inboundfeedhc"]      # old MineMeld name
```

Source formats: `plain`, `spamhaus-json`, `dshield`, `aws-json` (`service`, `region` filters).

## Bogon feeds

`bogons-v4` / `bogons-v6` publish Team Cymru's *full bogons*: unallocated and reserved address space. They include
RFC 1918, `100.64.0.0/10` (CGNAT, also Tailscale), loopback and multicast, so use them **only as a source match on
internet-facing zones** (drop spoofed or unallocated sources from outside), never on internal zones or as a
destination. Add ranges to `[sources.bogon_exceptions]` to carve anything out.

Size: `bogons-v4` is about 3,000 prefixes, but `bogons-v6` is about 150,000, which exceeds the per-list limit of many
firewalls (e.g. Palo Alto EDLs are typically capped around 50,000 IP entries per list, varying by model). Check your
platform's limit before using the IPv6 list.

## Migrating from MineMeld

The example config reproduces the classic MineMeld inbound setup (Spamhaus DROP/EDROP + DShield → aggregator →
`inboundfeedhc`/`mc`/`lc`) and an AWS S3 output. Give the container MineMeld's old IP address, keep the firewall's
EDL URLs, and add aliases for any custom output node names.

Note: MineMeld feeds used confidence levels; sources here default to confidence 100, so `*mc`/`*lc` feeds are
empty unless you give a source a lower `confidence`.

## Develop

```bash
python -m unittest discover -s tests -v
python edl_aggregator.py --config config.example.toml --data /tmp/edl --once --print inbound-block-v4
```

Images are built for `linux/amd64` and `linux/arm64` by GitHub Actions and published to
`ghcr.io/davidcoulson/edl-aggregator` (`latest`, version tags, and short SHA). A weekly rebuild picks up base-image
security updates.

## License

MIT
