#!/usr/bin/env python3
"""edl-aggregator: fetch threat feeds, merge them, and serve External Dynamic Lists (EDLs).

A small replacement for Palo Alto MineMeld's most common use: pull public feeds of IP addresses,
domains and URLs (Spamhaus DROP, DShield, Team Cymru bogons, Tor, abuse.ch URLhaus/ThreatFox,
OpenPhish, cloud/service ranges, plain-text, hosts-file and JSON lists), combine and de-duplicate them,
remove allow-listed entries, and publish one plain-text list per feed for a firewall to poll
(Palo Alto IP/domain/URL EDLs, pfSense/OPNsense URL tables, FortiGate threat feeds, ...).

Standard library only. Configuration is a TOML file; see config.example.toml.

Safety rules:
  * A source that fails to download, parses to fewer than `min_entries`, or shrinks by more than
    `max_shrink_percent` keeps its last good data (cached on disk). Block lists never empty themselves
    because an upstream had a bad day.
  * `[safety] never_block` (IPs) and `never_block_domains` are removed from every block feed, so your own
    addresses and domains can't be blocked by a bad upstream entry or a careless API call.
  * A feed over its `max_entries` keeps serving its previous build (or serves anyway, if configured).
  * Feeds are rebuilt in memory and swapped atomically; readers never see a half-built list.
  * A config change is applied only if the new file is valid; otherwise the running config stays.
"""

import argparse
import base64
import csv
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

__version__ = "1.5.2"

log = logging.getLogger("edl-aggregator")
USER_AGENT = f"edl-aggregator/{__version__} (+https://github.com/davidcoulson/edl-aggregator)"
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
TYPES = ("ip", "domain", "url")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expand_env(value):
    """Replace ${VAR} with the environment variable (empty if unset). Recurses into dicts; strings only."""
    if isinstance(value, str):
        return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def render_url(url: str) -> str:
    """Fill time placeholders at fetch time: {days_ago:N} -> UTC timestamp N days ago (YYYY-MM-DDTHH:MM:SS)."""
    return re.sub(r"\{days_ago:(\d+)\}", lambda m: (datetime.now(timezone.utc) - timedelta(days=int(m.group(1))))
                  .strftime("%Y-%m-%dT%H:%M:%S"), url or "")


RETRY_BACKOFF_SECONDS = 5


def http_get(url: str, headers: dict, timeout: int, retries: int = 2):
    """GET with retries on timeouts, connection errors and 5xx (not 4xx / 304). Returns (text, response headers)."""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace"), resp.headers
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == retries:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            if attempt == retries:
                raise
        time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))


# --------------------------------------------------------------------------- indicators

DOMAIN_RE = re.compile(r"^(\*\.)?(?=.{1,253}$)((?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")


def parse_ip(token: str) -> list[Network]:
    """IP, CIDR, 'a.b.c.d-e.f.g.h' range, '[v6]:port' or 'v4:port' -> networks. Raises ValueError if invalid."""
    token = token.strip()
    if token.startswith("["):                       # [2001:db8::1]:9001
        token = token[1:token.index("]")]
    elif token.count(":") == 1 and "." in token:    # 192.0.2.1:9001
        token = token.split(":", 1)[0]
    if "-" in token and "/" not in token:
        start, end = (ipaddress.ip_address(p.strip()) for p in token.split("-", 1))
        return list(ipaddress.summarize_address_range(start, end))
    return [ipaddress.ip_network(token, strict=False)]


parse_entry = parse_ip   # backwards-compatible name


def normalize_domain(token: str) -> str:
    """Lower-case, strip a trailing dot and any scheme/path. Raises ValueError if not a domain (IPs too)."""
    d = token.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not DOMAIN_RE.match(d):
        raise ValueError(f"not a domain: {token!r}")
    try:
        ipaddress.ip_address(d)
        raise ValueError(f"IP address, not a domain: {token!r}")
    except ValueError as e:
        if "IP address" in str(e):
            raise
    return d


def normalize_url(token: str, strip_scheme: bool = True, max_length: int = 255) -> str:
    """URL for an EDL: no scheme (Palo Alto format), no fragment, lower-case host. Raises ValueError if invalid."""
    u = token.strip()
    if not u or " " in u:
        raise ValueError(f"not a URL: {token!r}")
    scheme = ""
    if "://" in u:
        scheme, u = u.split("://", 1)
        scheme = scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {token!r}")
    u = u.split("#", 1)[0]
    host, sep, rest = u.partition("/")
    if not host:
        raise ValueError(f"no host: {token!r}")
    u = host.lower() + sep + rest
    if not strip_scheme and scheme:
        u = f"{scheme}://{u}"
    if max_length and len(u) > max_length:
        raise ValueError(f"longer than {max_length} characters")
    return u


def url_host(u: str) -> str:
    u = u.split("://", 1)[-1]
    host = u.split("/", 1)[0]
    return host[1:host.index("]")] if host.startswith("[") else host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def domain_covers(parent: str, child: str) -> bool:
    """True if `child` equals `parent` or is a subdomain of it (wildcard prefixes ignored)."""
    parent, child = parent.removeprefix("*."), child.removeprefix("*.")
    return child == parent or child.endswith("." + parent)


def to_items(itype: str, tokens, opts: dict) -> list:
    out = []
    for t in tokens:
        try:
            if itype == "ip":
                out.extend(parse_ip(t))
            elif itype == "domain":
                out.append(normalize_domain(t))
            else:
                out.append(normalize_url(t, opts.get("strip_scheme", True), int(opts.get("max_length", 255))))
        except ValueError:
            log.debug("%s: skipping %r", itype, t)
    return out


def collapse_items(itype: str, items) -> list:
    items = list(items)
    if itype == "ip":
        v4 = ipaddress.collapse_addresses(n for n in items if n.version == 4)
        v6 = ipaddress.collapse_addresses(n for n in items if n.version == 6)
        return list(v4) + list(v6)
    return sorted(set(items))


collapse = lambda networks: collapse_items("ip", networks)   # noqa: E731  (backwards-compatible name)


def subtract(networks: list[Network], excludes: list[Network]) -> list[Network]:
    """Remove every address in `excludes` from `networks` (splitting networks where needed)."""
    by_version = {4: [e for e in excludes if e.version == 4], 6: [e for e in excludes if e.version == 6]}
    result = []
    for net in networks:
        pieces = [net]
        for ex in by_version[net.version]:
            if not net.overlaps(ex):
                continue
            nxt = []
            for p in pieces:
                if p.subnet_of(ex):
                    continue                           # fully excluded
                if ex.subnet_of(p):
                    nxt.extend(p.address_exclude(ex))  # punch a hole
                else:
                    nxt.append(p)
            pieces = nxt
        result.extend(pieces)
    return result


def exclude_items(itype: str, items: list, excludes: list, never_domains: list[str] = ()) -> list:
    """Remove excluded entries from a domain or URL list.

    `excludes` (feed allow-lists): domains remove the domain, its subdomains, and every URL on them;
    entries containing '/' are URL prefixes. `never_domains` ([safety] never_block_domains): in domain feeds
    they remove the domain and subdomains; in URL feeds only bare-host entries ("google.com/"), so a specific
    malicious path on a big shared host (s3.amazonaws.com/..., raw.githubusercontent.com/...) stays blocked."""
    if itype == "ip":
        return subtract(items, excludes)
    doms = [d for d in excludes if "/" not in d]
    prefixes = [x for x in excludes if "/" in x]                 # URL-prefix exclusions
    out = []
    for it in items:
        host = it if itype == "domain" else url_host(it)
        if any(domain_covers(d, host) for d in doms):
            continue
        if itype == "url" and any(it.startswith(p) for p in prefixes):
            continue
        bare = itype == "domain" or it.split("/", 1)[1:] in ([], [""])
        if bare and any(domain_covers(d, host) for d in never_domains):
            continue
        out.append(it)
    return out


def item_matches(itype: str, items: list, query) -> list:
    """Entries in `items` that match `query` (an ip_address, a domain, or a URL)."""
    if itype == "ip":
        return [str(n) for n in items if isinstance(query, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                and query.version == n.version and query in n]
    if isinstance(query, str):
        host = url_host(query)
        if itype == "domain":
            return [d for d in items if domain_covers(d, host)]
        return [u for u in items if query.startswith(u)]
    return []


def contains(networks: list[Network], ip) -> bool:   # backwards-compatible helper
    return bool(item_matches("ip", networks, ip))


# --------------------------------------------------------------------------- parsers (text -> tokens)

def parse_plain(text: str, item_type: str = "ip", **_) -> list[str]:
    """One entry per line. Comments start with '#', ';' or '//'. Only the first token is used (for URLs:
    the first whitespace-separated token, since URLs may contain ';', ',' or '#')."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//", "!")):
            continue
        out.append(line.split()[0] if item_type == "url" else re.split(r"[\s;,#]", line, maxsplit=1)[0])
    return out


def parse_hosts(text: str, **_) -> list[str]:
    """Hosts-file format: '0.0.0.0 bad.example' or '127.0.0.1 bad.example other.example'."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        out.extend(f for f in fields[1:] if f not in ("localhost", "localhost.localdomain", "broadcasthost"))
    return out


def parse_spamhaus_json(text: str, **_) -> list[str]:
    """Spamhaus DROP JSON (drop_v4.json / drop_v6.json): one JSON object per line with a 'cidr' key."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "cidr" in obj:
            out.append(obj["cidr"])
    return out


def parse_dshield(text: str, **_) -> list[str]:
    """DShield block.txt: tab-separated 'start  end  bits  attacks ...'; '#' comments and a 'Start' header."""
    out = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or line.startswith("Start"):
            continue
        f = line.split()
        if len(f) >= 3:
            out.append(f"{f[0]}/{f[2]}")
    return out


def parse_aws_json(text: str, service=None, region=None, **_) -> list[str]:
    """AWS ip-ranges.json, optionally filtered by service (e.g. "S3") and region (str or list)."""
    data = json.loads(text)
    services = {service} if isinstance(service, str) else set(service or [])
    regions = {region} if isinstance(region, str) else set(region or [])
    out = []
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for p in data.get(key, []):
            if services and p.get("service") not in services:
                continue
            if regions and p.get("region") not in regions:
                continue
            out.append(p[field])
    return out


def _walk(node, segments: list[str], where: dict):
    """Yield leaf strings of a JSON document along a path like 'prefixes[].ipv6Prefix' or '[].ips[]'."""
    if isinstance(node, dict) and where:
        for k, want in where.items():
            if k in node and node[k] not in (want if isinstance(want, list) else [want]):
                return
    if not segments:
        if isinstance(node, list):
            yield from (v for v in node if isinstance(v, str))
        elif isinstance(node, str):
            yield node
        return
    seg, rest = segments[0], segments[1:]
    key, many = (seg[:-2], True) if seg.endswith("[]") else (seg, False)
    if key:
        if not isinstance(node, dict) or key not in node:
            return
        node = node[key]
    if many:
        if isinstance(node, list):
            for item in node:
                yield from _walk(item, rest, where)
    else:
        yield from _walk(node, rest, where)


def json_values(text: str, paths, where=None) -> list[str]:
    data = json.loads(text)
    out = []
    for path in paths:
        out.extend(_walk(data, [s for s in path.split(".") if s], where or {}))
    return out


def parse_json(text: str, paths=None, where=None, **_) -> list[str]:
    """Generic JSON: `paths` like ["prefixes[].ipv4Prefix", "hooks[]", "[].ips[]"]; `[]` iterates a list.
    `where` (optional) skips any object whose listed keys don't match, e.g. {category = ["Optimize", "Allow"]}."""
    if not paths:
        raise ValueError("format 'json' needs 'paths'")
    data = json.loads(text)
    out = []
    for path in paths:
        out.extend(_walk(data, [s for s in path.split(".") if s], where or {}))
    return out


def parse_csv(text: str, column=0, min_column=None, min_value=None, delimiter=",", **_) -> list[str]:
    """CSV: take `column` (0-based index). Lines starting with '#' are skipped. Optional numeric threshold:
    keep rows where column `min_column` >= `min_value` (e.g. ThreatFox confidence_level)."""
    out = []
    rows = csv.reader((l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")),
                      delimiter=delimiter, skipinitialspace=True)
    for row in rows:
        if len(row) <= int(column):
            continue
        if min_column is not None and min_value is not None:
            try:
                if float(row[int(min_column)]) < float(min_value):
                    continue
            except (ValueError, IndexError):
                continue
        out.append(row[int(column)].strip())
    return out


def parse_spamhaus_asn_json(text: str, **_) -> list[str]:
    """Spamhaus ASN-DROP (asndrop.json): one JSON object per line with an 'asn' key -> ['AS123', ...]."""
    out = []
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "asn" in obj:
            out.append(f"AS{obj['asn']}")
    return out


ASN_DB_DEFAULT = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
_asn_db_lock = threading.Lock()


def asn_ranges(asns: list[str], db_url: str, cache_dir: Path, refresh_minutes: float, timeout: int) -> list[str]:
    """Expand ASNs ('AS123' or '123') to the IP ranges they announce, using an ip2asn-style TSV
    (start, end, asn, ...; optionally gzipped). The database is cached on disk and re-downloaded when older
    than `refresh_minutes`; a failed download falls back to the cached copy."""
    wanted = {re.sub(r"(?i)^as", "", a.strip()) for a in asns if a.strip()}
    path = cache_dir / f"asn-db-{hashlib.sha256(db_url.encode()).hexdigest()[:12]}.tsv"
    with _asn_db_lock:
        stale = not path.exists() or time.time() - path.stat().st_mtime > refresh_minutes * 60
        if stale:
            try:
                req = urllib.request.Request(db_url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=max(timeout, 120)) as resp:
                    data = resp.read()
                if data[:2] == b"\x1f\x8b":
                    data = gzip.decompress(data)
                if data.count(b"\n") < 1000:
                    raise ValueError("ASN database looks truncated")
                tmp = path.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(path)
                log.info("ASN database refreshed from %s (%d lines)", db_url, data.count(b"\n"))
            except Exception as e:
                if not path.exists():
                    raise RuntimeError(f"ASN database unavailable: {e}") from e
                log.warning("ASN database refresh failed, using cached copy: %s", e)
        out = []
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                f = line.split("\t", 3)
                if len(f) >= 3 and f[2] in wanted:
                    out.append(f"{f[0]}-{f[1]}")
    return out


PARSERS = {
    "plain": parse_plain,
    "hosts": parse_hosts,
    "csv": parse_csv,
    "spamhaus-json": parse_spamhaus_json,
    "spamhaus-asn-json": parse_spamhaus_asn_json,
    "dshield": parse_dshield,
    "aws-json": parse_aws_json,
    "json": parse_json,
}
SOURCE_KEYS = {"url", "entries", "format", "type", "confidence", "min_entries", "enabled", "refresh_minutes",
               "headers", "max_shrink_percent", "description", "timeout", "dynamic", "expand_asns",
               "asn_database", "asn_database_refresh_minutes", "next_page", "max_pages", "retries"}


# --------------------------------------------------------------------------- alerts

class Alerter:
    """POSTs a JSON {title, body, type} message to a webhook (e.g. an Apprise API /notify/<key> URL)."""

    def __init__(self, cfg: dict):
        self.url = expand_env(cfg.get("webhook_url", ""))
        self.after = int(cfg.get("after_failures", 3))
        self.headers = expand_env(cfg.get("headers", {}))

    def send(self, title: str, body: str, kind: str = "warning"):
        (log.info if kind == "success" else log.warning)("ALERT %s: %s", title, body)
        if not self.url:
            return

        def post():
            try:
                data = json.dumps({"title": title, "body": body, "type": kind}).encode()
                req = urllib.request.Request(self.url, data=data, method="POST",
                                             headers={"Content-Type": "application/json", "User-Agent": USER_AGENT,
                                                      **self.headers})
                urllib.request.urlopen(req, timeout=20).read()
            except Exception as e:
                log.error("alert webhook failed: %s", e)
        threading.Thread(target=post, daemon=True).start()


# --------------------------------------------------------------------------- sources

class Source:
    def __init__(self, name: str, cfg: dict, data_dir: Path, defaults: dict):
        self.name = name
        self.cfg = cfg
        self.type = cfg.get("type", "ip")
        self.dynamic = bool(cfg.get("dynamic", False))
        self.url = expand_env(cfg.get("url"))
        self.entries_static = cfg.get("entries")              # inline list instead of a URL
        self.format = cfg.get("format", "plain")
        self.enabled = bool(cfg.get("enabled", True))
        self.confidence = int(cfg.get("confidence", 100))
        self.min_entries = int(cfg.get("min_entries", 1 if self.url else 0))
        self.refresh_minutes = float(cfg.get("refresh_minutes", defaults["refresh_minutes"]))
        self.max_shrink = float(cfg.get("max_shrink_percent", defaults["max_shrink_percent"]))
        self.timeout = int(cfg.get("timeout", 60))
        self.headers = expand_env(cfg.get("headers", {}))
        self.expand_asns = bool(cfg.get("expand_asns", self.format == "spamhaus-asn-json"))
        self.asn_db_url = expand_env(cfg.get("asn_database", ASN_DB_DEFAULT))
        self.asn_db_refresh = float(cfg.get("asn_database_refresh_minutes", 1440))
        self.next_page = cfg.get("next_page")                  # json path to the next page's URL (paginated APIs)
        self.max_pages = int(cfg.get("max_pages", 100))
        self.retries = int(cfg.get("retries", 2))
        self.backoff_until = 0.0                               # set by HTTP 429 / Retry-After
        self.opts = {k: v for k, v in cfg.items() if k not in SOURCE_KEYS}
        self.cache = data_dir / "cache" / f"{name}.txt"
        self.meta_file = data_dir / "cache" / f"{name}.json"
        self.dyn_file = data_dir / "dynamic" / f"{name}.json"
        self.items: list = []
        self.meta: dict = {}
        self.failures = 0
        self.last_attempt = 0.0
        self.lock = threading.Lock()
        self.dyn: dict[str, dict] = {}                         # dynamic: entry -> {added, expires, comment}
        self.status = {"name": name, "type": self.type, "url": self.url, "enabled": self.enabled,
                       "dynamic": self.dynamic, "ok": None, "count": 0, "fetched_at": None, "checked_at": None,
                       "error": None, "consecutive_failures": 0}
        if self.type not in TYPES:
            raise ValueError(f"source {name}: type must be one of {', '.join(TYPES)}")
        if self.expand_asns and self.type != "ip":
            raise ValueError(f"source {name}: expand_asns only works for type = ip")
        if self.format not in PARSERS:
            raise ValueError(f"source {name}: unknown format {self.format!r} (use one of {', '.join(PARSERS)})")
        if self.enabled and not self.url and self.entries_static is None and not self.dynamic:
            raise ValueError(f"source {name}: needs 'url', 'entries' or 'dynamic = true'"
                             + (" (url is empty - is its ${...} environment variable set?)" if "url" in cfg else ""))
        if self.dynamic:
            self._load_dynamic()
        elif self.entries_static is not None:
            self._load_static()
        else:
            self._load_cache()

    @property
    def networks(self):          # backwards-compatible name for IP sources
        return self.items

    @property
    def required(self) -> bool:
        return self.enabled and self.min_entries > 0 and not self.dynamic

    def _from_lines(self, lines) -> list:
        if self.type == "ip":
            return [ipaddress.ip_network(l) for l in lines if l]
        return [l for l in lines if l]

    def _load_cache(self):
        if self.cache.exists():
            self.items = self._from_lines(self.cache.read_text().split())
            self.status["count"] = len(self.items)
        if self.meta_file.exists():
            try:
                self.meta = json.loads(self.meta_file.read_text())
            except json.JSONDecodeError:
                self.meta = {}
            self.status["fetched_at"] = self.meta.get("fetched_at")
            self.status["checked_at"] = self.meta.get("checked_at")
            if self.items and self.meta.get("checked_at"):
                self.status["ok"] = True

    def _load_static(self):
        self.items = collapse_items(self.type, to_items(self.type, [str(e) for e in self.entries_static], self.opts))
        self.status.update(ok=True, count=len(self.items), error=None, fetched_at=now_iso(), checked_at=now_iso())

    # -- dynamic lists

    def _load_dynamic(self):
        if self.dyn_file.exists():
            try:
                self.dyn = json.loads(self.dyn_file.read_text())
            except json.JSONDecodeError:
                log.error("dynamic list %s: unreadable %s, starting empty", self.name, self.dyn_file)
                self.dyn = {}
        self._dyn_apply()

    def _dyn_apply(self):
        self.items = collapse_items(self.type, to_items(self.type, list(self.dyn), self.opts))
        self.status.update(ok=True, count=len(self.items), error=None, checked_at=now_iso())

    def _dyn_save(self):
        self.dyn_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.dyn_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.dyn, indent=1, sort_keys=True))
        tmp.replace(self.dyn_file)

    def dyn_add(self, entries: list[str], ttl_minutes: float | None, comment: str = "") -> dict:
        added, rejected = [], []
        now = time.time()
        with self.lock:
            for raw in entries:
                ok = to_items(self.type, [str(raw)], self.opts)
                if not ok:
                    rejected.append(raw)
                    continue
                key = str(ok[0]) if self.type != "ip" or len(ok) == 1 else str(raw).strip()
                self.dyn[key] = {"added": now_iso(), "comment": comment,
                                 "expires": now + ttl_minutes * 60 if ttl_minutes else None}
                added.append(key)
            self._dyn_save()
            self._dyn_apply()
        return {"added": added, "rejected": rejected}

    def dyn_remove(self, entries: list[str]) -> dict:
        removed = []
        with self.lock:
            for raw in entries:
                for key in {str(raw).strip(), *(str(x) for x in to_items(self.type, [str(raw)], self.opts))}:
                    if self.dyn.pop(key, None) is not None:
                        removed.append(key)
            self._dyn_save()
            self._dyn_apply()
        return {"removed": removed}

    def dyn_expire(self) -> bool:
        now = time.time()
        with self.lock:
            gone = [k for k, v in self.dyn.items() if v.get("expires") and v["expires"] <= now]
            for k in gone:
                del self.dyn[k]
            if gone:
                log.info("dynamic list %s: expired %d entries", self.name, len(gone))
                self._dyn_save()
                self._dyn_apply()
        return bool(gone)

    def dyn_list(self) -> dict:
        with self.lock:
            return {k: {**v, "expires": datetime.fromtimestamp(v["expires"], timezone.utc).isoformat(timespec="seconds")
                        if v.get("expires") else None} for k, v in sorted(self.dyn.items())}

    # -- fetching

    def due(self, now: float) -> bool:
        if not self.enabled or not self.url:
            return False
        if now < self.backoff_until:           # rate-limited by the upstream: wait as long as it asked
            return False
        if self.failures:   # retry failed sources sooner: 5 minutes, but never more often than the interval
            return now - self.last_attempt >= min(300, self.refresh_minutes * 60)
        return now - self.meta.get("checked_ts", 0) >= self.refresh_minutes * 60

    def _fail(self, error: str):
        self.failures += 1
        self.status.update(ok=False, error=error, consecutive_failures=self.failures)
        log.warning("source %s: %s (keeping %d cached entries)", self.name, error, len(self.items))

    def refresh(self) -> bool:
        """Download, parse and validate. Returns True if the source's data changed."""
        self.last_attempt = time.time()
        headers = {"User-Agent": USER_AGENT, **self.headers}
        if self.items and self.meta.get("etag"):
            headers["If-None-Match"] = self.meta["etag"]
        if self.items and self.meta.get("last_modified"):
            headers["If-Modified-Since"] = self.meta["last_modified"]
        try:
            text, rh = http_get(render_url(self.url), headers, self.timeout, self.retries)
            etag, last_mod = rh.get("ETag"), rh.get("Last-Modified")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                self._mark_checked()
                log.info("source %s: not modified", self.name)
                return False
            if e.code in (429, 503):
                retry_after = e.headers.get("Retry-After", "") if e.headers else ""
                wait = int(retry_after) if retry_after.isdigit() else self.refresh_minutes * 60
                self.backoff_until = time.time() + max(wait, 300)
                self._fail(f"HTTP {e.code} {e.reason} - backing off {max(wait, 300) // 60:.0f} min")
                return False
            self._fail(f"HTTP {e.code} {e.reason}")
            return False
        except Exception as e:
            self._fail(f"{type(e).__name__}: {e}")
            return False
        pages = [text]
        if self.next_page:                                     # follow "next" links (e.g. AlienVault OTX)
            try:
                nxt = next(iter(json_values(text, [self.next_page])), None)
                while nxt and len(pages) < self.max_pages:
                    page, _ = http_get(nxt, {"User-Agent": USER_AGENT, **self.headers}, self.timeout, self.retries)
                    pages.append(page)
                    nxt = next(iter(json_values(page, [self.next_page])), None)
            except Exception as e:
                self._fail(f"page {len(pages) + 1}: {type(e).__name__}: {e}")
                return False
        try:
            tokens = [t for page in pages for t in PARSERS[self.format](page, item_type=self.type, **self.opts)]
            raw_tokens = len(tokens)
            if self.expand_asns:
                tokens = asn_ranges(tokens, self.asn_db_url, self.cache.parent, self.asn_db_refresh, self.timeout)
            parsed = to_items(self.type, tokens, self.opts)
        except Exception as e:
            self._fail(f"parse error: {type(e).__name__}: {e}")
            return False
        # Size checks use the raw entry count from upstream: collapsing can legitimately merge thousands of
        # adjacent addresses into a few prefixes. For ASN lists that is the number of ASNs.
        raw = raw_tokens if self.expand_asns else len(parsed)
        if raw < self.min_entries:
            self._fail(f"only {raw} entries (min_entries={self.min_entries})")
            return False
        old = self.meta.get("raw_count") or len(self.items)
        if old and self.max_shrink < 100 and raw < old * (1 - self.max_shrink / 100):
            self._fail(f"shrank from {old} to {raw} entries (more than max_shrink_percent={self.max_shrink:g})")
            return False
        items = collapse_items(self.type, parsed)
        changed = items != self.items
        self.items = items
        if changed:
            tmp = self.cache.with_suffix(".tmp")
            tmp.write_text("".join(f"{i}\n" for i in items))
            tmp.replace(self.cache)
            self.meta["fetched_at"] = now_iso()
        self.meta.update(etag=etag, last_modified=last_mod, count=len(items), raw_count=raw, url=self.url)
        self._mark_checked()
        self.status.update(fetched_at=self.meta.get("fetched_at"), count=len(items))
        log.info("source %s: %d %s entries%s", self.name, len(items), self.type, "" if changed else " (unchanged)")
        return changed

    def _mark_checked(self):
        self.failures = 0
        self.meta.update(checked_at=now_iso(), checked_ts=time.time())
        self.meta_file.write_text(json.dumps(self.meta))
        self.status.update(ok=True, error=None, checked_at=self.meta["checked_at"], consecutive_failures=0)


# --------------------------------------------------------------------------- feeds

class Feed:
    KINDS = ("block", "allow", "bogon")

    def __init__(self, name: str, cfg: dict, sources: dict, server: dict):
        self.name = name
        self.inputs = cfg.get("sources", [])
        self.excludes = cfg.get("exclude", [])
        self.family = cfg.get("family", "both")          # ip only: ipv4 | ipv6 | both
        self.kind = cfg.get("kind", "block")              # block | allow | bogon  (never_block applies to block)
        self.min_conf = int(cfg.get("min_confidence", 0))
        self.max_conf = int(cfg.get("max_confidence", 100))
        self.max_entries = int(cfg.get("max_entries", 0))
        self.overflow = cfg.get("overflow", "keep-last")  # keep-last | serve
        self.aliases = cfg.get("aliases", [])
        self.description = cfg.get("description", "")
        self.basic_auth = expand_env(cfg.get("basic_auth", server.get("basic_auth")))
        self.allow_clients = [ipaddress.ip_network(c, strict=False)
                              for c in cfg.get("allow_clients", server.get("allow_clients", []))]
        if not self.inputs:
            raise ValueError(f"feed {name}: needs at least one source")
        for s in self.inputs + self.excludes:
            if s not in sources:
                raise ValueError(f"feed {name}: unknown source {s!r}")
        types = {sources[s].type for s in self.inputs}
        if len(types) != 1:
            raise ValueError(f"feed {name}: sources mix types {sorted(types)}; a feed is ip, domain or url")
        self.type = types.pop()
        for s in self.excludes:
            st = sources[s].type
            if st != self.type and not (self.type == "url" and st == "domain"):
                raise ValueError(f"feed {name}: cannot exclude {st} source {s!r} from a {self.type} feed")
        if self.family not in ("ipv4", "ipv6", "both"):
            raise ValueError(f"feed {name}: family must be ipv4, ipv6 or both")
        if self.kind not in self.KINDS:
            raise ValueError(f"feed {name}: kind must be one of {', '.join(self.KINDS)}")
        if self.overflow not in ("keep-last", "serve"):
            raise ValueError(f"feed {name}: overflow must be keep-last or serve")
        if self.basic_auth and not (self.basic_auth.get("username") and self.basic_auth.get("password")):
            raise ValueError(f"feed {name}: basic_auth needs username and password")

    def build(self, sources: dict, never_block: list, never_block_domains: list[str]) -> list:
        items = []
        for s in self.inputs:
            src = sources[s]
            if src.enabled and self.min_conf <= src.confidence <= self.max_conf:
                items.extend(src.items)
        if self.type == "ip" and self.family != "both":
            want = 4 if self.family == "ipv4" else 6
            items = [n for n in items if n.version == want]
        excl = [i for s in self.excludes for i in sources[s].items]
        if self.type == "ip":
            excl = [i for i in excl if not isinstance(i, str)]
            if self.kind == "block":
                excl += never_block
            return collapse_items("ip", subtract(collapse_items("ip", items), excl))
        excl = [str(i) for i in excl]
        return exclude_items(self.type, collapse_items(self.type, items), excl,
                             never_block_domains if self.kind == "block" else [])


class Published:
    """One built feed, immutable once created."""

    def __init__(self, items: list, overflow: bool = False):
        self.items = items
        self.text = "".join(f"{i}\n" for i in items)
        self.body = self.text.encode()
        self.etag = '"' + hashlib.sha256(self.body).hexdigest()[:32] + '"'
        self.last_modified = time.time()
        self.overflow = overflow

    @property
    def networks(self):
        return self.items

    @property
    def count(self):
        return len(self.items)


# --------------------------------------------------------------------------- aggregator

class Aggregator:
    def __init__(self, config: dict, data_dir: Path, alerter: Alerter | None = None):
        self.config = config
        self.data_dir = data_dir
        safety = config.get("safety", {})
        self.server = config.get("server", {})
        self.api_token = expand_env(config.get("api", {}).get("token", ""))
        self.parallel = max(1, int(config.get("parallel_fetches", 6)))
        self.defaults = {"refresh_minutes": float(config.get("refresh_minutes", 60)),
                         "max_shrink_percent": float(safety.get("max_shrink_percent", 50))}
        self.never_block = collapse_items("ip", (n for e in safety.get("never_block", []) for n in parse_ip(str(e))))
        self.never_block_domains = [normalize_domain(d) for d in safety.get("never_block_domains", [])]
        self.alerter = alerter or Alerter(config.get("alerts", {}))
        (data_dir / "cache").mkdir(parents=True, exist_ok=True)
        srcs = dict(config.get("sources", {}))
        for name, dcfg in config.get("dynamic", {}).items():      # [dynamic.<name>] = shorthand for a dynamic source
            if name in srcs:
                raise ValueError(f"dynamic list {name}: a source with that name already exists")
            srcs[name] = {**dcfg, "dynamic": True}
        self.sources = {n: Source(n, c, data_dir, self.defaults) for n, c in srcs.items()}
        self.feeds = {n: Feed(n, c, self.sources, self.server) for n, c in config.get("feeds", {}).items()}
        self.lock = threading.Lock()
        self.published: dict[str, Published] = {}     # feed name -> build
        self.names: dict[str, str] = {}               # feed name or alias -> feed name
        self.last_build = None
        self.alerted: set[str] = set()
        self.rebuild()   # serve cached data immediately at start-up

    # -- refresh / build

    def tick(self, force: bool = False) -> bool:
        """Refresh due sources (all enabled URL sources if force), expire dynamic entries, rebuild if changed."""
        now = time.time()
        changed = False
        for s in self.sources.values():
            if s.dynamic:
                changed |= s.dyn_expire()
        due = [s for s in self.sources.values() if not s.dynamic and s.url and s.enabled and (force or s.due(now))]
        if due:   # download in parallel so one slow upstream doesn't hold up the rest
            with ThreadPoolExecutor(max_workers=self.parallel, thread_name_prefix="fetch") as pool:
                results = list(pool.map(lambda src: src.refresh(), due))
            changed |= any(results)
            for s in due:
                self._check_alert(s)
        if changed or not self.published:
            self.rebuild()
        return changed

    def _check_alert(self, s: Source):
        if s.failures >= self.alerter.after and s.name not in self.alerted:
            self.alerted.add(s.name)
            self.alerter.send(f"edl-aggregator: source {s.name} failing",
                              f"{s.failures} consecutive failures: {s.status['error']}. "
                              f"Serving {len(s.items)} cached entries from {s.status['fetched_at']}.")
        elif s.failures == 0 and s.name in self.alerted:
            self.alerted.discard(s.name)
            self.alerter.send(f"edl-aggregator: source {s.name} recovered", f"{len(s.items)} entries.", "success")

    def rebuild(self):
        published, names = {}, {}
        for name, feed in self.feeds.items():
            items = feed.build(self.sources, self.never_block, self.never_block_domains)
            prev = self.published.get(name)
            if feed.max_entries and len(items) > feed.max_entries:
                msg = f"feed {name} has {len(items)} entries, over max_entries={feed.max_entries}"
                if feed.overflow == "keep-last" and prev is not None and not prev.overflow and prev.count:
                    published[name] = prev
                    msg += f"; still serving previous build ({prev.count} entries)"
                else:
                    published[name] = Published(items, overflow=True)
                    msg += "; serving it anyway"
                if f"feed:{name}" not in self.alerted:
                    self.alerted.add(f"feed:{name}")
                    self.alerter.send(f"edl-aggregator: feed {name} too large", msg)
            else:
                self.alerted.discard(f"feed:{name}")
                published[name] = prev if prev is not None and prev.items == items else Published(items)
            for key in [name] + feed.aliases:
                names[key] = name
        with self.lock:
            self.published, self.names = published, names
            self.last_build = now_iso()
        log.info("feeds rebuilt: %s", ", ".join(f"{k}={v.count}" for k, v in published.items()))

    # -- queries

    def feed_for(self, name: str) -> Feed | None:
        with self.lock:
            n = self.names.get(name)
        return self.feeds.get(n) if n else None

    def get(self, name: str) -> Published | None:
        with self.lock:
            feed = self.names.get(name)
            return self.published.get(feed) if feed else None

    def lookup(self, ip: str = "", domain: str = "", url: str = "") -> dict:
        if ip:
            q, qtype = ipaddress.ip_address(ip.strip()), "ip"
        elif domain:
            q, qtype = normalize_domain(domain), "domain"
        elif url:
            q, qtype = normalize_url(url), "url"
        else:
            raise ValueError("give ip, domain or url")
        with self.lock:
            published = dict(self.published)
        out = {"query": str(q), "type": qtype, "in_feeds": {}, "in_sources": {}}
        # a URL query is also checked against domain lists (its host)
        checks = [(qtype, q)] + ([("domain", url_host(q))] if qtype == "url" else [])
        for t, val in checks:
            for n, p in published.items():
                if self.feeds[n].type == t and (m := item_matches(t, p.items, val)):
                    out["in_feeds"][n] = m[:10]
            for n, s in self.sources.items():
                if s.type == t and (m := item_matches(t, s.items, val)):
                    out["in_sources"][n] = m[:10]
        if qtype == "ip":
            out["never_block"] = bool(item_matches("ip", self.never_block, q))
        else:   # same rule as the feeds: URLs are only protected when they are a bare host
            host = q if qtype == "domain" else url_host(q)
            bare = qtype == "domain" or q.split("/", 1)[1:] in ([], [""])
            out["never_block"] = bare and any(domain_covers(d, host) for d in self.never_block_domains)
        return out

    def status(self) -> dict:
        with self.lock:
            feeds = {n: {"count": p.count, "type": self.feeds[n].type, "kind": self.feeds[n].kind,
                         "aliases": self.feeds[n].aliases, "sources": self.feeds[n].inputs, "overflow": p.overflow,
                         "max_entries": self.feeds[n].max_entries, "description": self.feeds[n].description,
                         "protected": bool(self.feeds[n].basic_auth or self.feeds[n].allow_clients)}
                     for n, p in self.published.items()}
        return {"version": __version__, "last_build": self.last_build,
                "refresh_minutes": self.defaults["refresh_minutes"], "api_enabled": bool(self.api_token),
                "feeds": feeds, "sources": {n: s.status for n, s in self.sources.items()},
                "healthy": all(s.items or not s.required for s in self.sources.values())}

    def metrics(self) -> str:
        st = self.status()
        out = []

        def gauge(name, help_, samples):
            out.extend([f"# HELP {name} {help_}", f"# TYPE {name} gauge"] + samples)

        gauge("edl_feed_entries", "Entries currently served per feed",
              [f'edl_feed_entries{{feed="{n}",type="{f["type"]}",kind="{f["kind"]}"}} {f["count"]}'
               for n, f in st["feeds"].items()])
        gauge("edl_feed_overflow", "1 if the feed is over max_entries",
              [f'edl_feed_overflow{{feed="{n}"}} {int(f["overflow"])}' for n, f in st["feeds"].items()])
        gauge("edl_source_entries", "Entries held per source",
              [f'edl_source_entries{{source="{n}",type="{s["type"]}"}} {s["count"]}' for n, s in st["sources"].items()])
        gauge("edl_source_up", "1 if the last refresh succeeded",
              [f'edl_source_up{{source="{n}"}} {int(bool(s["ok"]))}' for n, s in st["sources"].items()
               if s["enabled"] and s["ok"] is not None])
        gauge("edl_source_consecutive_failures", "Consecutive failed refreshes",
              [f'edl_source_consecutive_failures{{source="{n}"}} {s["consecutive_failures"]}'
               for n, s in st["sources"].items()])
        gauge("edl_source_last_success_timestamp_seconds", "Last successful check",
              [f'edl_source_last_success_timestamp_seconds{{source="{n}"}} '
               f'{datetime.fromisoformat(s["checked_at"]).timestamp():.0f}'
               for n, s in st["sources"].items() if s.get("checked_at")])
        gauge("edl_healthy", "1 if every required source has data", [f"edl_healthy {int(st['healthy'])}"])
        gauge("edl_build_info", "Version", [f'edl_build_info{{version="{__version__}"}} 1'])
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- config / reload

def load_config(path: Path) -> dict:
    return tomllib.loads(path.read_text())


class Runtime:
    """Holds the current Aggregator and swaps it when the config file changes (only if the new one is valid)."""

    def __init__(self, cfg_path: Path, data_dir: Path):
        self.cfg_path, self.data_dir = cfg_path, data_dir
        self.mtime = cfg_path.stat().st_mtime
        self.agg = Aggregator(load_config(cfg_path), data_dir)
        self.reload_error = None

    def maybe_reload(self) -> bool:
        try:
            mtime = self.cfg_path.stat().st_mtime
        except FileNotFoundError:
            return False
        if mtime == self.mtime:
            return False
        self.mtime = mtime
        old = self.agg
        try:
            new = Aggregator(load_config(self.cfg_path), self.data_dir)
        except Exception as e:
            self.reload_error = f"{type(e).__name__}: {e}"
            old.alerter.send("edl-aggregator: config reload rejected",
                             f"{self.cfg_path}: {self.reload_error}. Still running the previous config.")
            return False
        new.alerted = old.alerted
        self.agg, self.reload_error = new, None
        log.info("config reloaded from %s (%d sources, %d feeds)", self.cfg_path, len(new.sources), len(new.feeds))
        new.tick()
        return True

    def run_forever(self, tick_seconds: int = 60):
        while True:
            try:
                self.maybe_reload()
                self.agg.tick()
            except Exception:
                log.exception("refresh cycle failed")
            time.sleep(tick_seconds)


# --------------------------------------------------------------------------- HTTP

def make_handler(runtime):
    """`runtime` is a Runtime, or an Aggregator (tests); handlers always use the current aggregator."""
    current = (lambda: runtime.agg) if isinstance(runtime, Runtime) else (lambda: runtime)

    class Handler(BaseHTTPRequestHandler):
        server_version = f"edl-aggregator/{__version__}"

        def _send(self, code: int, body: bytes | str, ctype="text/plain; charset=utf-8", headers=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD" and code != 304:
                self.wfile.write(data)

        def _json(self, code: int, obj):
            self._send(code, json.dumps(obj, indent=2) + "\n", "application/json")

        def _client_ip(self):
            return ipaddress.ip_address(self.client_address[0].removeprefix("::ffff:"))

        def _client_allowed(self, nets) -> bool:
            return not nets or bool(item_matches("ip", nets, self._client_ip()))

        def _admin_allowed(self, agg) -> bool:
            nets = [ipaddress.ip_network(c, strict=False) for c in agg.server.get("allow_clients", [])]
            if not self._client_allowed(nets):
                self._send(403, "forbidden\n")
                return False
            return True

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            agg = current()
            url = urlsplit(self.path)
            path = url.path.rstrip("/")
            if path.startswith("/feeds/"):
                return self._feed(agg, path[len("/feeds/"):].removesuffix(".txt"))
            if path.startswith("/api/"):
                return self._api(agg, "GET", path, url)
            if not self._admin_allowed(agg):
                return
            if path in ("/healthz", "/status"):
                st = agg.status()
                return self._json(200 if st["healthy"] else 503, st)
            if path == "/metrics":
                return self._send(200, agg.metrics(), "text/plain; version=0.0.4")
            if path == "/lookup":
                q = parse_qs(url.query)
                try:
                    return self._json(200, agg.lookup(q.get("ip", [""])[0], q.get("domain", [""])[0],
                                                      q.get("url", [""])[0]))
                except ValueError as e:
                    return self._send(400, f"{e}\nusage: /lookup?ip=1.2.3.4 | ?domain=example.com | ?url=...\n")
            if path == "":
                return self._send(200, self._index(agg))
            self._send(404, "not found\n")

        def do_POST(self):
            agg = current()
            url = urlsplit(self.path)
            if url.path.startswith("/api/"):
                return self._api(agg, "POST", url.path.rstrip("/"), url)
            self._send(405, "method not allowed\n")

        def do_DELETE(self):
            agg = current()
            url = urlsplit(self.path)
            if url.path.startswith("/api/"):
                return self._api(agg, "DELETE", url.path.rstrip("/"), url)
            self._send(405, "method not allowed\n")

        # -- feeds

        def _feed(self, agg, name: str):
            feed, pub = agg.feed_for(name), agg.get(name)
            if pub is None or feed is None:
                return self._send(404, "unknown feed\n")
            if not self._client_allowed(feed.allow_clients):
                return self._send(403, "forbidden\n")
            if feed.basic_auth and not self._basic_ok(feed.basic_auth):
                return self._send(401, "authentication required\n",
                                  headers={"WWW-Authenticate": f'Basic realm="edl-aggregator {name}"'})
            headers = {"ETag": pub.etag, "Last-Modified": formatdate(pub.last_modified, usegmt=True),
                       "Cache-Control": "no-cache"}
            inm, ims = self.headers.get("If-None-Match"), self.headers.get("If-Modified-Since")
            if inm and pub.etag in [t.strip() for t in inm.split(",")]:
                return self._send(304, b"", headers=headers)
            if ims and not inm:
                try:
                    if int(pub.last_modified) <= parsedate_to_datetime(ims).timestamp():
                        return self._send(304, b"", headers=headers)
                except (TypeError, ValueError):
                    pass
            self._send(200, pub.body, headers=headers)

        def _basic_ok(self, cred: dict) -> bool:
            h = self.headers.get("Authorization", "")
            if not h.startswith("Basic "):
                return False
            try:
                user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
            except Exception:
                return False
            return hmac.compare_digest(user, cred["username"]) & hmac.compare_digest(pw, cred["password"])

        # -- dynamic list API

        def _api(self, agg, method: str, path: str, url):
            if not agg.api_token:
                return self._send(404, "API disabled (set [api] token)\n")
            if not self._admin_allowed(agg):
                return
            auth = self.headers.get("Authorization", "")
            if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], agg.api_token)):
                return self._send(401, "bearer token required\n", headers={"WWW-Authenticate": "Bearer"})
            parts = path.split("/")       # ['', 'api', 'dynamic', '<name>']
            if len(parts) == 3 and parts[2] == "dynamic" and method == "GET":
                return self._json(200, {n: {"type": s.type, "count": len(s.dyn)} for n, s in agg.sources.items()
                                        if s.dynamic})
            if len(parts) != 4 or parts[2] != "dynamic":
                return self._send(404, "use /api/dynamic or /api/dynamic/<list>\n")
            src = agg.sources.get(parts[3])
            if src is None or not src.dynamic:
                return self._send(404, "unknown dynamic list\n")
            if method == "GET":
                return self._json(200, src.dyn_list())
            body = {}
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                try:
                    body = json.loads(self.rfile.read(min(length, 1_000_000)))
                except json.JSONDecodeError:
                    return self._send(400, "body must be JSON\n")
            entries = body.get("entries") or parse_qs(url.query).get("entry", [])
            if isinstance(entries, str):
                entries = [entries]
            if not entries:
                return self._send(400, 'give {"entries": [...]} or ?entry=\n')
            if method == "POST":
                ttl = body.get("ttl_minutes")
                result = src.dyn_add(entries, float(ttl) if ttl else None, str(body.get("comment", ""))[:200])
            else:
                result = src.dyn_remove(entries)
            agg.rebuild()
            log.info("api %s %s from %s: %s", method, src.name, self.client_address[0], result)
            return self._json(200, result)

        def _index(self, agg) -> str:
            st = agg.status()
            lines = [f"edl-aggregator {__version__} - last build {st['last_build']}", ""]
            titles = {"block": "Block lists", "allow": "Allow / service ranges",
                      "bogon": "Bogons (source match on internet-facing zones only)"}
            for kind in Feed.KINDS:
                for t in TYPES:
                    feeds = {n: f for n, f in st["feeds"].items() if f["kind"] == kind and f["type"] == t}
                    if not feeds:
                        continue
                    lines.append(f"{titles[kind]} - {t}")
                    for n, f in feeds.items():
                        names = ", ".join([f"/feeds/{n}"] + [f"/feeds/{a}" for a in f["aliases"]])
                        flags = ("  [OVER max_entries]" if f["overflow"] else "") + ("  [auth]" if f["protected"] else "")
                        lines.append(f"{f['count']:>8}  {names}  {f['description']}{flags}")
                    lines.append("")
            lines.append("Status: /status   Metrics: /metrics   Lookup: /lookup?ip= | ?domain= | ?url="
                         + ("   API: /api/dynamic" if st["api_enabled"] else ""))
            return "\n".join(lines) + "\n"

        def log_message(self, fmt, *args):
            log.info("%s %s", self.client_address[0], fmt % args)

    return Handler


def ensure_cert(cert: Path, key: Path):
    if cert.exists() and key.exists():
        return
    if not shutil.which("openssl"):
        raise RuntimeError("TLS cert/key missing and openssl not available to create one")
    cert.parent.mkdir(parents=True, exist_ok=True)
    log.info("creating self-signed certificate %s", cert)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                    "-subj", "/CN=edl-aggregator", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)


def serve(runtime, http_port: int, https_port: int, cert: Path, key: Path):
    servers = []
    if http_port:
        servers.append(ThreadingHTTPServer(("", http_port), make_handler(runtime)))
        log.info("HTTP on :%d", http_port)
    if https_port:
        ensure_cert(cert, key)
        s = ThreadingHTTPServer(("", https_port), make_handler(runtime))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
        servers.append(s)
        log.info("HTTPS on :%d", https_port)
    if not servers:
        raise SystemExit("nothing to serve: set HTTP_PORT and/or HTTPS_PORT")
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    servers[0].serve_forever()


# --------------------------------------------------------------------------- main

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=os.environ.get("CONFIG", "/config/config.toml"))
    p.add_argument("--data", default=os.environ.get("DATA_DIR", "/data"))
    p.add_argument("--check", action="store_true", help="validate the config and exit (no downloads)")
    p.add_argument("--once", action="store_true", help="refresh all sources, print a summary and exit")
    p.add_argument("--print", metavar="FEED", help="with --once: print this feed's contents")
    args = p.parse_args(argv)

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    cfg_path = Path(args.config)
    if args.check:
        try:
            agg = Aggregator(load_config(cfg_path), Path(args.data) if os.path.isdir(args.data) else
                             Path(tempfile_dir()))
        except Exception as e:
            print(f"INVALID: {type(e).__name__}: {e}")
            return 1
        types = {t: sum(1 for f in agg.feeds.values() if f.type == t) for t in TYPES}
        print(f"OK: {len(agg.sources)} sources, {len(agg.feeds)} feeds "
              f"({', '.join(f'{v} {k}' for k, v in types.items() if v)})")
        return 0
    if not cfg_path.exists():
        example = Path(__file__).with_name("config.example.toml")
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(example, cfg_path)
        log.info("no config found; wrote example config to %s", cfg_path)

    if args.once:
        agg = Aggregator(load_config(cfg_path), Path(args.data))
        agg.tick(force=True)
        agg.rebuild()
        print(json.dumps(agg.status(), indent=2))
        if args.print:
            pub = agg.get(args.print)
            sys.stdout.write(pub.text if pub else "")
        return 0 if agg.status()["healthy"] else 1

    runtime = Runtime(cfg_path, Path(args.data))
    threading.Thread(target=runtime.run_forever, args=(int(os.environ.get("TICK_SECONDS", 60)),),
                     daemon=True).start()
    data = Path(args.data)
    serve(runtime, int(os.environ.get("HTTP_PORT", 80)), int(os.environ.get("HTTPS_PORT", 443)),
          Path(os.environ.get("TLS_CERT", data / "tls" / "cert.pem")),
          Path(os.environ.get("TLS_KEY", data / "tls" / "key.pem")))


def tempfile_dir() -> str:
    import tempfile
    return tempfile.mkdtemp(prefix="edl-check-")


if __name__ == "__main__":
    sys.exit(main())
