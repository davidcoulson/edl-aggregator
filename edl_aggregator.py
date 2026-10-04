#!/usr/bin/env python3
"""edl-aggregator: fetch IP threat feeds, merge them, and serve External Dynamic Lists (EDLs).

A small replacement for Palo Alto MineMeld's most common use: pull public IP feeds (Spamhaus DROP,
DShield, Team Cymru bogons, Tor, cloud/service ranges, plain-text lists), combine and de-duplicate
them, remove allow-listed ranges, and publish one plain-text list per feed for a firewall to poll
(Palo Alto EDL, pfSense/OPNsense URL tables, FortiGate threat feeds, ...).

Standard library only. Configuration is a TOML file; see config.example.toml.

Safety rules:
  * A source that fails to download, parses to fewer than `min_entries`, or shrinks by more than
    `max_shrink_percent` keeps its last good data (cached on disk). Block lists never empty themselves
    because an upstream had a bad day.
  * `[safety] never_block` ranges are removed from every block feed, so your own addresses can't be
    blocked by a bad upstream entry.
  * A feed over its `max_entries` keeps serving its previous build (or serves anyway, if configured),
    instead of handing a firewall a list it will reject.
  * Feeds are rebuilt in memory and swapped atomically; readers never see a half-built list.
"""

import argparse
import hashlib
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
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

__version__ = "1.2.0"

log = logging.getLogger("edl-aggregator")
USER_AGENT = f"edl-aggregator/{__version__} (+https://github.com/davidcoulson/edl-aggregator)"
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expand_env(value):
    """Replace ${VAR} with the environment variable (empty if unset). Applies to strings only."""
    if isinstance(value, str):
        return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), value)
    return value


# --------------------------------------------------------------------------- parsing

def parse_entry(token: str) -> list[Network]:
    """Parse one IP, CIDR, 'a.b.c.d-e.f.g.h' range, '[v6]:port' or 'v4:port' into networks.
    Raises ValueError if invalid."""
    token = token.strip()
    if token.startswith("["):                       # [2001:db8::1]:9001
        token = token[1:token.index("]")]
    elif token.count(":") == 1 and "." in token:    # 192.0.2.1:9001
        token = token.split(":", 1)[0]
    if "-" in token and "/" not in token:
        start, end = (ipaddress.ip_address(p.strip()) for p in token.split("-", 1))
        return list(ipaddress.summarize_address_range(start, end))
    return [ipaddress.ip_network(token, strict=False)]


def parse_plain(text: str, **_) -> list[Network]:
    """One entry per line. Comments start with '#', ';' or '//'; anything after the first token is ignored."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        token = re.split(r"[\s;,#]", line, maxsplit=1)[0]
        try:
            out.extend(parse_entry(token))
        except ValueError:
            log.debug("plain: skipping %r", line)
    return out


def parse_spamhaus_json(text: str, **_) -> list[Network]:
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
            out.append(ipaddress.ip_network(obj["cidr"], strict=False))
    return out


def parse_dshield(text: str, **_) -> list[Network]:
    """DShield block.txt: tab-separated 'start  end  bits  attacks ...'; '#' comments and a 'Start' header."""
    out = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or line.startswith("Start"):
            continue
        f = line.split()
        if len(f) < 3:
            continue
        try:
            out.append(ipaddress.ip_network(f"{f[0]}/{f[2]}", strict=False))
        except ValueError:
            log.debug("dshield: skipping %r", line)
    return out


def parse_aws_json(text: str, service=None, region=None, **_) -> list[Network]:
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
            out.append(ipaddress.ip_network(p[field], strict=False))
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


def parse_json(text: str, paths=None, where=None, **_) -> list[Network]:
    """Generic JSON: `paths` like ["prefixes[].ipv4Prefix", "hooks[]", "[].ips[]"]; `[]` iterates a list.
    `where` (optional) skips any object whose listed keys don't match, e.g. {category = ["Optimize", "Allow"]}."""
    if not paths:
        raise ValueError("format 'json' needs 'paths'")
    out = []
    for value in json_values(text, paths, where):
        try:
            out.extend(parse_entry(value))
        except ValueError:
            log.debug("json: skipping %r", value)
    return out


PARSERS = {
    "plain": parse_plain,
    "spamhaus-json": parse_spamhaus_json,
    "dshield": parse_dshield,
    "aws-json": parse_aws_json,
    "json": parse_json,
}
SOURCE_KEYS = {"url", "entries", "format", "confidence", "min_entries", "enabled", "refresh_minutes",
               "headers", "max_shrink_percent", "description", "timeout"}


# --------------------------------------------------------------------------- set operations

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


def collapse(networks) -> list[Network]:
    networks = list(networks)
    v4 = ipaddress.collapse_addresses(n for n in networks if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in networks if n.version == 6)
    return list(v4) + list(v6)


def contains(networks: list[Network], ip) -> bool:
    return any(ip.version == n.version and ip in n for n in networks)


# --------------------------------------------------------------------------- alerts

class Alerter:
    """POSTs a JSON {title, body, type} message to a webhook (e.g. an Apprise API /notify/<key> URL)."""

    def __init__(self, cfg: dict):
        self.url = expand_env(cfg.get("webhook_url", ""))
        self.after = int(cfg.get("after_failures", 3))
        self.headers = {k: expand_env(v) for k, v in cfg.get("headers", {}).items()}

    def send(self, title: str, body: str, kind: str = "warning"):
        log.warning("ALERT %s: %s", title, body) if kind != "success" else log.info("ALERT %s: %s", title, body)
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


# --------------------------------------------------------------------------- sources and feeds

class Source:
    def __init__(self, name: str, cfg: dict, cache_dir: Path, defaults: dict):
        self.name = name
        self.cfg = cfg
        self.url = expand_env(cfg.get("url"))
        self.entries_static = cfg.get("entries")             # inline list instead of a URL
        self.format = cfg.get("format", "plain")
        self.enabled = bool(cfg.get("enabled", True))
        self.confidence = int(cfg.get("confidence", 100))
        self.min_entries = int(cfg.get("min_entries", 1 if self.url else 0))
        self.refresh_minutes = float(cfg.get("refresh_minutes", defaults["refresh_minutes"]))
        self.max_shrink = float(cfg.get("max_shrink_percent", defaults["max_shrink_percent"]))
        self.timeout = int(cfg.get("timeout", 60))
        self.headers = {k: expand_env(v) for k, v in cfg.get("headers", {}).items()}
        self.opts = {k: v for k, v in cfg.items() if k not in SOURCE_KEYS}
        self.cache = cache_dir / f"{name}.txt"
        self.meta_file = cache_dir / f"{name}.json"
        self.networks: list[Network] = []
        self.meta: dict = {}
        self.failures = 0
        self.last_attempt = 0.0
        self.status = {"name": name, "url": self.url, "enabled": self.enabled, "ok": None, "count": 0,
                       "fetched_at": None, "checked_at": None, "error": None, "consecutive_failures": 0}
        if self.format not in PARSERS:
            raise ValueError(f"source {name}: unknown format {self.format!r} (use one of {', '.join(PARSERS)})")
        if not self.url and self.entries_static is None:
            raise ValueError(f"source {name}: needs 'url' or 'entries'")
        self._load_cache()

    @property
    def required(self) -> bool:
        return self.enabled and self.min_entries > 0

    def _load_cache(self):
        if self.entries_static is not None:
            self._load_static()
            return
        if self.cache.exists():
            self.networks = [ipaddress.ip_network(l) for l in self.cache.read_text().split() if l]
            self.status["count"] = len(self.networks)
        if self.meta_file.exists():
            try:
                self.meta = json.loads(self.meta_file.read_text())
            except json.JSONDecodeError:
                self.meta = {}
            self.status["fetched_at"] = self.meta.get("fetched_at")
            self.status["checked_at"] = self.meta.get("checked_at")

    def _load_static(self):
        nets = []
        for e in self.entries_static:
            nets.extend(parse_entry(str(e)))
        self.networks = collapse(nets)
        self.status.update(ok=True, count=len(self.networks), error=None, fetched_at=now_iso(), checked_at=now_iso())

    def due(self, now: float) -> bool:
        if not self.enabled or self.entries_static is not None:
            return False
        if self.failures:   # retry failed sources sooner: 5 minutes, but never more often than the interval
            return now - self.last_attempt >= min(300, self.refresh_minutes * 60)
        checked = self.meta.get("checked_ts", 0)
        return now - checked >= self.refresh_minutes * 60

    def _fail(self, error: str):
        self.failures += 1
        self.status.update(ok=False, error=error, consecutive_failures=self.failures)
        log.warning("source %s: %s (keeping %d cached entries)", self.name, error, len(self.networks))

    def refresh(self) -> bool:
        """Fetch if due. Returns True if the source's data changed."""
        self.last_attempt = time.time()
        headers = {"User-Agent": USER_AGENT, **self.headers}
        if self.networks and self.meta.get("etag"):
            headers["If-None-Match"] = self.meta["etag"]
        if self.networks and self.meta.get("last_modified"):
            headers["If-Modified-Since"] = self.meta["last_modified"]
        try:
            req = urllib.request.Request(self.url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
                etag, last_mod = resp.headers.get("ETag"), resp.headers.get("Last-Modified")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                self._mark_checked()
                log.info("source %s: not modified", self.name)
                return False
            self._fail(f"HTTP {e.code} {e.reason}")
            return False
        except Exception as e:
            self._fail(f"{type(e).__name__}: {e}")
            return False
        try:
            parsed = PARSERS[self.format](text, **self.opts)
        except Exception as e:
            self._fail(f"parse error: {type(e).__name__}: {e}")
            return False
        # Size checks use the raw entry count from upstream: collapsing can legitimately merge thousands of
        # adjacent addresses into a few prefixes.
        raw = len(parsed)
        if raw < self.min_entries:
            self._fail(f"only {raw} entries (min_entries={self.min_entries})")
            return False
        old = self.meta.get("raw_count") or len(self.networks)
        if old and self.max_shrink < 100 and raw < old * (1 - self.max_shrink / 100):
            self._fail(f"shrank from {old} to {raw} entries (more than max_shrink_percent={self.max_shrink:g})")
            return False
        nets = collapse(parsed)
        changed = nets != self.networks
        self.networks = nets
        if changed:
            tmp = self.cache.with_suffix(".tmp")
            tmp.write_text("".join(f"{n}\n" for n in nets))
            tmp.replace(self.cache)
            self.meta["fetched_at"] = now_iso()
        self.meta.update(etag=etag, last_modified=last_mod, count=len(nets), raw_count=raw, url=self.url)
        self._mark_checked()
        self.status.update(fetched_at=self.meta.get("fetched_at"), count=len(nets))
        log.info("source %s: %d networks%s", self.name, len(nets), "" if changed else " (unchanged)")
        return changed

    def _mark_checked(self):
        self.failures = 0
        self.meta.update(checked_at=now_iso(), checked_ts=time.time())
        self.meta_file.write_text(json.dumps(self.meta))
        self.status.update(ok=True, error=None, checked_at=self.meta["checked_at"], consecutive_failures=0)


class Feed:
    KINDS = ("block", "allow", "bogon")

    def __init__(self, name: str, cfg: dict, sources: dict):
        self.name = name
        self.inputs = cfg.get("sources", [])
        self.excludes = cfg.get("exclude", [])
        self.family = cfg.get("family", "both")          # ipv4 | ipv6 | both
        self.kind = cfg.get("kind", "block")              # block | allow | bogon  (never_block applies to block)
        self.min_conf = int(cfg.get("min_confidence", 0))
        self.max_conf = int(cfg.get("max_confidence", 100))
        self.max_entries = int(cfg.get("max_entries", 0))
        self.overflow = cfg.get("overflow", "keep-last")  # keep-last | serve
        self.aliases = cfg.get("aliases", [])
        self.description = cfg.get("description", "")
        for s in self.inputs + self.excludes:
            if s not in sources:
                raise ValueError(f"feed {name}: unknown source {s!r}")
        if self.family not in ("ipv4", "ipv6", "both"):
            raise ValueError(f"feed {name}: family must be ipv4, ipv6 or both")
        if self.kind not in self.KINDS:
            raise ValueError(f"feed {name}: kind must be one of {', '.join(self.KINDS)}")
        if self.overflow not in ("keep-last", "serve"):
            raise ValueError(f"feed {name}: overflow must be keep-last or serve")

    def build(self, sources: dict, never_block: list[Network]) -> list[Network]:
        nets = []
        for s in self.inputs:
            src = sources[s]
            if src.enabled and self.min_conf <= src.confidence <= self.max_conf:
                nets.extend(src.networks)
        if self.family != "both":
            want = 4 if self.family == "ipv4" else 6
            nets = [n for n in nets if n.version == want]
        excl = [n for s in self.excludes for n in sources[s].networks]
        if self.kind == "block":
            excl += never_block
        return collapse(subtract(collapse(nets), excl))


class Published:
    """One built feed, immutable once created."""

    def __init__(self, networks: list[Network], overflow: bool = False):
        self.networks = networks
        self.text = "".join(f"{n}\n" for n in networks)
        self.body = self.text.encode()
        self.etag = '"' + hashlib.sha256(self.body).hexdigest()[:32] + '"'
        self.last_modified = time.time()
        self.overflow = overflow

    @property
    def count(self):
        return len(self.networks)


class Aggregator:
    def __init__(self, config: dict, data_dir: Path, alerter: Alerter | None = None):
        self.config = config
        safety = config.get("safety", {})
        self.defaults = {"refresh_minutes": float(config.get("refresh_minutes", 60)),
                         "max_shrink_percent": float(safety.get("max_shrink_percent", 50))}
        self.never_block = collapse(n for e in safety.get("never_block", []) for n in parse_entry(str(e)))
        self.alerter = alerter or Alerter(config.get("alerts", {}))
        cache = data_dir / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        self.sources = {n: Source(n, c, cache, self.defaults) for n, c in config.get("sources", {}).items()}
        self.feeds = {n: Feed(n, c, self.sources) for n, c in config.get("feeds", {}).items()}
        self.lock = threading.Lock()
        self.published: dict[str, Published] = {}     # feed name -> build
        self.names: dict[str, str] = {}               # feed name or alias -> feed name
        self.last_build = None
        self.alerted: set[str] = set()
        self.rebuild()   # serve cached data immediately at start-up

    # -- refresh / build

    def tick(self, force: bool = False) -> bool:
        """Refresh due sources (all enabled URL sources if force) and rebuild if anything changed."""
        now = time.time()
        changed = False
        for s in self.sources.values():
            if s.url and s.enabled and (force or s.due(now)):
                changed |= s.refresh()
                self._check_alert(s)
        if changed or not self.published:
            self.rebuild()
        return changed

    def _check_alert(self, s: Source):
        if s.failures >= self.alerter.after and s.name not in self.alerted:
            self.alerted.add(s.name)
            self.alerter.send(f"edl-aggregator: source {s.name} failing",
                              f"{s.failures} consecutive failures: {s.status['error']}. "
                              f"Serving {len(s.networks)} cached entries from {s.status['fetched_at']}.")
        elif s.failures == 0 and s.name in self.alerted:
            self.alerted.discard(s.name)
            self.alerter.send(f"edl-aggregator: source {s.name} recovered", f"{len(s.networks)} entries.", "success")

    def rebuild(self):
        published, names = {}, {}
        for name, feed in self.feeds.items():
            nets = feed.build(self.sources, self.never_block)
            prev = self.published.get(name)
            if feed.max_entries and len(nets) > feed.max_entries:
                msg = f"feed {name} has {len(nets)} entries, over max_entries={feed.max_entries}"
                if feed.overflow == "keep-last" and prev is not None and not prev.overflow and prev.count:
                    published[name] = prev
                    msg += f"; still serving previous build ({prev.count} entries)"
                else:
                    published[name] = Published(nets, overflow=True)
                    msg += "; serving it anyway"
                if f"feed:{name}" not in self.alerted:
                    self.alerted.add(f"feed:{name}")
                    self.alerter.send(f"edl-aggregator: feed {name} too large", msg)
            else:
                self.alerted.discard(f"feed:{name}")
                published[name] = prev if prev is not None and prev.networks == nets else Published(nets)
            for key in [name] + feed.aliases:
                names[key] = name
        with self.lock:
            self.published, self.names = published, names
            self.last_build = now_iso()
        log.info("feeds rebuilt: %s", ", ".join(f"{k}={v.count}" for k, v in published.items()))

    # -- queries

    def get(self, name: str) -> Published | None:
        with self.lock:
            feed = self.names.get(name)
            return self.published.get(feed) if feed else None

    def lookup(self, query: str) -> dict:
        ip = ipaddress.ip_address(query.strip())
        with self.lock:
            published = dict(self.published)
        feeds = [n for n, p in published.items() if contains(p.networks, ip)]
        sources = [n for n, s in self.sources.items() if contains(s.networks, ip)]
        return {"query": str(ip), "in_feeds": feeds, "in_sources": sources,
                "never_block": contains(self.never_block, ip)}

    def status(self) -> dict:
        with self.lock:
            feeds = {n: {"count": p.count, "kind": self.feeds[n].kind, "aliases": self.feeds[n].aliases,
                         "sources": self.feeds[n].inputs, "overflow": p.overflow,
                         "max_entries": self.feeds[n].max_entries, "description": self.feeds[n].description}
                     for n, p in self.published.items()}
        return {"version": __version__, "last_build": self.last_build,
                "refresh_minutes": self.defaults["refresh_minutes"], "feeds": feeds,
                "sources": {n: s.status for n, s in self.sources.items()},
                "healthy": all(s.networks or not s.required for s in self.sources.values())}

    def metrics(self) -> str:
        st = self.status()
        lines = ["# HELP edl_feed_entries Entries currently served per feed",
                 "# TYPE edl_feed_entries gauge"]
        lines += [f'edl_feed_entries{{feed="{n}",kind="{f["kind"]}"}} {f["count"]}' for n, f in st["feeds"].items()]
        lines += ["# HELP edl_feed_overflow 1 if the feed is over max_entries", "# TYPE edl_feed_overflow gauge"]
        lines += [f'edl_feed_overflow{{feed="{n}"}} {int(f["overflow"])}' for n, f in st["feeds"].items()]
        lines += ["# HELP edl_source_entries Entries held per source", "# TYPE edl_source_entries gauge"]
        lines += [f'edl_source_entries{{source="{n}"}} {s["count"]}' for n, s in st["sources"].items()]
        lines += ["# HELP edl_source_up 1 if the last refresh succeeded", "# TYPE edl_source_up gauge"]
        lines += [f'edl_source_up{{source="{n}"}} {int(bool(s["ok"]))}' for n, s in st["sources"].items()
                  if s["enabled"] and s["ok"] is not None]
        lines += ["# HELP edl_source_consecutive_failures Consecutive failed refreshes",
                  "# TYPE edl_source_consecutive_failures gauge"]
        lines += [f'edl_source_consecutive_failures{{source="{n}"}} {s["consecutive_failures"]}'
                  for n, s in st["sources"].items()]
        lines += ["# HELP edl_source_last_success_timestamp_seconds Last successful check",
                  "# TYPE edl_source_last_success_timestamp_seconds gauge"]
        for n, s in st["sources"].items():
            if s.get("checked_at"):
                lines.append(f'edl_source_last_success_timestamp_seconds{{source="{n}"}} '
                             f'{datetime.fromisoformat(s["checked_at"]).timestamp():.0f}')
        lines += ["# HELP edl_healthy 1 if every required source has data", "# TYPE edl_healthy gauge",
                  f"edl_healthy {int(st['healthy'])}", f'edl_build_info{{version="{__version__}"}} 1']
        return "\n".join(lines) + "\n"

    def run_forever(self, tick_seconds: int = 60):
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("refresh cycle failed")
            time.sleep(tick_seconds)


# --------------------------------------------------------------------------- HTTP

def make_handler(agg: Aggregator):
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

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            url = urlsplit(self.path)
            path = url.path.rstrip("/")
            if path.startswith("/feeds/"):
                return self._feed(path[len("/feeds/"):].removesuffix(".txt"))
            if path in ("/healthz", "/status"):
                st = agg.status()
                return self._send(200 if st["healthy"] else 503, json.dumps(st, indent=2) + "\n", "application/json")
            if path == "/metrics":
                return self._send(200, agg.metrics(), "text/plain; version=0.0.4")
            if path == "/lookup":
                q = parse_qs(url.query).get("ip", [""])[0]
                try:
                    return self._send(200, json.dumps(agg.lookup(q), indent=2) + "\n", "application/json")
                except ValueError:
                    return self._send(400, "usage: /lookup?ip=<address>\n")
            if path == "":
                return self._send(200, self._index())
            self._send(404, "not found\n")

        def _feed(self, name: str):
            pub = agg.get(name)
            if pub is None:
                return self._send(404, "unknown feed\n")
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

        def _index(self) -> str:
            st = agg.status()
            lines = [f"edl-aggregator {__version__} - last build {st['last_build']}", ""]
            for kind in Feed.KINDS:
                feeds = {n: f for n, f in st["feeds"].items() if f["kind"] == kind}
                if not feeds:
                    continue
                lines.append({"block": "Block lists", "allow": "Allow / service ranges",
                              "bogon": "Bogons (source match on internet-facing zones only)"}[kind])
                for n, f in feeds.items():
                    names = ", ".join([f"/feeds/{n}"] + [f"/feeds/{a}" for a in f["aliases"]])
                    flag = "  [OVER max_entries]" if f["overflow"] else ""
                    lines.append(f"{f['count']:>8}  {names}  {f['description']}{flag}")
                lines.append("")
            lines += ["Status: /status   Metrics: /metrics   Lookup: /lookup?ip=1.2.3.4"]
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


def serve(agg: Aggregator, http_port: int, https_port: int, cert: Path, key: Path):
    servers = []
    if http_port:
        servers.append(ThreadingHTTPServer(("", http_port), make_handler(agg)))
        log.info("HTTP on :%d", http_port)
    if https_port:
        ensure_cert(cert, key)
        s = ThreadingHTTPServer(("", https_port), make_handler(agg))
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

def load_config(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default=os.environ.get("CONFIG", "/config/config.toml"))
    p.add_argument("--data", default=os.environ.get("DATA_DIR", "/data"))
    p.add_argument("--once", action="store_true", help="refresh all sources, print a summary and exit")
    p.add_argument("--print", metavar="FEED", help="with --once: print this feed's contents")
    args = p.parse_args(argv)

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        example = Path(__file__).with_name("config.example.toml")
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(example, cfg_path)
        log.info("no config found; wrote example config to %s", cfg_path)
    agg = Aggregator(load_config(cfg_path), Path(args.data))

    if args.once:
        agg.tick(force=True)
        agg.rebuild()
        print(json.dumps(agg.status(), indent=2))
        if args.print:
            pub = agg.get(args.print)
            sys.stdout.write(pub.text if pub else "")
        return 0 if agg.status()["healthy"] else 1

    threading.Thread(target=agg.run_forever, args=(int(os.environ.get("TICK_SECONDS", 60)),), daemon=True).start()
    data = Path(args.data)
    serve(agg, int(os.environ.get("HTTP_PORT", 80)), int(os.environ.get("HTTPS_PORT", 443)),
          Path(os.environ.get("TLS_CERT", data / "tls" / "cert.pem")),
          Path(os.environ.get("TLS_KEY", data / "tls" / "key.pem")))


if __name__ == "__main__":
    sys.exit(main())
