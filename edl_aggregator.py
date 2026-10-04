#!/usr/bin/env python3
"""edl-aggregator: fetch IP threat feeds, merge them, and serve External Dynamic Lists (EDLs).

A small replacement for Palo Alto MineMeld's most common use: pull a few public IP feeds
(Spamhaus DROP, DShield, cloud provider ranges, plain-text lists), combine and de-duplicate them,
remove allow-listed ranges, and publish one plain-text list per feed for a firewall to poll
(Palo Alto EDL, pfSense/OPNsense URL tables, FortiGate threat feeds, ...).

Standard library only. Configuration is a TOML file; see config.example.toml.

Design rules:
  * A source that fails to download or parses to fewer than `min_entries` keeps its last good
    data (cached on disk), so a feed never empties itself because an upstream had a bad day.
  * Feeds are rebuilt in memory and swapped atomically; readers never see a half-built list.
  * Output is one network per line in CIDR form, collapsed to the fewest prefixes.
"""

import argparse
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
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

__version__ = "1.0.0"

log = logging.getLogger("edl-aggregator")
USER_AGENT = f"edl-aggregator/{__version__} (+https://github.com/davidcoulson/edl-aggregator)"
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


# --------------------------------------------------------------------------- parsing

def parse_entry(token: str) -> list[Network]:
    """Parse one IP, CIDR or 'a.b.c.d-e.f.g.h' range into networks. Raises ValueError if invalid."""
    token = token.strip()
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


PARSERS = {
    "plain": parse_plain,
    "spamhaus-json": parse_spamhaus_json,
    "dshield": parse_dshield,
    "aws-json": parse_aws_json,
}


# --------------------------------------------------------------------------- set operations

def subtract(networks: list[Network], excludes: list[Network]) -> list[Network]:
    """Remove every address in `excludes` from `networks` (splitting networks where needed)."""
    result = []
    for net in networks:
        pieces = [net]
        for ex in excludes:
            if ex.version != net.version:
                continue
            nxt = []
            for p in pieces:
                if p.subnet_of(ex):
                    continue                        # fully allow-listed
                if ex.subnet_of(p):
                    nxt.extend(p.address_exclude(ex))  # punch a hole
                else:
                    nxt.append(p)
            pieces = nxt
        result.extend(pieces)
    return result


def collapse(networks: list[Network]) -> list[Network]:
    v4 = ipaddress.collapse_addresses(n for n in networks if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in networks if n.version == 6)
    return list(v4) + list(v6)


# --------------------------------------------------------------------------- sources and feeds

class Source:
    def __init__(self, name: str, cfg: dict, cache_dir: Path):
        self.name = name
        self.cfg = cfg
        self.url = cfg.get("url")
        self.entries_static = cfg.get("entries")  # inline list instead of a URL
        self.format = cfg.get("format", "plain")
        self.confidence = int(cfg.get("confidence", 100))
        self.min_entries = int(cfg.get("min_entries", 1 if self.url else 0))
        self.cache = cache_dir / f"{name}.txt"
        self.meta_file = cache_dir / f"{name}.json"
        self.networks: list[Network] = []
        self.status = {"name": name, "url": self.url, "ok": None, "count": 0, "fetched_at": None, "error": None}
        if self.format not in PARSERS:
            raise ValueError(f"source {name}: unknown format {self.format!r} (use one of {', '.join(PARSERS)})")
        if not self.url and self.entries_static is None:
            raise ValueError(f"source {name}: needs 'url' or 'entries'")
        self._load_cache()

    def _load_cache(self):
        if self.cache.exists():
            self.networks = [ipaddress.ip_network(l) for l in self.cache.read_text().split() if l]
            self.status["count"] = len(self.networks)
            if self.meta_file.exists():
                self.status["fetched_at"] = json.loads(self.meta_file.read_text()).get("fetched_at")

    def refresh(self, timeout: int = 60) -> None:
        if self.entries_static is not None:
            nets = []
            for e in self.entries_static:
                nets.extend(parse_entry(str(e)))
            self.networks = collapse(nets)
            self.status.update(ok=True, count=len(self.networks), error=None,
                               fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
            return
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
            opts = {k: v for k, v in self.cfg.items() if k not in ("url", "format", "confidence", "min_entries")}
            nets = collapse(PARSERS[self.format](text, **opts))
            if len(nets) < self.min_entries:
                raise ValueError(f"only {len(nets)} entries (min_entries={self.min_entries})")
        except Exception as e:  # keep last good data
            self.status.update(ok=False, error=f"{type(e).__name__}: {e}")
            log.warning("source %s: refresh failed, keeping %d cached entries: %s", self.name, len(self.networks), e)
            return
        self.networks = nets
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        tmp = self.cache.with_suffix(".tmp")
        tmp.write_text("".join(f"{n}\n" for n in nets))
        tmp.replace(self.cache)
        self.meta_file.write_text(json.dumps({"fetched_at": now, "count": len(nets), "url": self.url}))
        self.status.update(ok=True, count=len(nets), error=None, fetched_at=now)
        log.info("source %s: %d networks", self.name, len(nets))


class Feed:
    def __init__(self, name: str, cfg: dict, sources: dict):
        self.name = name
        self.inputs = cfg.get("sources", [])
        self.excludes = cfg.get("exclude", [])
        self.family = cfg.get("family", "both")          # ipv4 | ipv6 | both
        self.min_conf = int(cfg.get("min_confidence", 0))
        self.max_conf = int(cfg.get("max_confidence", 100))
        self.aliases = cfg.get("aliases", [])
        self.description = cfg.get("description", "")
        for s in self.inputs + self.excludes:
            if s not in sources:
                raise ValueError(f"feed {name}: unknown source {s!r}")
        if self.family not in ("ipv4", "ipv6", "both"):
            raise ValueError(f"feed {name}: family must be ipv4, ipv6 or both")

    def build(self, sources: dict) -> list[Network]:
        nets = []
        for s in self.inputs:
            src = sources[s]
            if self.min_conf <= src.confidence <= self.max_conf:
                nets.extend(src.networks)
        if self.family != "both":
            want = 4 if self.family == "ipv4" else 6
            nets = [n for n in nets if n.version == want]
        excl = [n for s in self.excludes for n in sources[s].networks]
        return collapse(subtract(collapse(nets), excl))


class Aggregator:
    def __init__(self, config: dict, data_dir: Path):
        self.config = config
        self.refresh_minutes = int(config.get("refresh_minutes", 60))
        cache = data_dir / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        self.sources = {n: Source(n, c, cache) for n, c in config.get("sources", {}).items()}
        self.feeds = {n: Feed(n, c, self.sources) for n, c in config.get("feeds", {}).items()}
        self.lock = threading.Lock()
        self.published: dict[str, str] = {}   # feed name or alias -> text
        self.counts: dict[str, int] = {}
        self.last_build = None
        self.rebuild()  # serve cached data immediately at start-up

    def refresh(self):
        for s in self.sources.values():
            s.refresh()
        self.rebuild()

    def rebuild(self):
        published, counts = {}, {}
        for name, feed in self.feeds.items():
            nets = feed.build(self.sources)
            text = "".join(f"{n}\n" for n in nets)
            counts[name] = len(nets)
            for key in [name] + feed.aliases:
                published[key] = text
        with self.lock:
            self.published, self.counts = published, counts
            self.last_build = datetime.now(timezone.utc).isoformat(timespec="seconds")
        log.info("feeds rebuilt: %s", ", ".join(f"{k}={v}" for k, v in counts.items()))

    def get(self, name: str):
        with self.lock:
            return self.published.get(name)

    def status(self) -> dict:
        with self.lock:
            feeds = {n: {"count": self.counts.get(n, 0), "aliases": f.aliases, "sources": f.inputs,
                         "description": f.description} for n, f in self.feeds.items()}
        return {"version": __version__, "last_build": self.last_build, "refresh_minutes": self.refresh_minutes,
                "feeds": feeds, "sources": {n: s.status for n, s in self.sources.items()},
                "healthy": all(s.status["count"] > 0 or s.min_entries == 0 for s in self.sources.values())}

    def run_forever(self):
        while True:
            try:
                self.refresh()
            except Exception:
                log.exception("refresh cycle failed")
            time.sleep(self.refresh_minutes * 60)


# --------------------------------------------------------------------------- HTTP

def make_handler(agg: Aggregator):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"edl-aggregator/{__version__}"

        def _send(self, code: int, body: str, ctype="text/plain; charset=utf-8"):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = self.path.split("?", 1)[0].rstrip("/")
            if path.startswith("/feeds/"):
                name = path[len("/feeds/"):].removesuffix(".txt")
                text = agg.get(name)
                return self._send(200, text) if text is not None else self._send(404, "unknown feed\n")
            if path in ("/healthz", "/status"):
                st = agg.status()
                return self._send(200 if st["healthy"] else 503, json.dumps(st, indent=2) + "\n", "application/json")
            if path == "":
                st = agg.status()
                lines = [f"edl-aggregator {__version__} - last build {st['last_build']}", ""]
                for n, f in st["feeds"].items():
                    names = ", ".join([f"/feeds/{n}"] + [f"/feeds/{a}" for a in f["aliases"]])
                    lines.append(f"{f['count']:>7}  {names}  {f['description']}")
                lines += ["", "Status: /status"]
                return self._send(200, "\n".join(lines) + "\n")
            self._send(404, "not found\n")

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
    config = tomllib.loads(cfg_path.read_text())
    agg = Aggregator(config, Path(args.data))

    if args.once:
        agg.refresh()
        print(json.dumps(agg.status(), indent=2))
        if args.print:
            sys.stdout.write(agg.get(args.print) or "")
        return 0 if agg.status()["healthy"] else 1

    threading.Thread(target=agg.run_forever, daemon=True).start()
    data = Path(args.data)
    serve(agg, int(os.environ.get("HTTP_PORT", 80)), int(os.environ.get("HTTPS_PORT", 443)),
          Path(os.environ.get("TLS_CERT", data / "tls" / "cert.pem")),
          Path(os.environ.get("TLS_KEY", data / "tls" / "key.pem")))


if __name__ == "__main__":
    sys.exit(main())
