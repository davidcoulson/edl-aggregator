import base64
import ipaddress
import json
import os
import sys
import tempfile
import threading
import time
import tomllib
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import edl_aggregator as e  # noqa: E402

N = ipaddress.ip_network
EXAMPLE = Path(e.__file__).with_name("config.example.toml")


def ips(tokens):
    return e.to_items("ip", tokens, {})


class Upstream:
    """Tiny HTTP server serving mutable content with ETag support, to test fetching behaviour offline."""

    def __init__(self):
        self.body, self.etag, self.status, self.hits, self.last_headers = "", '"v1"', 200, 0, {}
        up = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                up.hits += 1
                up.last_headers = dict(self.headers)
                if up.status != 200:
                    self.send_response(up.status); self.end_headers(); return
                if self.headers.get("If-None-Match") == up.etag:
                    self.send_response(304); self.end_headers(); return
                data = up.body.encode()
                self.send_response(200)
                self.send_header("ETag", up.etag)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/list"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Served:
    """Run the edl-aggregator HTTP handler for an aggregator on an ephemeral port."""

    def __init__(self, agg):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), e.make_handler(agg))
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def req(self, path, method="GET", body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method,
                                   headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as err:
            return err.code, err.read(), err.headers

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class RecordingAlerter(e.Alerter):
    def __init__(self):
        super().__init__({"after_failures": 2})
        self.sent = []

    def send(self, title, body, kind="warning"):
        self.sent.append((title, kind))


def make(cfg, d):
    return e.Aggregator(cfg, Path(d), alerter=RecordingAlerter())


# ------------------------------------------------------------------ parsing

class ParserTests(unittest.TestCase):
    def test_plain_ip(self):
        text = "# comment\n1.2.3.4\n10.0.0.0/8 ; note\n\n// x\n192.0.2.1-192.0.2.6\nbogus\n2001:db8::/32\n"
        got = ips(e.parse_plain(text))
        self.assertIn(N("1.2.3.4/32"), got)
        self.assertIn(N("10.0.0.0/8"), got)
        self.assertIn(N("2001:db8::/32"), got)
        self.assertEqual(set(e.collapse([n for n in got if str(n).startswith("192.0.2.")])),
                         {N("192.0.2.1/32"), N("192.0.2.2/31"), N("192.0.2.4/31"), N("192.0.2.6/32")})

    def test_ports_stripped(self):
        self.assertEqual(e.parse_ip("[2001:db8::1]:9001"), [N("2001:db8::1/128")])
        self.assertEqual(e.parse_ip("192.0.2.9:443"), [N("192.0.2.9/32")])
        self.assertEqual(e.parse_ip("2001:db8::5"), [N("2001:db8::5/128")])

    def test_spamhaus_dshield_aws(self):
        self.assertEqual(ips(e.parse_spamhaus_json('{"cidr":"1.10.16.0/20"}\n{"type":"metadata"}\n')),
                         [N("1.10.16.0/20")])
        self.assertEqual(ips(e.parse_dshield("Start\tEnd\tNetblock\n45.148.10.0\t45.148.10.255\t24\t9\n")),
                         [N("45.148.10.0/24")])
        aws = json.dumps({"prefixes": [{"ip_prefix": "3.5.0.0/19", "service": "S3", "region": "us-east-1"},
                                       {"ip_prefix": "3.0.0.0/15", "service": "EC2", "region": "us-east-1"}],
                          "ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/40", "service": "S3", "region": "x"}]})
        self.assertEqual(ips(e.parse_aws_json(aws, service="S3")), [N("3.5.0.0/19"), N("2600:1f00::/40")])
        self.assertEqual(ips(e.parse_aws_json(aws, service="S3", region="us-east-1")), [N("3.5.0.0/19")])

    def test_json_paths_and_where(self):
        m365 = json.dumps([{"category": "Optimize", "ips": ["13.107.6.152/31", "2603:1006::/40"],
                            "urls": ["*.outlook.com", "outlook.office.com"]},
                           {"category": "Default", "ips": ["52.0.0.0/8"]}])
        self.assertEqual(len(ips(e.parse_json(m365, paths=["[].ips[]"]))), 3)
        self.assertEqual(ips(e.parse_json(m365, paths=["[].ips[]"], where={"category": ["Optimize"]})),
                         [N("13.107.6.152/31"), N("2603:1006::/40")])
        self.assertEqual(e.to_items("domain", e.parse_json(m365, paths=["[].urls[]"]), {}),
                         ["*.outlook.com", "outlook.office.com"])
        tor = json.dumps({"relays": [{"or_addresses": ["198.51.100.7:9001", "[2001:db8::7]:9001"],
                                      "exit_addresses": ["198.51.100.8"]}]})
        self.assertEqual(set(ips(e.parse_json(tor, paths=["relays[].exit_addresses[]", "relays[].or_addresses[]"]))),
                         {N("198.51.100.7/32"), N("2001:db8::7/128"), N("198.51.100.8/32")})

    def test_hosts_format(self):
        text = "# hosts\n127.0.0.1\tlocalhost\n127.0.0.1\tBad.Example.COM.\n0.0.0.0 a.test b.test # x\n"
        self.assertEqual(e.to_items("domain", e.parse_hosts(text), {}), ["bad.example.com", "a.test", "b.test"])

    def test_domain_normalisation(self):
        self.assertEqual(e.normalize_domain("HTTP://Evil.Example.com:8080/path"), "evil.example.com")
        self.assertEqual(e.normalize_domain("*.outlook.com"), "*.outlook.com")
        for bad in ("1.2.3.4", "not a domain", "-bad.com", "localhost", ""):
            with self.assertRaises(ValueError, msg=bad):
                e.normalize_domain(bad)

    def test_url_normalisation(self):
        self.assertEqual(e.normalize_url("http://Evil.EXAMPLE.com/Path?a=1#frag"), "evil.example.com/Path?a=1")
        self.assertEqual(e.normalize_url("https://x.test/a", strip_scheme=False), "https://x.test/a")
        with self.assertRaises(ValueError):
            e.normalize_url("ftp://x.test/a")
        with self.assertRaises(ValueError):
            e.normalize_url("http://x.test/" + "a" * 300)
        # URLs keep ; , # handling sane in plain files
        self.assertEqual(e.parse_plain("http://x.test/a;b,c\n", item_type="url"), ["http://x.test/a;b,c"])


class CsvAndAsnTests(unittest.TestCase):
    def test_csv_column_and_threshold(self):
        text = ('# "first_seen","id","ioc","type","x","y","z","w","v","confidence"\n'
                '"2026-10-04", "1", "46.246.6.4:2703", "ip:port", "c", "f", "n", "A", "", "75"\n'
                '"2026-10-04", "2", "45.86.60.114:5656", "ip:port", "c", "f", "n", "B", "", "50"\n')
        self.assertEqual(ips(e.parse_csv(text, column=2, min_column=9, min_value=75)), [N("46.246.6.4/32")])
        self.assertEqual(len(e.parse_csv(text, column=2)), 2)

    def test_asn_drop_expansion(self):
        filler = "".join(f"10.{i // 256}.{i % 256}.0\t10.{i // 256}.{i % 256}.255\t64512\tZZ\tFILL\n" for i in range(1100))
        db = ("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
              "198.51.100.0\t198.51.100.255\t64666\tXX\tBADNET\n"
              "203.0.113.0\t203.0.113.127\t64666\tXX\tBADNET\n"
              "2001:db8:bad::\t2001:db8:bad:ffff:ffff:ffff:ffff:ffff\t64666\tXX\tBADNET\n" + filler)
        asn_up, db_up = Upstream(), Upstream()
        try:
            asn_up.body = '{"asn":64666,"asname":"BADNET"}\n{"asn":64999,"asname":"GONE"}\n{"type":"metadata"}\n'
            db_up.body = db
            cfg = {"sources": {"a": {"url": asn_up.url, "format": "spamhaus-asn-json", "asn_database": db_up.url,
                                     "min_entries": 2}},
                   "feeds": {"f": {"sources": ["a"]}}}
            with tempfile.TemporaryDirectory() as d:
                agg = make(cfg, d)
                agg.tick(force=True)
                self.assertTrue(agg.sources["a"].status["ok"], agg.sources["a"].status["error"])
                self.assertEqual(agg.get("f").text,
                                 "198.51.100.0/24\n203.0.113.0/25\n2001:db8:bad::/48\n")
                db_up.status = 500                      # database download fails -> cached copy is used
                os.utime(next(Path(d, "cache").glob("asn-db-*.tsv")), (0, 0))
                asn_up.etag = '"v2"'
                agg.tick(force=True)
                self.assertTrue(agg.sources["a"].status["ok"])
                self.assertEqual(agg.get("f").count, 3)
        finally:
            asn_up.close()
            db_up.close()


class PaginationAndStatusTests(unittest.TestCase):
    def test_follows_next_page_links(self):
        pages = {}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = pages.get(self.path.split("?")[0], "").encode()
                self.send_response(200 if body else 404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_port}"
        pages["/p1"] = json.dumps({"results": [{"indicator": "198.51.100.1"}], "next": base + "/p2"})
        pages["/p2"] = json.dumps({"results": [{"indicator": "2001:db8::2"}], "next": base + "/p3"})
        pages["/p3"] = json.dumps({"results": [{"indicator": "203.0.113.3"}], "next": None})
        try:
            cfg = {"sources": {"o": {"url": base + "/p1", "format": "json", "paths": ["results[].indicator"],
                                     "next_page": "next", "min_entries": 3}},
                   "feeds": {"f": {"sources": ["o"]}}}
            with tempfile.TemporaryDirectory() as d:
                agg = make(cfg, d)
                agg.tick(force=True)
                self.assertTrue(agg.sources["o"].status["ok"], agg.sources["o"].status["error"])
                self.assertEqual(agg.get("f").text, "198.51.100.1/32\n203.0.113.3/32\n2001:db8::2/128\n")
                pages["/p2"] = ""                       # a missing middle page fails the refresh, cache kept
                agg.tick(force=True)
                self.assertFalse(agg.sources["o"].status["ok"])
                self.assertIn("page 2", agg.sources["o"].status["error"])
                self.assertEqual(agg.get("f").count, 3)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_cached_source_reports_ok_at_startup(self):
        up = Upstream()
        try:
            up.body = "192.0.2.1\n"
            cfg = {"sources": {"s": {"url": up.url}}, "feeds": {"f": {"sources": ["s"]}}}
            with tempfile.TemporaryDirectory() as d:
                make(cfg, d).tick(force=True)
                fresh = make(cfg, d)                      # restart: served from cache, not yet re-checked
                self.assertTrue(fresh.sources["s"].status["ok"])
                self.assertEqual(fresh.get("f").text, "192.0.2.1/32\n")
        finally:
            up.close()


class SetTests(unittest.TestCase):
    def test_subtract(self):
        self.assertEqual(e.collapse(e.subtract([N("10.0.0.0/24")], [N("10.0.0.128/25")])), [N("10.0.0.0/25")])
        self.assertEqual(e.subtract([N("10.0.0.0/25")], [N("10.0.0.0/24")]), [])
        self.assertEqual(e.subtract([N("10.0.0.0/24")], [N("::/0")]), [N("10.0.0.0/24")])

    def test_domain_and_url_exclusion(self):
        doms = ["a.evil.test", "evil.test", "good.test", "x.good.test"]
        self.assertEqual(e.exclude_items("domain", doms, ["good.test"]), ["a.evil.test", "evil.test"])
        urls = ["s3.amazonaws.com/bad/payload.exe", "amazonaws.com/", "evil.test/x", "evil.test/keep"]
        # never_block_domains only removes bare-host URLs
        self.assertEqual(e.exclude_items("url", urls, [], ["amazonaws.com"]),
                         ["s3.amazonaws.com/bad/payload.exe", "evil.test/x", "evil.test/keep"])
        # feed allow-list domains remove every URL on that host; URL prefixes remove matching URLs
        self.assertEqual(e.exclude_items("url", urls, ["amazonaws.com", "evil.test/x"]), ["evil.test/keep"])


# ------------------------------------------------------------------ aggregator

class AggregatorTests(unittest.TestCase):
    def test_feed_build_confidence_family_alias(self):
        cfg = {"sources": {"a": {"entries": ["1.1.1.0/24", "2001:db8::/32"], "confidence": 100},
                           "b": {"entries": ["1.1.2.0/24"], "confidence": 60},
                           "wl": {"entries": ["1.1.1.128/25"]}},
               "feeds": {"hc": {"sources": ["a", "b"], "exclude": ["wl"], "family": "ipv4", "min_confidence": 76,
                                "aliases": ["inboundfeedhc"]},
                         "mc": {"sources": ["a", "b"], "min_confidence": 50, "max_confidence": 75}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            self.assertEqual(agg.get("hc").text, "1.1.1.0/25\n")
            self.assertIs(agg.get("inboundfeedhc"), agg.get("hc"))
            self.assertEqual(agg.get("mc").text, "1.1.2.0/24\n")
            self.assertTrue(agg.status()["healthy"])

    def test_never_block_only_applies_to_block_feeds(self):
        cfg = {"safety": {"never_block": ["10.0.0.0/8"], "never_block_domains": ["mine.test"]},
               "sources": {"s": {"entries": ["10.1.0.0/16", "203.0.113.0/24"]},
                           "d": {"type": "domain", "entries": ["mine.test", "www.mine.test", "evil.test"]}},
               "feeds": {"blk": {"sources": ["s"]}, "bog": {"sources": ["s"], "kind": "bogon"},
                         "alw": {"sources": ["s"], "kind": "allow"},
                         "dblk": {"sources": ["d"]}, "dalw": {"sources": ["d"], "kind": "allow"}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            self.assertEqual(agg.get("blk").text, "203.0.113.0/24\n")
            self.assertIn("10.1.0.0/16", agg.get("bog").text)
            self.assertIn("10.1.0.0/16", agg.get("alw").text)
            self.assertEqual(agg.get("dblk").text, "evil.test\n")
            self.assertEqual(agg.get("dalw").count, 3)

    def test_feed_type_validation(self):
        cfg = {"sources": {"i": {"entries": ["192.0.2.1"]}, "d": {"type": "domain", "entries": ["x.test"]}},
               "feeds": {"mixed": {"sources": ["i", "d"]}}}
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            make(cfg, d)
        cfg["feeds"] = {"f": {"sources": ["i"], "exclude": ["d"]}}
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            make(cfg, d)

    def test_disabled_source_contributes_nothing_and_is_not_required(self):
        cfg = {"sources": {"on": {"entries": ["192.0.2.0/24"]},
                           "off": {"url": "${EDL_TEST_UNSET_URL}", "enabled": False, "min_entries": 5}},
               "feeds": {"f": {"sources": ["on", "off"]}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            agg.tick(force=True)
            self.assertEqual(agg.get("f").text, "192.0.2.0/24\n")
            self.assertTrue(agg.status()["healthy"])

    def test_failed_download_keeps_cache_and_alerts(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "cache").mkdir()
            (Path(d) / "cache" / "s.txt").write_text("198.51.100.0/24\n")
            cfg = {"sources": {"s": {"url": "http://127.0.0.1:9/never"}}, "feeds": {"f": {"sources": ["s"]}}}
            agg = make(cfg, d)
            agg.tick(force=True)
            agg.tick(force=True)
            self.assertEqual(agg.get("f").text, "198.51.100.0/24\n")
            self.assertEqual(agg.sources["s"].status["consecutive_failures"], 2)
            self.assertEqual(agg.alerter.sent[0][1], "warning")

    def test_conditional_get_and_shrink_protection(self):
        up = Upstream()
        try:
            up.body = "".join(f"198.51.100.{i}\n" for i in range(100))
            cfg = {"safety": {"max_shrink_percent": 50},
                   "sources": {"s": {"url": up.url, "min_entries": 1}}, "feeds": {"f": {"sources": ["s"]}}}
            with tempfile.TemporaryDirectory() as d:
                agg = make(cfg, d)
                self.assertTrue(agg.tick(force=True))
                self.assertEqual(agg.get("f").count, 3)                   # .0-.99 -> /26 + /27 + /30
                self.assertFalse(agg.tick(force=True))                    # 304 -> unchanged
                self.assertEqual(up.last_headers.get("If-None-Match"), '"v1"')
                up.body, up.etag = "198.51.100.1\n", '"v2"'               # shrinks 100 -> 1 entry
                self.assertFalse(agg.tick(force=True))
                self.assertIn("shrank", agg.sources["s"].status["error"])
                self.assertEqual(agg.get("f").count, 3)                   # still serving the good copy
        finally:
            up.close()

    def test_min_entries_counts_raw_entries_not_collapsed(self):
        up = Upstream()
        try:
            up.body = "".join(f"192.251.226.{i}\n" for i in range(256))     # 256 lines -> one /24
            cfg = {"sources": {"s": {"url": up.url, "min_entries": 200}}, "feeds": {"f": {"sources": ["s"]}}}
            with tempfile.TemporaryDirectory() as d:
                agg = make(cfg, d)
                agg.tick(force=True)
                self.assertTrue(agg.sources["s"].status["ok"])
                self.assertEqual(agg.get("f").text, "192.251.226.0/24\n")
        finally:
            up.close()

    def test_domain_and_url_sources_from_upstream(self):
        up = Upstream()
        try:
            up.body = "0.0.0.0 Bad.test\n0.0.0.0 worse.test\n"
            cfg = {"sources": {"d": {"type": "domain", "format": "hosts", "url": up.url, "min_entries": 1}},
                   "feeds": {"f": {"sources": ["d"]}}}
            with tempfile.TemporaryDirectory() as d:
                agg = make(cfg, d)
                agg.tick(force=True)
                self.assertEqual(agg.get("f").text, "bad.test\nworse.test\n")
                agg2 = make(cfg, d)                                        # reload from cache
                self.assertEqual(agg2.get("f").text, "bad.test\nworse.test\n")
        finally:
            up.close()

    def test_max_entries_keep_last(self):
        cfg = {"sources": {"s": {"entries": ["192.0.2.1"]}}, "feeds": {"f": {"sources": ["s"], "max_entries": 2}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            first = agg.get("f")
            agg.sources["s"].entries_static = ["192.0.2.1", "198.51.100.1", "203.0.113.1"]
            agg.sources["s"]._load_static()
            agg.rebuild()
            self.assertIs(agg.get("f"), first)
            self.assertTrue(any("too large" in t for t, _ in agg.alerter.sent))

    def test_lookup(self):
        cfg = {"safety": {"never_block": ["10.0.0.0/8"]},
               "sources": {"s": {"entries": ["203.0.113.0/24", "2001:db8::/32"]},
                           "d": {"type": "domain", "entries": ["evil.test"]},
                           "u": {"type": "url", "entries": ["http://evil2.test/payload"]}},
               "feeds": {"f": {"sources": ["s"]}, "fd": {"sources": ["d"]}, "fu": {"sources": ["u"]}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            self.assertEqual(list(agg.lookup(ip="2001:db8::99")["in_feeds"]), ["f"])
            self.assertTrue(agg.lookup(ip="10.1.2.3")["never_block"])
            self.assertEqual(agg.lookup(domain="a.b.evil.test")["in_feeds"], {"fd": ["evil.test"]})
            r = agg.lookup(url="https://evil2.test/payload?x=1")
            self.assertEqual(r["in_feeds"], {"fu": ["evil2.test/payload"]})
            self.assertEqual(agg.lookup(url="http://www.evil.test/x")["in_feeds"], {"fd": ["evil.test"]})

    def test_metrics(self):
        cfg = {"sources": {"s": {"entries": ["203.0.113.0/24", "2001:db8::/32"]}}, "feeds": {"f": {"sources": ["s"]}}}
        with tempfile.TemporaryDirectory() as d:
            m = make(cfg, d).metrics()
            self.assertIn('edl_feed_entries{feed="f",type="ip",kind="block"} 2', m)
            self.assertIn("edl_healthy 1", m)

    def test_env_expansion_in_headers(self):
        os.environ["EDL_TEST_KEY"] = "secret123"
        with tempfile.TemporaryDirectory() as d:
            src = e.Source("x", {"url": "http://h/${EDL_TEST_KEY}", "headers": {"Key": "${EDL_TEST_KEY}"}},
                           Path(d), {"refresh_minutes": 60, "max_shrink_percent": 50})
        self.assertEqual(src.headers["Key"], "secret123")
        self.assertEqual(src.url, "http://h/secret123")

    def test_example_config_parses(self):
        cfg = tomllib.loads(EXAMPLE.read_text())
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)     # validates sources/feeds without downloading
            self.assertIsNotNone(agg.get("inboundfeedhc"))
            self.assertEqual(agg.get("bogons-v6-compact").count, 7)
            self.assertEqual(agg.feeds["malware-urls"].type, "url")
            self.assertEqual(agg.feeds["malware-domains"].type, "domain")


# ------------------------------------------------------------------ dynamic lists + HTTP

class DynamicAndHttpTests(unittest.TestCase):
    CFG = {"api": {"token": "t0ken"},
           "safety": {"never_block": ["10.0.0.0/8"]},
           "dynamic": {"blk": {"type": "ip"}, "dom": {"type": "domain"}},
           "sources": {"s": {"entries": ["203.0.113.0/24"]}},
           "feeds": {"f": {"sources": ["s"]}, "dyn": {"sources": ["blk"]}, "dd": {"sources": ["dom"]},
                     "secret": {"sources": ["s"], "basic_auth": {"username": "u", "password": "p"}},
                     "lan": {"sources": ["s"], "allow_clients": ["192.0.2.0/24"]}}}
    AUTH = {"Authorization": "Bearer t0ken"}

    def test_dynamic_api_flow(self):
        with tempfile.TemporaryDirectory() as d:
            agg = make(self.CFG, d)
            s = Served(agg)
            try:
                self.assertEqual(s.req("/api/dynamic/blk", "POST", {"entries": ["198.51.100.7"]})[0], 401)
                code, body, _ = s.req("/api/dynamic/blk", "POST",
                                      {"entries": ["198.51.100.7", "10.9.9.9", "nope"], "ttl_minutes": 0.01,
                                       "comment": "test"}, self.AUTH)
                self.assertEqual(code, 200)
                self.assertEqual(json.loads(body)["rejected"], ["nope"])
                # never_block still protects 10.9.9.9 in the block feed
                self.assertEqual(s.req("/feeds/dyn")[1], b"198.51.100.7/32\n")
                s.req("/api/dynamic/dom", "POST", {"entries": ["Evil.Test"]}, self.AUTH)
                self.assertEqual(s.req("/feeds/dd")[1], b"evil.test\n")
                listing = json.loads(s.req("/api/dynamic/blk", headers=self.AUTH)[1])
                self.assertEqual(listing["198.51.100.7/32"]["comment"], "test")
                # persisted: a new aggregator sees the entries
                self.assertIn("evil.test", make(self.CFG, d).get("dd").text)
                # expiry
                time.sleep(1)
                agg.tick()
                self.assertEqual(s.req("/feeds/dyn")[1], b"")
                # delete
                s.req("/api/dynamic/dom?entry=evil.test", "DELETE", headers=self.AUTH)
                self.assertEqual(s.req("/feeds/dd")[1], b"")
                self.assertEqual(s.req("/api/dynamic/nolist", headers=self.AUTH)[0], 404)
            finally:
                s.close()

    def test_api_disabled_without_token(self):
        cfg = {k: v for k, v in self.CFG.items() if k != "api"}
        with tempfile.TemporaryDirectory() as d:
            s = Served(make(cfg, d))
            try:
                self.assertEqual(s.req("/api/dynamic", headers=self.AUTH)[0], 404)
            finally:
                s.close()

    def test_feed_access_control_and_etag(self):
        with tempfile.TemporaryDirectory() as d:
            s = Served(make(self.CFG, d))
            try:
                code, body, h = s.req("/feeds/f?tr=1")
                self.assertEqual((code, body), (200, b"203.0.113.0/24\n"))
                self.assertEqual(s.req("/feeds/f", headers={"If-None-Match": h["ETag"]})[0], 304)
                self.assertEqual(s.req("/feeds/secret")[0], 401)
                good = "Basic " + base64.b64encode(b"u:p").decode()
                bad = "Basic " + base64.b64encode(b"u:x").decode()
                self.assertEqual(s.req("/feeds/secret", headers={"Authorization": good})[0], 200)
                self.assertEqual(s.req("/feeds/secret", headers={"Authorization": bad})[0], 401)
                self.assertEqual(s.req("/feeds/lan")[0], 403)          # 127.0.0.1 not in 192.0.2.0/24
                self.assertEqual(json.loads(s.req("/lookup?domain=x.y.test")[1])["type"], "domain")
                self.assertIn(b"edl_feed_entries", s.req("/metrics")[1])
            finally:
                s.close()


class ReloadTests(unittest.TestCase):
    def test_reload_valid_and_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "config.toml"
            cfg.write_text('[sources.s]\nentries = ["192.0.2.1"]\n[feeds.f]\nsources = ["s"]\n')
            rt = e.Runtime(cfg, Path(d))
            self.assertEqual(rt.agg.get("f").text, "192.0.2.1/32\n")
            time.sleep(0.01)
            cfg.write_text('[sources.s]\nentries = ["192.0.2.2"]\n[feeds.f]\nsources = ["s"]\n')
            os.utime(cfg, (time.time() + 5, time.time() + 5))
            self.assertTrue(rt.maybe_reload())
            self.assertEqual(rt.agg.get("f").text, "192.0.2.2/32\n")
            cfg.write_text('[feeds.f]\nsources = ["missing"]\n')
            os.utime(cfg, (time.time() + 10, time.time() + 10))
            self.assertFalse(rt.maybe_reload())                         # rejected, old config kept
            self.assertEqual(rt.agg.get("f").text, "192.0.2.2/32\n")
            self.assertIn("unknown source", rt.reload_error)

    def test_check_cli(self):
        self.assertEqual(e.main(["--check", "--config", str(EXAMPLE), "--data", tempfile.mkdtemp()]), 0)
        bad = Path(tempfile.mkdtemp()) / "bad.toml"
        bad.write_text('[feeds.f]\nsources = ["nope"]\n')
        self.assertEqual(e.main(["--check", "--config", str(bad)]), 1)


if __name__ == "__main__":
    unittest.main()
