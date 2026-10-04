import ipaddress
import json
import sys
import tempfile
import threading
import tomllib
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import edl_aggregator as e  # noqa: E402

N = ipaddress.ip_network


class Upstream:
    """Tiny HTTP server serving mutable content with ETag support, to test fetching behaviour offline."""

    def __init__(self):
        self.body, self.etag, self.status, self.hits = "", '"v1"', 200, 0
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


class ParserTests(unittest.TestCase):
    def test_plain(self):
        text = "# comment\n1.2.3.4\n10.0.0.0/8 ; note\n\n// x\n192.0.2.1-192.0.2.6\nbogus\n2001:db8::/32\n"
        got = e.parse_plain(text)
        self.assertIn(N("1.2.3.4/32"), got)
        self.assertIn(N("10.0.0.0/8"), got)
        self.assertIn(N("2001:db8::/32"), got)
        self.assertEqual(set(e.collapse([n for n in got if str(n).startswith("192.0.2.")])),
                         {N("192.0.2.1/32"), N("192.0.2.2/31"), N("192.0.2.4/31"), N("192.0.2.6/32")})

    def test_ports_stripped(self):
        self.assertEqual(e.parse_entry("[2001:db8::1]:9001"), [N("2001:db8::1/128")])
        self.assertEqual(e.parse_entry("192.0.2.9:443"), [N("192.0.2.9/32")])
        self.assertEqual(e.parse_entry("2001:db8::5"), [N("2001:db8::5/128")])  # bare v6 untouched

    def test_spamhaus_json(self):
        text = '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n{"type":"metadata","timestamp":1}\n'
        self.assertEqual(e.parse_spamhaus_json(text), [N("1.10.16.0/20")])

    def test_dshield(self):
        text = "# DShield\nStart\tEnd\tNetblock\tAttacks\n45.148.10.0\t45.148.10.255\t24\t1234\tX\tNL\n"
        self.assertEqual(e.parse_dshield(text), [N("45.148.10.0/24")])

    def test_aws(self):
        text = json.dumps({"prefixes": [
            {"ip_prefix": "3.5.0.0/19", "service": "S3", "region": "us-east-1"},
            {"ip_prefix": "3.0.0.0/15", "service": "EC2", "region": "us-east-1"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/40", "service": "S3", "region": "us-west-2"}]})
        self.assertEqual(e.parse_aws_json(text, service="S3"), [N("3.5.0.0/19"), N("2600:1f00::/40")])
        self.assertEqual(e.parse_aws_json(text, service="S3", region="us-east-1"), [N("3.5.0.0/19")])

    def test_json_paths(self):
        google = json.dumps({"prefixes": [{"ipv4Prefix": "8.8.4.0/24"}, {"ipv6Prefix": "2001:4860::/32"}]})
        self.assertEqual(e.parse_json(google, paths=["prefixes[].ipv4Prefix", "prefixes[].ipv6Prefix"]),
                         [N("8.8.4.0/24"), N("2001:4860::/32")])
        github = json.dumps({"hooks": ["192.30.252.0/22", "2606:50c0::/32"], "web": ["140.82.112.0/20"]})
        self.assertEqual(e.parse_json(github, paths=["hooks[]"]), [N("192.30.252.0/22"), N("2606:50c0::/32")])
        m365 = json.dumps([{"category": "Optimize", "ips": ["13.107.6.152/31", "2603:1006::/40"]},
                           {"category": "Default", "ips": ["52.0.0.0/8"]}, {"category": "Allow"}])
        self.assertEqual(len(e.parse_json(m365, paths=["[].ips[]"])), 3)
        self.assertEqual(e.parse_json(m365, paths=["[].ips[]"], where={"category": ["Optimize", "Allow"]}),
                         [N("13.107.6.152/31"), N("2603:1006::/40")])
        tor = json.dumps({"relays": [{"or_addresses": ["198.51.100.7:9001", "[2001:db8::7]:9001"],
                                      "exit_addresses": ["198.51.100.8"]}]})
        self.assertEqual(set(e.parse_json(tor, paths=["relays[].exit_addresses[]", "relays[].or_addresses[]"])),
                         {N("198.51.100.7/32"), N("2001:db8::7/128"), N("198.51.100.8/32")})


class SetTests(unittest.TestCase):
    def test_subtract_hole(self):
        self.assertEqual(e.collapse(e.subtract([N("10.0.0.0/24")], [N("10.0.0.128/25")])), [N("10.0.0.0/25")])

    def test_subtract_whole(self):
        self.assertEqual(e.subtract([N("10.0.0.0/25")], [N("10.0.0.0/24")]), [])

    def test_subtract_other_family(self):
        self.assertEqual(e.subtract([N("10.0.0.0/24")], [N("::/0")]), [N("10.0.0.0/24")])


def make(cfg, d):
    return e.Aggregator(cfg, Path(d), alerter=RecordingAlerter())


class RecordingAlerter(e.Alerter):
    def __init__(self):
        super().__init__({"after_failures": 2})
        self.sent = []

    def send(self, title, body, kind="warning"):
        self.sent.append((title, kind))


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
        cfg = {"safety": {"never_block": ["10.0.0.0/8"]},
               "sources": {"s": {"entries": ["10.1.0.0/16", "203.0.113.0/24"]}},
               "feeds": {"blk": {"sources": ["s"]}, "bog": {"sources": ["s"], "kind": "bogon"},
                         "alw": {"sources": ["s"], "kind": "allow"}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            self.assertEqual(agg.get("blk").text, "203.0.113.0/24\n")
            self.assertIn("10.1.0.0/16", agg.get("bog").text)
            self.assertIn("10.1.0.0/16", agg.get("alw").text)

    def test_disabled_source_contributes_nothing_and_is_not_required(self):
        cfg = {"sources": {"on": {"entries": ["192.0.2.0/24"]},
                           "off": {"url": "http://127.0.0.1:9/x", "enabled": False, "min_entries": 5}},
               "feeds": {"f": {"sources": ["on", "off"]}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            agg.tick(force=True)
            self.assertEqual(agg.get("f").text, "192.0.2.0/24\n")
            self.assertTrue(agg.status()["healthy"])

    def test_failed_download_keeps_cache_and_alerts(self):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "cache"
            cache.mkdir()
            (cache / "s.txt").write_text("198.51.100.0/24\n")
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
                self.assertTrue(agg.tick(force=True))                     # first fetch: changed
                self.assertEqual(agg.get("f").count, 3)                   # .0-.99 collapses to /26 + /27 + /30
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

    def test_max_entries_keep_last(self):
        cfg = {"sources": {"s": {"entries": ["192.0.2.1"]}},
               "feeds": {"f": {"sources": ["s"], "max_entries": 2}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            first = agg.get("f")
            agg.sources["s"].entries_static = ["192.0.2.1", "198.51.100.1", "203.0.113.1"]
            agg.sources["s"]._load_static()
            agg.rebuild()
            self.assertIs(agg.get("f"), first)               # previous build kept
            self.assertTrue(any("too large" in t for t, _ in agg.alerter.sent))

    def test_lookup_and_metrics(self):
        cfg = {"safety": {"never_block": ["10.0.0.0/8"]},
               "sources": {"s": {"entries": ["203.0.113.0/24", "2001:db8::/32"]}},
               "feeds": {"f": {"sources": ["s"]}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            r = agg.lookup("2001:db8::99")
            self.assertEqual(r["in_feeds"], ["f"])
            self.assertEqual(r["in_sources"], ["s"])
            self.assertTrue(agg.lookup("10.1.2.3")["never_block"])
            m = agg.metrics()
            self.assertIn('edl_feed_entries{feed="f",kind="block"} 2', m)
            self.assertIn("edl_healthy 1", m)

    def test_http_etag_304(self):
        cfg = {"sources": {"s": {"entries": ["203.0.113.0/24"]}}, "feeds": {"f": {"sources": ["s"]}}}
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)
            srv = ThreadingHTTPServer(("127.0.0.1", 0), e.make_handler(agg))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{srv.server_port}"
            try:
                with urllib.request.urlopen(base + "/feeds/f?tr=1") as r:
                    etag = r.headers["ETag"]
                    self.assertEqual(r.read(), b"203.0.113.0/24\n")
                req = urllib.request.Request(base + "/feeds/f", headers={"If-None-Match": etag})
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 304)
                with urllib.request.urlopen(base + "/lookup?ip=203.0.113.5") as r:
                    self.assertEqual(json.load(r)["in_feeds"], ["f"])
                with urllib.request.urlopen(base + "/metrics") as r:
                    self.assertIn(b"edl_feed_entries", r.read())
            finally:
                srv.shutdown()

    def test_env_expansion_in_headers(self):
        import os
        os.environ["EDL_TEST_KEY"] = "secret123"
        src = e.Source("x", {"url": "http://h/${EDL_TEST_KEY}", "headers": {"Key": "${EDL_TEST_KEY}"}},
                       Path(tempfile.mkdtemp()), {"refresh_minutes": 60, "max_shrink_percent": 50})
        self.assertEqual(src.headers["Key"], "secret123")
        self.assertEqual(src.url, "http://h/secret123")

    def test_example_config_parses(self):
        cfg = tomllib.loads((Path(e.__file__).with_name("config.example.toml")).read_text())
        with tempfile.TemporaryDirectory() as d:
            agg = make(cfg, d)     # validates sources/feeds without downloading
            self.assertIsNotNone(agg.get("inboundfeedhc"))
            self.assertEqual(agg.get("bogons-v6-compact").count, 7)


if __name__ == "__main__":
    unittest.main()
