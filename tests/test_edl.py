import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import edl_aggregator as e  # noqa: E402

N = ipaddress.ip_network


class ParserTests(unittest.TestCase):
    def test_plain(self):
        text = "# comment\n1.2.3.4\n10.0.0.0/8 ; note\n\n// x\n192.0.2.1-192.0.2.6\nbogus\n2001:db8::/32\n"
        got = e.parse_plain(text)
        self.assertIn(N("1.2.3.4/32"), got)
        self.assertIn(N("10.0.0.0/8"), got)
        self.assertIn(N("2001:db8::/32"), got)
        self.assertEqual(set(e.collapse([n for n in got if str(n).startswith("192.0.2.")])),
                         {N("192.0.2.1/32"), N("192.0.2.2/31"), N("192.0.2.4/31"), N("192.0.2.6/32")})

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


class SetTests(unittest.TestCase):
    def test_subtract_hole(self):
        got = e.collapse(e.subtract([N("10.0.0.0/24")], [N("10.0.0.128/25")]))
        self.assertEqual(got, [N("10.0.0.0/25")])

    def test_subtract_whole(self):
        self.assertEqual(e.subtract([N("10.0.0.0/25")], [N("10.0.0.0/24")]), [])

    def test_subtract_other_family(self):
        self.assertEqual(e.subtract([N("10.0.0.0/24")], [N("::/0")]), [N("10.0.0.0/24")])


class AggregatorTests(unittest.TestCase):
    def test_feed_build_confidence_family_alias(self):
        cfg = {
            "sources": {
                "a": {"entries": ["1.1.1.0/24", "2001:db8::/32"], "confidence": 100},
                "b": {"entries": ["1.1.2.0/24"], "confidence": 60},
                "wl": {"entries": ["1.1.1.128/25"]},
            },
            "feeds": {
                "hc": {"sources": ["a", "b"], "exclude": ["wl"], "family": "ipv4", "min_confidence": 76,
                       "aliases": ["inboundfeedhc"]},
                "mc": {"sources": ["a", "b"], "min_confidence": 50, "max_confidence": 75},
            },
        }
        with tempfile.TemporaryDirectory() as d:
            agg = e.Aggregator(cfg, Path(d))
            agg.refresh()
            self.assertEqual(agg.get("hc"), "1.1.1.0/25\n")
            self.assertEqual(agg.get("inboundfeedhc"), agg.get("hc"))
            self.assertEqual(agg.get("mc"), "1.1.2.0/24\n")
            self.assertTrue(agg.status()["healthy"])

    def test_failed_download_keeps_cache(self):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "cache"
            cache.mkdir()
            (cache / "s.txt").write_text("198.51.100.0/24\n")
            cfg = {"sources": {"s": {"url": "http://127.0.0.1:9/never", "min_entries": 1}},
                   "feeds": {"f": {"sources": ["s"]}}}
            agg = e.Aggregator(cfg, Path(d))
            agg.refresh()  # download fails
            self.assertEqual(agg.get("f"), "198.51.100.0/24\n")
            self.assertFalse(agg.sources["s"].status["ok"])

    def test_example_config_parses(self):
        import tomllib
        cfg = tomllib.loads((Path(e.__file__).with_name("config.example.toml")).read_text())
        with tempfile.TemporaryDirectory() as d:
            agg = e.Aggregator(cfg, Path(d))  # validates sources/feeds without downloading
            self.assertIn("inboundfeedhc", agg.published)


if __name__ == "__main__":
    unittest.main()
