"""Tests for source-body parsing and registry integrity (no network)."""

import unittest

from getproxy.fetch import _parse_geonode, _parse_text
from getproxy.proxy import Protocol
from getproxy.sources import INDEX, SOURCES, Kind


class TestParseText(unittest.TestCase):
    def test_mixed_lines(self):
        body = b"1.1.1.1:80\n# comment\n\nsocks5://2.2.2.2:1080\n3.3.3.3:3128 RU\n"
        proxies = _parse_text(body, Protocol.HTTP)
        self.assertEqual(len(proxies), 3)
        self.assertEqual({p.addr for p in proxies},
                         {"1.1.1.1:80", "2.2.2.2:1080", "3.3.3.3:3128"})
        self.assertTrue(all(p.protocol is Protocol.HTTP for p in proxies))


class TestParseGeonode(unittest.TestCase):
    def test_self_describing(self):
        body = (
            b'{"data":[{"ip":"4.4.4.4","port":"8080","protocols":["socks5","http"]},'
            b'{"ip":"5.5.5.5","port":"1080","protocols":["socks4"]}]}'
        )
        proxies = _parse_geonode(body, None)
        keys = {p.key for p in proxies}
        self.assertIn("socks5|4.4.4.4:8080", keys)
        self.assertIn("http|4.4.4.4:8080", keys)
        self.assertIn("socks4|5.5.5.5:1080", keys)

    def test_respects_want_filter(self):
        body = b'{"data":[{"ip":"4.4.4.4","port":"8080","protocols":["socks5","http"]}]}'
        proxies = _parse_geonode(body, {Protocol.SOCKS5})
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].protocol, Protocol.SOCKS5)


class TestRegistry(unittest.TestCase):
    def test_all_urls_https(self):
        for src in SOURCES:
            self.assertTrue(src.url.startswith("https://"), src.url)

    def test_text_sources_have_protocol(self):
        for src in SOURCES:
            if src.kind is Kind.TEXT:
                self.assertIsNotNone(src.protocol, src.url)

    def test_no_duplicate_urls(self):
        urls = [s.url for s in SOURCES]
        self.assertEqual(len(urls), len(set(urls)))

    def test_index_nonempty(self):
        # Sources die and get pruned over time; this is a populated-registry
        # smoke check, not an exact count.
        self.assertGreaterEqual(len(INDEX), 5)


if __name__ == "__main__":
    unittest.main()
