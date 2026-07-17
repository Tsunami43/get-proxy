"""Tests for address and protocol parsing."""

import unittest

from getproxy.proxy import Protocol, Result, is_ipv4, parse, parse_protocol


class TestParse(unittest.TestCase):
    def test_plain(self):
        p = parse("1.2.3.4:8080", Protocol.HTTP)
        self.assertIsNotNone(p)
        self.assertEqual(p.host, "1.2.3.4")
        self.assertEqual(p.port, 8080)
        self.assertEqual(p.protocol, Protocol.HTTP)
        self.assertEqual(p.url, "http://1.2.3.4:8080")

    def test_strips_scheme(self):
        p = parse("socks5://9.9.9.9:1080", Protocol.SOCKS5)
        self.assertEqual(p.addr, "9.9.9.9:1080")

    def test_strips_trailing_column(self):
        p = parse("5.5.5.5:3128 US elite", Protocol.HTTP)
        self.assertEqual(p.addr, "5.5.5.5:3128")

    def test_tab_column(self):
        p = parse("7.7.7.7:1080\t120ms", Protocol.SOCKS4)
        self.assertEqual(p.port, 1080)

    def test_rejects_blank_and_comment(self):
        self.assertIsNone(parse("", Protocol.HTTP))
        self.assertIsNone(parse("   ", Protocol.HTTP))
        self.assertIsNone(parse("# comment", Protocol.HTTP))

    def test_rejects_bad_port(self):
        self.assertIsNone(parse("1.2.3.4:99999", Protocol.HTTP))
        self.assertIsNone(parse("1.2.3.4:abc", Protocol.HTTP))
        self.assertIsNone(parse("1.2.3.4", Protocol.HTTP))

    def test_key_dedup(self):
        a = parse("1.1.1.1:80", Protocol.HTTP)
        b = parse("http://1.1.1.1:80", Protocol.HTTP)
        self.assertEqual(a.key, b.key)


class TestProtocol(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(parse_protocol("https"), Protocol.HTTP)
        self.assertEqual(parse_protocol("SOCKS5H"), Protocol.SOCKS5)
        self.assertEqual(parse_protocol("socks4a"), Protocol.SOCKS4)
        self.assertIsNone(parse_protocol("garbage"))

    def test_str(self):
        self.assertEqual(str(Protocol.HTTP), "http")


class TestHelpers(unittest.TestCase):
    def test_is_ipv4(self):
        self.assertTrue(is_ipv4("8.8.8.8"))
        self.assertFalse(is_ipv4("999.1.1.1"))
        self.assertFalse(is_ipv4("::1"))

    def test_result_dict(self):
        p = parse("1.2.3.4:8080", Protocol.HTTP)
        res = Result(proxy=p, ok=True, latency_ms=120, exit_ip="5.6.7.8", anonymous=True)
        d = res.to_dict()
        self.assertEqual(d["protocol"], "http")
        self.assertTrue(d["anonymous"])
        self.assertEqual(d["latency_ms"], 120)


if __name__ == "__main__":
    unittest.main()
