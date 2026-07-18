"""Tests for judge-body parsing and the Judge constructor (no network)."""

import unittest

from getproxy.check import DEFAULT_JUDGE, Judge, _parse_body


class TestParseBody(unittest.TestCase):
    def test_ipapi_json(self):
        body = b'{"status":"success","query":"5.6.7.8","countryCode":"RU","country":"Russia"}'
        ip, cc, country = _parse_body(body)
        self.assertEqual(ip, "5.6.7.8")
        self.assertEqual(cc, "RU")
        self.assertEqual(country, "Russia")

    def test_plain_ip(self):
        ip, cc, country = _parse_body(b"5.6.7.8\n")
        self.assertEqual(ip, "5.6.7.8")
        self.assertEqual(cc, "")
        self.assertEqual(country, "")

    def test_garbage(self):
        ip, cc, country = _parse_body(b"<html>nope</html>")
        self.assertEqual(ip, "")

    def test_broken_json_falls_back_to_regex(self):
        ip, _, _ = _parse_body(b'{"query":"9.9.9.9" broken')
        self.assertEqual(ip, "9.9.9.9")


class TestJudge(unittest.TestCase):
    def test_default_is_http(self):
        j = Judge.parse(DEFAULT_JUDGE)
        self.assertEqual(j.host, "ip-api.com")
        self.assertEqual(j.port, 80)
        self.assertTrue(j.path.startswith("/json/"))

    def test_rejects_https(self):
        with self.assertRaises(ValueError):
            Judge.parse("https://example.com/")


if __name__ == "__main__":
    unittest.main()
