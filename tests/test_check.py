"""Tests for judge-body parsing and the Judge constructor (no network)."""

import unittest

from getproxy.check import DEFAULT_JUDGE, Judge, JudgeError, _parse_body


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


class TestJudgeRefusal(unittest.TestCase):
    """ip-api answers {"status":"fail"} when it rate-limits; that is not a proxy fault."""

    def test_fail_payload_raises(self):
        with self.assertRaises(JudgeError):
            _parse_body(b'{"status":"fail","message":"rate limit exceeded"}')

    def test_message_is_carried(self):
        with self.assertRaises(JudgeError) as caught:
            _parse_body(b'{"status":"fail","message":"reserved range"}')
        self.assertIn("reserved range", str(caught.exception))

    def test_success_payload_does_not_raise(self):
        ip, cc, _ = _parse_body(b'{"status":"success","query":"5.6.7.8","countryCode":"RU"}')
        self.assertEqual((ip, cc), ("5.6.7.8", "RU"))

    def test_plain_body_without_ip_is_a_proxy_fault_not_a_judge_one(self):
        # No JudgeError here: an unparseable body means the proxy mangled it.
        self.assertEqual(_parse_body(b"<html>blocked</html>")[0], "")


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
