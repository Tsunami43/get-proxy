"""Tests for CLI output modes (no network, no real store).

``run`` is exercised with the network-touching pieces replaced: Context.build
would resolve our external IP and find_one would scan live feeds.
"""

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from getproxy import cli
from getproxy.proxy import Protocol, Proxy, Result

_PROXY = Proxy(host="1.2.3.4", port=8080, protocol=Protocol.HTTP)


def _result(ok=True):
    return Result(proxy=_PROXY, ok=ok, latency_ms=120, exit_ip="9.9.9.9",
                  country_code="RU", country="Russia", anonymous=True)


class _FakeContext:
    """Stands in for ops.Context so nothing dials out."""

    my_ip = "5.5.5.5"

    @classmethod
    def build(cls, *a, **kw):
        return cls()


def _run(argv, found):
    """Run the CLI with find_one stubbed, returning (exit_code, stdout)."""
    buf = io.StringIO()
    with mock.patch.object(cli, "Context", _FakeContext), \
         mock.patch.object(cli, "find_one", return_value=found), \
         redirect_stdout(buf):
        code = cli.run([*argv, "--db", ":memory:", "--no-menu"])
    return code, buf.getvalue()


class TestRawOutput(unittest.TestCase):
    def test_prints_only_the_url(self):
        code, out = _run(["--get", "--raw"], _result())
        self.assertEqual(out, "http://1.2.3.4:8080\n")
        self.assertEqual(code, 0)

    def test_usable_in_command_substitution(self):
        # $(...) strips the trailing newline; what is left must be a bare URL.
        _, out = _run(["--get", "--raw"], _result())
        self.assertEqual(out.strip(), _PROXY.url)

    def test_nothing_found_stays_silent_and_signals_by_exit_code(self):
        code, out = _run(["--get", "--raw"], None)
        self.assertEqual(out, "")
        self.assertEqual(code, 1)

    def test_country_filter_reaches_find_one(self):
        with mock.patch.object(cli, "Context", _FakeContext), \
             mock.patch.object(cli, "find_one", return_value=_result()) as found, \
             redirect_stdout(io.StringIO()):
            cli.run(["--get", "--raw", "-c", "ru", "--db", ":memory:", "--no-menu"])
        self.assertEqual(found.call_args.args[2].country_code, "ru")


class TestOtherOutputModes(unittest.TestCase):
    def test_json_still_emits_an_object(self):
        _, out = _run(["--get", "--json"], _result())
        self.assertIn('"proxy": "http://1.2.3.4:8080"', out)

    def test_human_output_is_annotated(self):
        _, out = _run(["--get"], _result())
        self.assertIn("120ms", out)
        self.assertIn("[RU]", out)

    def test_raw_never_opens_the_menu(self):
        args = cli._parse_args(["--raw"])
        self.assertFalse(cli._wants_menu(args))


if __name__ == "__main__":
    unittest.main()
