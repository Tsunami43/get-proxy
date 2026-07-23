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


class TestMenuLaunch(unittest.TestCase):
    """The menu path needs a TTY, so nothing else here exercises it.

    Regression: run() passed Context knobs straight to Menu(), which does not
    take them, and every menu launch died with TypeError.
    """

    def _launch(self, argv):
        with mock.patch.object(cli, "_wants_menu", return_value=True), \
             mock.patch("getproxy.menu.Menu.run", return_value=0) as run, \
             redirect_stdout(io.StringIO()):
            code = cli.run([*argv, "--db", ":memory:"])
        return code, run

    def test_bare_run_constructs_the_menu(self):
        code, run = self._launch([])
        self.assertEqual(code, 0)
        run.assert_called_once()

    def test_every_run_flag_is_accepted_on_the_menu_path(self):
        # Whatever the CLI accepts, the menu must be constructible with.
        code, _ = self._launch([
            "--max-fails", "5", "--revive-after", "2", "--verify-https",
            "--check-anonymity", "-t", "3", "--connect-timeout", "2",
            "--fetch-timeout", "9", "-w", "10",
        ])
        self.assertEqual(code, 0)

    def test_the_context_factory_carries_the_flags(self):
        args = cli._parse_args(["--max-fails", "5", "--revive-after", "2",
                                "--verify-https", "--check-anonymity"])
        with mock.patch.object(cli, "Context") as ctx:
            cli._context(args)
        kw = ctx.build.call_args.kwargs
        self.assertEqual(kw["max_fails"], 5)
        self.assertEqual(kw["revive_days"], 2)
        self.assertTrue(kw["https_target"])
        self.assertTrue(kw["anon_judge_url"])


if __name__ == "__main__":
    unittest.main()
