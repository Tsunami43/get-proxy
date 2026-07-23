"""Tests for the preload / recheck / find_one operations.

The network layer is replaced: fetch_all and check_all are the only pieces that
dial out, so both are patched and every assertion is about what ops does with
the store around them.
"""

import unittest
from unittest import mock

from getproxy import ops
from getproxy.check import Judge
from getproxy.fetch import Pool
from getproxy.proxy import Protocol, Proxy, Result
from getproxy.store import STATUS_DEAD, STATUS_WORKING, Filters, Store


def _proxy(host, proto=Protocol.HTTP):
    return Proxy(host=host, port=8080, protocol=proto)


def _ok(proxy, latency=100, cc="RU", anon=True, https=False, anonymity=""):
    return Result(proxy=proxy, ok=True, latency_ms=latency, exit_ip="9.9.9.9",
                  country_code=cc, country="Russia", anonymous=anon,
                  https=https, anonymity=anonymity)


def _fail(proxy):
    return Result(proxy=proxy, ok=False, error="timeout")


def _pool(proxies, protocol=Protocol.HTTP):
    pool = Pool()
    pool.proxies[protocol] = list(proxies)
    return pool


def _ctx(**kw):
    kw.setdefault("revive_days", 0)
    return ops.Context(judge=Judge.parse("http://judge.test/"), my_ip="203.0.113.7", **kw)


class _OpsCase(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def patch(self, *, pool=None, results=None):
        """Patch the two network entry points ops calls."""
        if pool is not None:
            self.enterContext(mock.patch.object(ops, "fetch_all", return_value=pool))
        if results is not None:
            select = lambda proxies, *a, **kw: [r for r in results if r.proxy in proxies]
            checker = mock.Mock(side_effect=select)
            self.enterContext(mock.patch.object(ops, "check_all", checker))
            # find_one streams instead of batching; a list is a fine stand-in
            # for the generator, and an early break just stops iterating it.
            self.enterContext(mock.patch.object(ops, "check_iter",
                                                mock.Mock(side_effect=select)))
            return checker
        return None


class TestPreload(_OpsCase):
    def test_records_the_whole_pool_then_checks_within_the_limit(self):
        proxies = [_proxy(f"10.0.0.{i}") for i in range(5)]
        self.patch(pool=_pool(proxies), results=[_ok(p) for p in proxies])
        out = ops.preload(self.store, _ctx(), None, limit=2)
        # Every fetched proxy is known...
        self.assertEqual(self.store.total(), 5)
        self.assertEqual(out.new_seen, 5)
        # ...but only the limit was actually checked.
        self.assertEqual(out.checked, 2)

    def test_skips_known_dead(self):
        alive, dead = _proxy("10.0.0.1"), _proxy("10.0.0.2")
        self.store.record(_fail(dead), max_fails=1)
        self.patch(pool=_pool([alive, dead]), results=[_ok(alive)])
        out = ops.preload(self.store, _ctx(), None)
        self.assertEqual(out.skipped_dead, 1)
        self.assertEqual(out.checked, 1)

    def test_revives_before_deciding_what_to_skip(self):
        p = _proxy("10.0.0.1")
        self.store.record(_fail(p), max_fails=1)
        self.store.db.execute("UPDATE proxies SET last_checked='2000-01-01T00:00:00+00:00'")
        self.store.db.commit()
        self.patch(pool=_pool([p]), results=[_ok(p)])
        out = ops.preload(self.store, _ctx(revive_days=7), None)
        self.assertEqual(out.revived, 1)
        self.assertEqual(out.skipped_dead, 0)
        self.assertEqual(out.checked, 1)

    def test_results_are_sorted_by_latency(self):
        slow, fast = _proxy("10.0.0.1"), _proxy("10.0.0.2")
        self.patch(pool=_pool([slow, fast]),
                   results=[_ok(slow, latency=900), _ok(fast, latency=10)])
        out = ops.preload(self.store, _ctx(), None)
        self.assertEqual([r.latency_ms for r in out.results], [10, 900])

    def test_failures_reach_the_store(self):
        p = _proxy("10.0.0.1")
        self.patch(pool=_pool([p]), results=[_fail(p)])
        ops.preload(self.store, _ctx(max_fails=1), None)
        self.assertEqual(self.store.details(p.key)["status"], STATUS_DEAD)


class TestRecheck(_OpsCase):
    def test_counts_survivors_and_casualties(self):
        alive, gone = _proxy("10.0.0.1"), _proxy("10.0.0.2")
        for p in (alive, gone):
            self.store.record(_ok(p))
        self.patch(results=[_ok(alive), _fail(gone)])
        out = ops.recheck(self.store, _ctx(max_fails=1))
        self.assertEqual((out.checked, out.still_working, out.newly_dead), (2, 1, 1))
        self.assertEqual(self.store.details(gone.key)["status"], STATUS_DEAD)
        self.assertEqual(self.store.details(alive.key)["status"], STATUS_WORKING)

    def test_empty_store_does_not_call_the_checker(self):
        checker = self.patch(results=[])
        out = ops.recheck(self.store, _ctx())
        self.assertEqual(out.checked, 0)
        checker.assert_not_called()

    def test_unchecked_feed_entries_are_not_rechecked(self):
        # seen() only records existence; there is no verdict to re-verify yet.
        self.store.seen([_proxy("10.0.0.1")])
        checker = self.patch(results=[])
        ops.recheck(self.store, _ctx())
        checker.assert_not_called()


class TestFindOne(_OpsCase):
    def test_prefers_the_store_and_confirms_it(self):
        p = _proxy("10.0.0.1")
        self.store.record(_ok(p))
        with mock.patch.object(ops, "check_one", return_value=_ok(p)) as confirm, \
             mock.patch.object(ops, "fetch_all") as fetched:
            res = ops.find_one(self.store, _ctx(), Filters())
        self.assertEqual(res.proxy.key, p.key)
        confirm.assert_called_once()
        fetched.assert_not_called()  # no feed scan when the store delivers

    def test_falls_back_to_a_feed_scan_when_the_candidate_is_dead(self):
        stale, fresh = _proxy("10.0.0.1"), _proxy("10.0.0.2")
        self.store.record(_ok(stale))
        self.patch(pool=_pool([fresh]), results=[_ok(fresh)])
        with mock.patch.object(ops, "check_one", return_value=_fail(stale)):
            res = ops.find_one(self.store, _ctx(), Filters())
        self.assertEqual(res.proxy.key, fresh.key)

    def test_stops_at_the_first_match(self):
        # Every candidate would match; the scan must return the first and stop,
        # not drain the rest.
        proxies = [_proxy(f"10.0.0.{i}") for i in range(10)]
        self.patch(pool=_pool(proxies), results=[_ok(p) for p in proxies])
        scanned = []
        res = ops.find_one(self.store, _ctx(), Filters(),
                           on_scan=lambda done, total: scanned.append(done))
        self.assertEqual(res.proxy.key, proxies[0].key)
        self.assertEqual(scanned[-1], 1)  # broke after the very first result

    def test_country_filter_rejects_a_live_but_wrong_proxy(self):
        ru, us = _proxy("10.0.0.1"), _proxy("10.0.0.2")
        self.patch(pool=_pool([ru, us]),
                   results=[_ok(ru, cc="RU"), _ok(us, cc="US")])
        res = ops.find_one(self.store, _ctx(), Filters(country_code="US"))
        self.assertEqual(res.country_code, "US")

    def test_records_outcomes_scanned_before_the_hit(self):
        miss, hit = _proxy("10.0.0.1"), _proxy("10.0.0.2")
        self.patch(pool=_pool([miss, hit]),
                   results=[_ok(miss, cc="RU"), _ok(hit, cc="US")])
        ops.find_one(self.store, _ctx(), Filters(country_code="US"), flush_every=1)
        # Both the rejected proxy and the hit are persisted.
        self.assertEqual(self.store.details(miss.key)["status"], STATUS_WORKING)
        self.assertEqual(self.store.details(hit.key)["status"], STATUS_WORKING)

    def test_returns_none_when_nothing_matches(self):
        p = _proxy("10.0.0.1")
        self.patch(pool=_pool([p]), results=[_ok(p, cc="RU")])
        self.assertIsNone(ops.find_one(self.store, _ctx(), Filters(country_code="JP")))


class TestMatches(unittest.TestCase):
    """_matches guards the filters that SQL cannot apply to a fresh result."""

    def test_country_is_case_insensitive(self):
        res = _ok(_proxy("10.0.0.1"), cc="ru")
        self.assertTrue(ops._matches(res, Filters(country_code="RU")))

    def test_anonymous_only(self):
        res = _ok(_proxy("10.0.0.1"), anon=False)
        self.assertFalse(ops._matches(res, Filters(anonymous_only=True)))

    def test_latency_ceiling(self):
        res = _ok(_proxy("10.0.0.1"), latency=500)
        self.assertFalse(ops._matches(res, Filters(max_latency_ms=100)))
        self.assertTrue(ops._matches(res, Filters(max_latency_ms=500)))

    def test_https_only(self):
        res = _ok(_proxy("10.0.0.1"), https=False)
        self.assertFalse(ops._matches(res, Filters(https_only=True)))

    def test_elite_only_rejects_a_merely_anonymous_proxy(self):
        res = _ok(_proxy("10.0.0.1"), anonymity="anonymous")
        self.assertFalse(ops._matches(res, Filters(elite_only=True)))
        self.assertTrue(ops._matches(_ok(_proxy("10.0.0.2"), anonymity="elite"),
                                     Filters(elite_only=True)))

    def test_empty_filters_accept_anything_live(self):
        self.assertTrue(ops._matches(_ok(_proxy("10.0.0.1")), Filters()))


if __name__ == "__main__":
    unittest.main()
