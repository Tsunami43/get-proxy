"""Tests for the persistent store: statuses, filters, dead logic."""

import unittest

from getproxy.proxy import Protocol, Proxy, Result
from getproxy.store import (
    STATUS_DEAD,
    STATUS_UNKNOWN,
    STATUS_WORKING,
    Filters,
    Store,
)


def _proxy(host="1.2.3.4", port=8080, proto=Protocol.HTTP):
    return Proxy(host=host, port=port, protocol=proto)


def _ok(proxy, latency=100, cc="RU", anon=True):
    return Result(proxy=proxy, ok=True, latency_ms=latency,
                  exit_ip="9.9.9.9", country_code=cc, country="Russia", anonymous=anon)


def _fail(proxy):
    return Result(proxy=proxy, ok=False, error="timeout")


class TestStore(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_seen_inserts_unknown(self):
        new = self.store.seen([_proxy(), _proxy("5.5.5.5", 80)])
        self.assertEqual(new, 2)
        self.assertEqual(self.store.counts_by_status().get(STATUS_UNKNOWN), 2)
        # A repeated seen does not create duplicates.
        self.assertEqual(self.store.seen([_proxy()]), 0)

    def test_record_working(self):
        p = _proxy()
        status = self.store.record(_ok(p))
        self.assertEqual(status, STATUS_WORKING)
        best = self.store.best(Filters())
        self.assertEqual(best.key, p.key)

    def test_fail_marks_dead_and_excluded(self):
        p = _proxy()
        self.store.record(_ok(p))
        # A failure with max_fails=1 → dead.
        self.assertEqual(self.store.record(_fail(p), max_fails=1), STATUS_DEAD)
        self.assertIsNone(self.store.best(Filters()))
        # dead is not among the recheckable ones.
        self.assertEqual(self.store.recheckable(), [])

    def test_fail_threshold(self):
        p = _proxy()
        self.store.seen([p])
        self.assertEqual(self.store.record(_fail(p), max_fails=2), STATUS_UNKNOWN)
        self.assertEqual(self.store.record(_fail(p), max_fails=2), STATUS_DEAD)

    def test_country_filter(self):
        ru = _proxy("1.1.1.1", 80)
        us = _proxy("2.2.2.2", 80)
        self.store.record(_ok(ru, cc="RU"))
        self.store.record(_ok(us, cc="US"))
        res = self.store.query(Filters(country_code="ru"))
        self.assertEqual([p.key for p in res], [ru.key])

    def test_latency_and_anonymous_filters(self):
        fast = _proxy("1.1.1.1", 80)
        slow = _proxy("2.2.2.2", 80)
        clear = _proxy("3.3.3.3", 80)
        self.store.record(_ok(fast, latency=50, anon=True))
        self.store.record(_ok(slow, latency=900, anon=True))
        self.store.record(_ok(clear, latency=60, anon=False))
        fast_only = self.store.query(Filters(max_latency_ms=100))
        self.assertEqual({p.key for p in fast_only}, {fast.key, clear.key})
        anon_only = self.store.query(Filters(anonymous_only=True))
        self.assertNotIn(clear.key, {p.key for p in anon_only})

    def test_purge_dead(self):
        p = _proxy()
        self.store.record(_ok(p))
        self.store.record(_fail(p), max_fails=1)
        self.assertEqual(self.store.purge_dead(), 1)
        self.assertEqual(self.store.total(), 0)

    def test_recovery_resets_fail_count(self):
        p = _proxy()
        self.store.seen([p])
        self.store.record(_fail(p), max_fails=3)
        self.store.record(_ok(p))
        row = self.store.details(p.key)
        self.assertEqual(row["fail_count"], 0)
        self.assertEqual(row["status"], STATUS_WORKING)


if __name__ == "__main__":
    unittest.main()
