"""Tests for the persistent store: statuses, filters, dead logic."""

import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from getproxy.proxy import Protocol, Proxy, Result
from getproxy.store import (
    _SCHEMA,
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


def _judge_error(proxy):
    return Result(proxy=proxy, ok=False, error="judge refused: rate limit", judge_error=True)


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


class TestSchemaMigration(unittest.TestCase):
    """An older store must survive an upgrade instead of needing deletion."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "old.db")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _make_pre_https_db(self):
        """Build a store with the 0.2.0 schema — no https column."""
        db = sqlite3.connect(self.path)
        db.executescript(_SCHEMA.replace("    https        INTEGER NOT NULL DEFAULT 0,\n", ""))
        db.execute(
            "INSERT INTO proxies(key,protocol,host,port,status,first_seen,last_seen) "
            "VALUES('http|1.2.3.4:8080','http','1.2.3.4',8080,'working','x','x')")
        db.commit()
        db.close()

    def test_adds_the_missing_column(self):
        self._make_pre_https_db()
        with Store(self.path) as store:
            cols = {r["name"] for r in store.db.execute("PRAGMA table_info(proxies)")}
        self.assertIn("https", cols)

    def test_keeps_existing_rows(self):
        self._make_pre_https_db()
        with Store(self.path) as store:
            self.assertEqual(store.total(), 1)
            self.assertEqual(store.details("http|1.2.3.4:8080")["https"], 0)

    def test_is_idempotent(self):
        self._make_pre_https_db()
        Store(self.path).close()
        Store(self.path).close()  # must not raise "duplicate column name"
        with Store(self.path) as store:
            self.assertEqual(store.total(), 1)


class TestHttpsFilter(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_filters_to_tls_capable_only(self):
        tls, plain = _proxy("1.1.1.1"), _proxy("2.2.2.2")
        self.store.record(Result(proxy=tls, ok=True, latency_ms=10, exit_ip="9.9.9.9", https=True))
        self.store.record(Result(proxy=plain, ok=True, latency_ms=10, exit_ip="9.9.9.9"))
        got = self.store.query(Filters(https_only=True))
        self.assertEqual([p.key for p in got], [tls.key])

    def test_best_keeps_every_filter(self):
        # Regression: best() used to rebuild Filters positionally, so a new
        # field silently shifted the others by one.
        plain = _proxy("2.2.2.2")
        self.store.record(Result(proxy=plain, ok=True, latency_ms=10, exit_ip="9.9.9.9"))
        self.assertIsNone(self.store.best(Filters(https_only=True)))


class TestJudgeErrorIsNotProxyFailure(unittest.TestCase):
    """A refusal by the judge must never count against the proxy."""

    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_does_not_increment_fail_count(self):
        p = _proxy()
        self.store.record(_ok(p))
        status = self.store.record(_judge_error(p), max_fails=1)
        self.assertEqual(status, STATUS_WORKING)
        row = self.store.details(p.key)
        self.assertEqual(row["fail_count"], 0)

    def test_cannot_kill_a_proxy_even_at_max_fails_one(self):
        p = _proxy()
        self.store.record(_ok(p))
        for _ in range(5):
            self.store.record(_judge_error(p), max_fails=1)
        self.assertEqual(self.store.details(p.key)["status"], STATUS_WORKING)
        self.assertIsNotNone(self.store.best(Filters()))

    def test_records_the_attempt(self):
        p = _proxy()
        self.store.record(_ok(p))
        before = self.store.details(p.key)["last_checked"]
        self.store.record(_judge_error(p))
        self.assertNotEqual(self.store.details(p.key)["last_checked"], "")
        self.assertIsNotNone(before)

    def test_unknown_proxy_is_not_inserted(self):
        # Nothing was learned, so there is nothing to write down.
        self.assertEqual(self.store.record(_judge_error(_proxy())), STATUS_UNKNOWN)
        self.assertEqual(self.store.total(), 0)


class TestReviveDead(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def _kill(self, proxy, days_ago):
        self.store.record(_fail(proxy), max_fails=1)
        stamp = (datetime.now(timezone.utc) - timedelta(days=days_ago)).replace(
            microsecond=0).isoformat()
        self.store.db.execute("UPDATE proxies SET last_checked=? WHERE key=?",
                              (stamp, proxy.key))
        self.store.db.commit()

    def test_revives_only_the_stale(self):
        old, fresh = _proxy("1.1.1.1"), _proxy("2.2.2.2")
        self._kill(old, days_ago=30)
        self._kill(fresh, days_ago=1)
        self.assertEqual(self.store.revive_dead(7), 1)
        self.assertEqual(self.store.details(old.key)["status"], STATUS_UNKNOWN)
        self.assertEqual(self.store.details(fresh.key)["status"], STATUS_DEAD)

    def test_revived_proxy_leaves_the_skip_set(self):
        p = _proxy()
        self._kill(p, days_ago=30)
        self.assertIn(p.key, self.store.dead_keys())
        self.store.revive_dead(7)
        self.assertNotIn(p.key, self.store.dead_keys())

    def test_resets_fail_count_so_it_gets_a_full_budget(self):
        p = _proxy()
        self._kill(p, days_ago=30)
        self.store.revive_dead(7)
        self.assertEqual(self.store.details(p.key)["fail_count"], 0)

    def test_zero_disables_the_sweep(self):
        p = _proxy()
        self._kill(p, days_ago=999)
        self.assertEqual(self.store.revive_dead(0), 0)
        self.assertEqual(self.store.details(p.key)["status"], STATUS_DEAD)


if __name__ == "__main__":
    unittest.main()
