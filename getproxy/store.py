"""Persistent store of known proxies on sqlite3 (standard library).

Holds every proxy getproxy has ever found or checked, with its status, country
and metrics. Key rule: a proxy with status ``dead`` (dropped on a recheck) is no
longer checked and is excluded from results.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from .proxy import Protocol, Proxy, Result

# Record statuses.
STATUS_UNKNOWN = "unknown"  # seen in a feed, not checked yet
STATUS_WORKING = "working"  # passed a check
STATUS_DEAD = "dead"        # dropped on a recheck — no longer checked

_SCHEMA = """
CREATE TABLE IF NOT EXISTS proxies (
    key          TEXT PRIMARY KEY,
    protocol     TEXT NOT NULL,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'unknown',
    country_code TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    exit_ip      TEXT NOT NULL DEFAULT '',
    anonymous    INTEGER NOT NULL DEFAULT 0,
    anonymity    TEXT NOT NULL DEFAULT '',
    https        INTEGER NOT NULL DEFAULT 0,
    latency_ms   INTEGER NOT NULL DEFAULT 0,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    last_checked TEXT NOT NULL DEFAULT '',
    last_ok      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_status  ON proxies(status);
CREATE INDEX IF NOT EXISTS idx_country ON proxies(country_code);
CREATE INDEX IF NOT EXISTS idx_proto   ON proxies(protocol);
"""

# Columns introduced after 0.2.0, applied to older stores by Store._migrate.
# Append here when the schema grows; never reorder or remove.
_ADDED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("https", "https INTEGER NOT NULL DEFAULT 0"),
    ("anonymity", "anonymity TEXT NOT NULL DEFAULT ''"),
)


def default_path() -> str:
    """Default DB path (XDG_DATA_HOME or ~/.local/share)."""
    env = os.environ.get("GETPROXY_DB")
    if env:
        return env
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "getproxy", "proxies.db")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True, slots=True)
class Filters:
    """Selection filters for pulling proxies out of the store."""

    protocols: set[Protocol] | None = None
    country_code: str = ""       # ISO code, e.g. "RU" (case-insensitive)
    anonymous_only: bool = False
    https_only: bool = False     # only proxies whose TLS probe succeeded
    elite_only: bool = False     # only proxies graded "elite" (no proxy headers)
    max_latency_ms: int = 0      # 0 = no limit
    limit: int = 0               # 0 = no limit


def _row_to_proxy(row: sqlite3.Row) -> Proxy:
    return Proxy(host=row["host"], port=row["port"], protocol=Protocol(row["protocol"]))


class Store:
    """Proxy store. Creates the DB file and schema on first use."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or default_path()
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self._migrate()
        self.db.commit()

    def _migrate(self) -> None:
        """Add columns missing from a database created by an older version.

        ``CREATE TABLE IF NOT EXISTS`` leaves an existing table alone, so new
        columns have to be added explicitly or every upgrade would need the user
        to delete their store.
        """
        have = {row["name"] for row in self.db.execute("PRAGMA table_info(proxies)")}
        for column, ddl in _ADDED_COLUMNS:
            if column not in have:
                self.db.execute(f"ALTER TABLE proxies ADD COLUMN {ddl}")

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- writes ------------------------------------------------------------

    def seen(self, proxies: list[Proxy]) -> int:
        """Mark proxies as seen in a feed: insert new ones (unknown), bump
        ``last_seen`` for known ones. A dead status is not resurrected here.
        Returns the number of first-time proxies."""
        now = _now()
        new = 0
        for p in proxies:
            cur = self.db.execute(
                "UPDATE proxies SET last_seen=? WHERE key=?", (now, p.key)
            )
            if cur.rowcount == 0:
                self.db.execute(
                    "INSERT INTO proxies(key,protocol,host,port,status,first_seen,last_seen) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (p.key, str(p.protocol), p.host, p.port, STATUS_UNKNOWN, now, now),
                )
                new += 1
        self.db.commit()
        return new

    def _apply(self, result: Result, max_fails: int, now: str) -> str:
        """Apply one check outcome to the DB (no commit). Returns the new status."""
        p = result.proxy
        row = self.db.execute("SELECT status, fail_count FROM proxies WHERE key=?", (p.key,)).fetchone()

        # A judge-side refusal is not evidence against the proxy: record that we
        # tried and leave the verdict untouched, or the store would fill up with
        # proxies killed by someone else's rate limit.
        if result.judge_error:
            if row is None:
                return STATUS_UNKNOWN
            self.db.execute("UPDATE proxies SET last_checked=? WHERE key=?", (now, p.key))
            return row["status"]

        if row is None:
            self.db.execute(
                "INSERT INTO proxies(key,protocol,host,port,status,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?,?)",
                (p.key, str(p.protocol), p.host, p.port, STATUS_UNKNOWN, now, now),
            )
            fails = 0
        else:
            fails = row["fail_count"]

        if result.ok:
            self.db.execute(
                "UPDATE proxies SET status=?, country_code=?, country=?, exit_ip=?, "
                "anonymous=?, anonymity=?, https=?, latency_ms=?, fail_count=0, "
                "last_checked=?, last_ok=? "
                "WHERE key=?",
                (STATUS_WORKING, result.country_code, result.country, result.exit_ip,
                 int(result.anonymous), result.anonymity, int(result.https),
                 result.latency_ms, now, now, p.key),
            )
            return STATUS_WORKING

        fails += 1
        status = STATUS_DEAD if fails >= max_fails else STATUS_UNKNOWN
        self.db.execute(
            "UPDATE proxies SET status=?, fail_count=?, last_checked=? WHERE key=?",
            (status, fails, now, p.key),
        )
        return status

    def record(self, result: Result, *, max_fails: int = 3) -> str:
        """Record a check outcome and return the resulting record status.

        Success → ``working`` (fail_count reset). Failure → increment fail_count;
        once it reaches ``max_fails`` the status becomes ``dead`` (the proxy will
        no longer be checked). The row is created if it did not exist.
        """
        status = self._apply(result, max_fails, _now())
        self.db.commit()
        return status

    def record_many(self, results: list[Result], *, max_fails: int = 3) -> None:
        """Record many outcomes in a single transaction (one commit for the batch).

        Prefer this over a ``record`` loop: one commit means one fsync instead of
        one per proxy, which matters on batches of thousands.
        """
        now = _now()
        for r in results:
            self._apply(r, max_fails, now)
        self.db.commit()

    def revive_dead(self, older_than_days: int) -> int:
        """Return long-dead proxies to ``unknown`` so they get another chance.

        Without this, ``dead`` is a life sentence: a proxy killed by one bad
        night is skipped forever and the candidate pool only ever shrinks. Free
        proxies come back, so anything not re-tested in ``older_than_days`` is
        worth one more look. 0 disables the sweep.
        """
        if older_than_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).replace(
            microsecond=0).isoformat()
        cur = self.db.execute(
            "UPDATE proxies SET status=?, fail_count=0 "
            "WHERE status=? AND last_checked != '' AND last_checked < ?",
            (STATUS_UNKNOWN, STATUS_DEAD, cutoff),
        )
        self.db.commit()
        return cur.rowcount

    def purge_dead(self) -> int:
        """Delete dead records from the DB. Returns the number removed."""
        cur = self.db.execute("DELETE FROM proxies WHERE status=?", (STATUS_DEAD,))
        self.db.commit()
        return cur.rowcount

    # --- reads -------------------------------------------------------------

    def query(self, filters: Filters, *, statuses: tuple[str, ...] = (STATUS_WORKING,),
              checked_only: bool = False) -> list[Proxy]:
        """Return proxies of the given statuses under the filters, sorted by latency.

        ``checked_only`` keeps only proxies that were actually checked before
        (``last_checked`` is set).
        """
        where = [f"status IN ({','.join('?' * len(statuses))})"]
        params: list = list(statuses)
        if checked_only:
            where.append("last_checked != ''")
        if filters.protocols:
            where.append(f"protocol IN ({','.join('?' * len(filters.protocols))})")
            params.extend(str(p) for p in filters.protocols)
        if filters.country_code:
            where.append("country_code = ?")
            params.append(filters.country_code.upper())
        if filters.anonymous_only:
            where.append("anonymous = 1")
        if filters.https_only:
            where.append("https = 1")
        if filters.elite_only:
            where.append("anonymity = 'elite'")
        if filters.max_latency_ms > 0:
            where.append("latency_ms > 0 AND latency_ms <= ?")
            params.append(filters.max_latency_ms)

        sql = f"SELECT * FROM proxies WHERE {' AND '.join(where)} ORDER BY latency_ms ASC, last_ok DESC"
        if filters.limit > 0:
            sql += " LIMIT ?"
            params.append(filters.limit)
        return [_row_to_proxy(r) for r in self.db.execute(sql, params).fetchall()]

    def recheckable(self, filters: Filters | None = None) -> list[Proxy]:
        """Previously-checked proxies that may be rechecked (everything but dead).

        Raw feed entries that were never checked are NOT included — we only
        recheck what we actually found alive or evaluated.
        """
        f = filters or Filters()
        return self.query(f, statuses=(STATUS_WORKING, STATUS_UNKNOWN), checked_only=True)

    def dead_keys(self) -> set[str]:
        """Keys of proxies marked ``dead`` — cheap set to skip on the next run."""
        rows = self.db.execute("SELECT key FROM proxies WHERE status=?", (STATUS_DEAD,)).fetchall()
        return {r["key"] for r in rows}

    def best(self, filters: Filters) -> Proxy | None:
        """Best working proxy under the filters (lowest latency) or None."""
        f = replace(filters, limit=1)
        rows = self.query(f)
        return rows[0] if rows else None

    def details(self, key: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM proxies WHERE key=?", (key,)).fetchone()

    # --- statistics --------------------------------------------------------

    def counts_by_status(self) -> dict[str, int]:
        rows = self.db.execute("SELECT status, COUNT(*) c FROM proxies GROUP BY status").fetchall()
        return {r["status"]: r["c"] for r in rows}

    def counts_by_protocol(self, status: str = STATUS_WORKING) -> dict[str, int]:
        rows = self.db.execute(
            "SELECT protocol, COUNT(*) c FROM proxies WHERE status=? GROUP BY protocol",
            (status,),
        ).fetchall()
        return {r["protocol"]: r["c"] for r in rows}

    def top_countries(self, limit: int = 10, status: str = STATUS_WORKING) -> list[tuple[str, int]]:
        rows = self.db.execute(
            "SELECT country_code, COUNT(*) c FROM proxies "
            "WHERE status=? AND country_code!='' GROUP BY country_code ORDER BY c DESC LIMIT ?",
            (status, limit),
        ).fetchall()
        return [(r["country_code"], r["c"]) for r in rows]

    def total(self) -> int:
        return self.db.execute("SELECT COUNT(*) c FROM proxies").fetchone()["c"]
