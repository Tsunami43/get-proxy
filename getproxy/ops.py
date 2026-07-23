"""High-level getproxy operations on top of fetch + check + store.

Shared by both the CLI and the interactive menu so the logic lives in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .check import DEFAULT_JUDGE, Judge, check_all, check_iter, check_one, local_ip
from .fetch import fetch_all
from .proxy import ALL_PROTOCOLS, Protocol, Proxy, Result
from .store import STATUS_WORKING, Filters, Store

# Progress callback: (done, total).
Progress = Callable[[int, int], None]


@dataclass(slots=True)
class Context:
    """Shared parameters for check runs."""

    judge: Judge
    my_ip: str
    timeout: float = 8.0
    connect_timeout: float = 5.0
    fetch_timeout: float = 20.0
    workers: int = 200
    max_fails: int = 3
    revive_days: int = 7
    # Empty = skip the TLS probe entirely (it doubles the work per proxy).
    https_target: str = ""
    # None = skip anonymity grading.
    anon_judge: Judge | None = None

    @classmethod
    def build(cls, judge_url: str = DEFAULT_JUDGE, *, timeout: float = 8.0,
              connect_timeout: float = 5.0, fetch_timeout: float = 20.0,
              workers: int = 200, max_fails: int = 3, revive_days: int = 7,
              https_target: str = "", anon_judge_url: str = "") -> "Context":
        judge = Judge.parse(judge_url)
        return cls(judge=judge, my_ip=local_ip(judge, timeout),
                   timeout=timeout, connect_timeout=connect_timeout,
                   fetch_timeout=fetch_timeout, workers=workers, max_fails=max_fails,
                   revive_days=revive_days, https_target=https_target,
                   anon_judge=Judge.parse(anon_judge_url) if anon_judge_url else None)


@dataclass(slots=True)
class PreloadResult:
    fetched: int = 0
    feeds_ok: int = 0
    feeds_total: int = 0
    checked: int = 0
    skipped_dead: int = 0
    revived: int = 0
    new_seen: int = 0
    results: list[Result] = field(default_factory=list)


def _order(want: set[Protocol] | None) -> list[Protocol]:
    return [p for p in ALL_PROTOCOLS if want is None or p in want]


def preload(
    store: Store, ctx: Context, want: set[Protocol] | None, *,
    limit: int = 0,
    on_fetch_done: Callable[[int, int, int], None] | None = None,
    on_progress: Callable[[Protocol, int, int], None] | None = None,
) -> PreloadResult:
    """Fetch the sources, check the proxies and record the outcome in the store.

    ``limit`` caps how many proxies per protocol are checked (0 = all).
    """
    pool = fetch_all(want, timeout=ctx.fetch_timeout, workers=32)
    feeds_ok = sum(1 for s in pool.stats if not s.error)

    out = PreloadResult(fetched=pool.total, feeds_ok=feeds_ok, feeds_total=len(pool.stats))
    if on_fetch_done:
        on_fetch_done(pool.total, feeds_ok, len(pool.stats))

    # Everything the feeds carry goes into the store as ``unknown``, including
    # what ``limit`` will cut from this run — otherwise a limited run throws away
    # the rest of the pool and the next run has to re-fetch it to learn anything.
    for proxies in pool.proxies.values():
        out.new_seen += store.seen(proxies)

    # Give long-dead proxies another chance before we decide what to skip.
    out.revived = store.revive_dead(ctx.revive_days)

    # Skip proxies already known to be dead — no point burning a timeout on them.
    dead = store.dead_keys()

    for proto in _order(want):
        proxies = pool.proxies.get(proto, [])
        if dead:
            kept = [p for p in proxies if p.key not in dead]
            out.skipped_dead += len(proxies) - len(kept)
            proxies = kept
        if limit > 0:
            proxies = proxies[:limit]
        if not proxies:
            continue
        cb = (lambda d, t, _p=proto: on_progress(_p, d, t)) if on_progress else None
        results = check_all(proxies, ctx.judge, timeout=ctx.timeout,
                            connect_timeout=ctx.connect_timeout,
                            workers=ctx.workers, my_ip=ctx.my_ip,
                            https_target=ctx.https_target, anon_judge=ctx.anon_judge, on_progress=cb)
        store.record_many(results, max_fails=ctx.max_fails)
        out.checked += len(proxies)
        out.results.extend(results)

    out.results.sort(key=lambda r: r.latency_ms)
    return out


@dataclass(slots=True)
class RecheckResult:
    checked: int = 0
    still_working: int = 0
    newly_dead: int = 0


def recheck(
    store: Store, ctx: Context, filters: Filters | None = None, *,
    on_progress: Progress | None = None,
) -> RecheckResult:
    """Recheck recent proxies (everything but the already-dead ones).

    Any proxy that drops on the check is marked ``dead`` and thereafter excluded
    from results and from further rechecks.
    """
    proxies = store.recheckable(filters)
    out = RecheckResult()
    if not proxies:
        return out

    results = check_all(proxies, ctx.judge, timeout=ctx.timeout,
                        connect_timeout=ctx.connect_timeout,
                        workers=ctx.workers, my_ip=ctx.my_ip,
                        https_target=ctx.https_target, anon_judge=ctx.anon_judge, on_progress=on_progress)
    store.record_many(results, max_fails=ctx.max_fails)
    ok_keys = {r.proxy.key for r in results if r.ok}

    out.checked = len(proxies)
    out.still_working = len(ok_keys)
    out.newly_dead = len(proxies) - len(ok_keys)
    return out


def find_one(
    store: Store, ctx: Context, filters: Filters, *,
    flush_every: int = 200,
    on_scan: Callable[[int, int], None] | None = None,
) -> Result | None:
    """Quickly hand back one working proxy under the filters.

    First try the best candidate from the store and confirm it with a fresh
    check. If the store is empty, stream checks over the live feeds and return
    the first match, recording outcomes along the way.
    """
    # 1) Candidate from the store.
    best = store.best(filters)
    if best is not None:
        res = check_one(best, ctx.judge, ctx.timeout, ctx.my_ip, ctx.connect_timeout,
                        https_target=ctx.https_target)
        store.record(res, max_fails=ctx.max_fails)
        if res.ok and _matches(res, filters):
            return res

    # 2) Scan of fresh sources.
    want = filters.protocols
    pool = fetch_all(want, timeout=ctx.fetch_timeout, workers=32)
    store.revive_dead(ctx.revive_days)
    dead = store.dead_keys()
    candidates: list[Proxy] = []
    for proto in _order(want):
        candidates.extend(p for p in pool.proxies.get(proto, []) if p.key not in dead)

    total = len(candidates)
    scanned = 0
    hit: Result | None = None
    pending: list[Result] = []  # buffered so the DB still commits in batches
    stream = check_iter(candidates, ctx.judge, timeout=ctx.timeout,
                        connect_timeout=ctx.connect_timeout,
                        workers=ctx.workers, my_ip=ctx.my_ip,
                        https_target=ctx.https_target)
    for res in stream:
        pending.append(res)
        scanned += 1
        if on_scan:
            on_scan(scanned, total)
        if res.ok and _matches(res, filters):
            hit = res
            break  # closes the generator, cancelling the rest of the scan
        if len(pending) >= flush_every:
            store.record_many(pending, max_fails=ctx.max_fails)
            pending = []

    if pending:
        store.record_many(pending, max_fails=ctx.max_fails)
    return hit


def _matches(res: Result, filters: Filters) -> bool:
    """Check that a result satisfies the filters (country/anonymity/latency)."""
    if filters.country_code and res.country_code.upper() != filters.country_code.upper():
        return False
    if filters.anonymous_only and not res.anonymous:
        return False
    if filters.https_only and not res.https:
        return False
    if filters.elite_only and res.anonymity != "elite":
        return False
    if filters.max_latency_ms > 0 and res.latency_ms > filters.max_latency_ms:
        return False
    return True
