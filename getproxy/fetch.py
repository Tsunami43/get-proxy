"""Download the configured proxy feeds concurrently into a deduplicated pool.

Standard library only: ``urllib`` for HTTP and ``concurrent.futures`` for
parallelism.
"""

from __future__ import annotations

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .proxy import Protocol, Proxy, parse, parse_protocol
from .sources import SOURCES, Kind, Source

# Realistic User-Agent: some sources answer 403 to the default urllib agent.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Upper bound on a feed body size so a misbehaving source cannot exhaust memory.
_MAX_BODY = 16 << 20  # 16 MiB


@dataclass(slots=True)
class SourceStat:
    """Outcome of fetching one feed."""

    url: str
    count: int = 0
    error: str = ""


@dataclass(slots=True)
class Pool:
    """Aggregated, deduplicated result of a fetch run."""

    proxies: dict[Protocol, list[Proxy]] = field(default_factory=dict)
    stats: list[SourceStat] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Number of unique proxies across all protocols."""
        return sum(len(v) for v in self.proxies.values())


def _http_get(url: str, timeout: float) -> bytes:
    """Download a URL with a browser UA and return a size-capped body."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted https feeds)
        return resp.read(_MAX_BODY)


def _parse_text(body: bytes, protocol: Protocol) -> list[Proxy]:
    """Parse a plain "ip:port" list, assigning every entry the source protocol."""
    out: list[Proxy] = []
    for line in body.decode("utf-8", "ignore").splitlines():
        p = parse(line, protocol)
        if p is not None:
            out.append(p)
    return out


def _parse_geonode(body: bytes, want: set[Protocol] | None) -> list[Proxy]:
    """Parse the geonode JSON API, whose entries name their own protocols."""
    payload = json.loads(body.decode("utf-8", "ignore"))
    out: list[Proxy] = []
    for entry in payload.get("data", []):
        ip = entry.get("ip") or ""
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if not ip:
            continue
        for raw in entry.get("protocols", []):
            proto = parse_protocol(raw)
            if proto is None or (want is not None and proto not in want):
                continue
            out.append(Proxy(host=ip, port=port, protocol=proto))
    return out


def _fetch_one(src: Source, want: set[Protocol] | None, timeout: float) -> tuple[SourceStat, list[Proxy]]:
    """Download and parse a single source."""
    stat = SourceStat(url=src.url)
    try:
        body = _http_get(src.url, timeout)
        if src.kind is Kind.GEONODE:
            proxies = _parse_geonode(body, want)
        else:
            proxies = _parse_text(body, src.protocol)  # type: ignore[arg-type]
        stat.count = len(proxies)
        return stat, proxies
    except Exception as exc:  # network/parse errors must not abort the whole run
        stat.error = f"{type(exc).__name__}: {exc}"
        return stat, []


def fetch_all(
    want: set[Protocol] | None = None,
    *,
    timeout: float = 20.0,
    workers: int = 32,
) -> Pool:
    """Fetch every feed for the wanted protocols in parallel, deduplicated.

    ``want`` is the set of wanted protocols (``None`` = all). Individual feed
    failures are recorded in :attr:`Pool.stats` rather than aborting the run.
    """
    targets = [
        src for src in SOURCES
        # A TEXT source has a fixed protocol we can skip early; GEONODE is
        # self-describing, so it always runs when any protocol is wanted.
        if src.kind is Kind.GEONODE or want is None or src.protocol in want
    ]

    pool = Pool()
    seen: set[str] = set()

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool_exec:
        for stat, proxies in pool_exec.map(lambda s: _fetch_one(s, want, timeout), targets):
            pool.stats.append(stat)
            for p in proxies:
                if p.key in seen:
                    continue
                seen.add(p.key)
                pool.proxies.setdefault(p.protocol, []).append(p)

    for proto in pool.proxies:
        pool.proxies[proto].sort(key=lambda p: (p.host, p.port))
    return pool
