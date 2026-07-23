"""Interactive getproxy menu: get a proxy, filters, recheck, preload.

Opens when the tool is run with no flags on a terminal. Results are printed on
plain stdout between menu screens (raw mode is only enabled while navigating).
"""

from __future__ import annotations

import sys
from typing import Callable

from . import tui
from .ops import Context, find_one, preload, recheck
from .proxy import ALL_PROTOCOLS, Protocol, Result
from .sources import INDEX, SOURCES
from .store import STATUS_WORKING, Filters, Store

_HEADER = "  getproxy · fresh free proxies from 17 sources (45 feeds)"


def _progress(label: str):
    """Single-line progress callback for operations."""
    def cb(done: int, total: int) -> None:
        pct = (done / total * 100) if total else 100.0
        sys.stdout.write(f"\r\033[K  {tui.color(tui.ACCENT, label)}: {done}/{total} ({pct:3.0f}%)")
        if done >= total:
            sys.stdout.write("\n")
        sys.stdout.flush()
    return cb


def _print_proxy(res: Result) -> None:
    """Show a single handed-out proxy in a highlighted box."""
    tag = tui.color(tui.GOOD, "anonymous") if res.anonymous else tui.color(tui.WARN, "transparent")
    geo = f"{res.country_code} {res.country}".strip() or "—"
    lines = [
        tui.color(tui.BOLD + tui.ACCENT, res.proxy.url),
        "",
        f"{tui.color(tui.MUTED, 'protocol ')}{res.proxy.protocol}",
        f"{tui.color(tui.MUTED, 'latency  ')}{res.latency_ms} ms",
        f"{tui.color(tui.MUTED, 'country  ')}{geo}",
        f"{tui.color(tui.MUTED, 'exit     ')}{res.exit_ip}  ({tag})",
    ]
    print(tui.panel("proxy", lines))


def _print_table(proxies, store: Store, title: str) -> None:
    """Show a list of proxies from the store with their metrics."""
    if not proxies:
        print(tui.color(tui.WARN, "  Nothing found for the filters."))
        return
    lines = []
    for p in proxies:
        row = store.details(p.key)
        cc = (row["country_code"] or "--") if row else "--"
        lat = row["latency_ms"] if row else 0
        anon = "anon" if (row and row["anonymous"]) else "clear"
        lines.append(
            f"{tui.color(tui.ACCENT, p.url):<34}  "
            f"{tui.color(tui.MUTED, f'{lat:>5}ms')}  "
            f"{tui.color(tui.TEXT, f'[{cc}]')}  {tui.color(tui.MUTED, anon)}"
        )
    print(tui.panel(title, lines))


def _pick_protocols() -> set[Protocol] | None:
    """Protocol submenu. None = all."""
    opts = [
        tui.Option("All protocols", "http + socks4 + socks5"),
        tui.Option("HTTP", "http/https"),
        tui.Option("SOCKS5", "socks5"),
        tui.Option("SOCKS4", "socks4"),
    ]
    idx = tui.select("protocol", opts, header=_HEADER)
    if idx is None or idx == 0:
        return None
    return {[None, Protocol.HTTP, Protocol.SOCKS5, Protocol.SOCKS4][idx]}


class Menu:
    """State and loop of the interactive menu."""

    def __init__(self, store: Store, build_ctx: Callable[[], Context]) -> None:
        # A factory, not a copy of every Context knob: mirroring the parameters
        # here is what let the menu drift out of sync with the CLI.
        self.store = store
        self._build_ctx = build_ctx
        self._ctx: Context | None = None

    def ctx(self) -> Context:
        """Build the check context (resolving our IP) once."""
        if self._ctx is None:
            print(tui.color(tui.MUTED, "  Resolving external IP…"))
            self._ctx = self._build_ctx()
            print(tui.color(tui.MUTED, f"  My IP: {self._ctx.my_ip or 'unknown'}"))
        return self._ctx

    # --- actions -----------------------------------------------------------

    def action_get(self) -> None:
        print(tui.color(tui.ACCENT, "\n  Looking for a working proxy…"))
        res = find_one(self.store, self.ctx(), Filters(), on_scan=_progress("scan"))
        if res is None:
            print(tui.color(tui.BAD, "  No live proxy found — try Preload."))
        else:
            _print_proxy(res)
        tui.pause()

    def action_get_filtered(self) -> None:
        protocols = _pick_protocols()
        cc = tui.prompt("Country (ISO code, e.g. RU/US; empty = any)").upper()
        anon = tui.prompt("Anonymous only? (y/n)", "n").lower().startswith("y")
        lat_raw = tui.prompt("Max latency, ms (empty = any)")
        max_lat = int(lat_raw) if lat_raw.isdigit() else 0
        filters = Filters(protocols=protocols, country_code=cc,
                          anonymous_only=anon, max_latency_ms=max_lat)

        # Show what the store already has first.
        cached = self.store.query(filters, statuses=(STATUS_WORKING,))
        if cached:
            _print_table(cached[:20], self.store, f"from store ({len(cached)})")
        else:
            print(tui.color(tui.ACCENT, "\n  Store is empty for these filters — scanning feeds…"))
            res = find_one(self.store, self.ctx(), filters, on_scan=_progress("scan"))
            if res is None:
                print(tui.color(tui.BAD, "  No proxy found for these filters."))
            else:
                _print_proxy(res)
        tui.pause()

    def action_recheck(self) -> None:
        n = len(self.store.recheckable())
        if n == 0:
            print(tui.color(tui.WARN, "\n  No proxies to recheck — run Preload first."))
            tui.pause()
            return
        print(tui.color(tui.ACCENT, f"\n  Rechecking {n} recent proxies…"))
        out = recheck(self.store, self.ctx(), on_progress=_progress("check"))
        print(tui.panel("recheck", [
            f"{tui.color(tui.MUTED, 'checked ')}{out.checked}",
            f"{tui.color(tui.GOOD, 'alive   ')}{out.still_working}",
            f"{tui.color(tui.BAD, 'dropped ')}{out.newly_dead}  {tui.color(tui.MUTED, '(marked dead, no longer checked)')}",
        ]))
        tui.pause()

    def action_preload(self) -> None:
        protocols = _pick_protocols()
        lim_raw = tui.prompt("Limit per protocol (0 = all; higher = slower)", "300")
        limit = int(lim_raw) if lim_raw.isdigit() else 300
        print(tui.color(tui.ACCENT, "\n  Fetching sources and checking…"))
        out = preload(
            self.store, self.ctx(), protocols, limit=limit,
            on_fetch_done=lambda total, ok, all_: print(
                tui.color(tui.GOOD, f"  Collected {total} proxies from {ok}/{all_} feeds")),
            on_progress=lambda proto, d, t: _progress(f"check {proto}")(d, t),
        )
        alive = [r for r in out.results if r.ok]
        panel_lines = [
            f"{tui.color(tui.MUTED, 'checked ')}{out.checked}",
            f"{tui.color(tui.GOOD, 'alive   ')}{len(alive)}",
        ]
        if out.skipped_dead:
            panel_lines.append(f"{tui.color(tui.MUTED, 'skipped ')}{out.skipped_dead} known-dead")
        panel_lines.append(tui.color(tui.MUTED, 'all saved to the store'))
        print(tui.panel("preload", panel_lines))
        if alive:
            _print_table([r.proxy for r in alive[:15]], self.store, "top alive")
        tui.pause()

    def action_stats(self) -> None:
        by_status = self.store.counts_by_status()
        by_proto = self.store.counts_by_protocol()
        top = self.store.top_countries()
        lines = [
            f"{tui.color(tui.MUTED, 'total in db  ')}{self.store.total()}",
            f"{tui.color(tui.GOOD, 'working      ')}{by_status.get('working', 0)}",
            f"{tui.color(tui.WARN, 'unknown      ')}{by_status.get('unknown', 0)}",
            f"{tui.color(tui.BAD, 'dead         ')}{by_status.get('dead', 0)}",
            "",
            tui.color(tui.MUTED, "working by protocol:"),
        ]
        for proto in ALL_PROTOCOLS:
            lines.append(f"  {str(proto):<8} {by_proto.get(str(proto), 0)}")
        if top:
            lines.append("")
            lines.append(tui.color(tui.MUTED, "top countries (working):"))
            lines.append("  " + "  ".join(f"{cc}:{n}" for cc, n in top))
        print(tui.panel("statistics", lines))
        tui.pause()

    def action_sources(self) -> None:
        lines = [tui.color(tui.MUTED, f"{'SOURCE':<26}{'PROTOCOLS':<26}UPDATED")]
        for repo in INDEX:
            lines.append(f"{tui.color(tui.ACCENT, repo.name):<26}"
                         f"{tui.color(tui.TEXT, repo.kinds):<26}{tui.color(tui.MUTED, repo.cadence)}")
        print(tui.panel(f"sources · {len(SOURCES)} feeds", lines))
        tui.pause()

    # --- loop --------------------------------------------------------------

    def run(self) -> int:
        options = [
            tui.Option("Get a proxy", "first working"),
            tui.Option("Get by filters", "country · protocol · anonymity"),
            tui.Option("Recheck recent", "dropped → dead"),
            tui.Option("Preload", "fetch and check everything"),
            tui.Option("Statistics", "store status"),
            tui.Option("Sources", "feed registry"),
            tui.Option("Quit", ""),
        ]
        actions = [
            self.action_get, self.action_get_filtered, self.action_recheck,
            self.action_preload, self.action_stats, self.action_sources,
        ]
        while True:
            working = self.store.counts_by_status().get("working", 0)
            subtitle = f"working in store: {working}"
            idx = tui.select("main menu", options, subtitle=subtitle, header=_HEADER)
            if idx is None or idx == len(options) - 1:
                print(tui.color(tui.MUTED, "  Bye!"))
                return 0
            actions[idx]()
