"""Argument parsing and the getproxy pipeline.

With no flags on a terminal it opens the interactive menu; with flags or when
piped it behaves as a classic one-shot command with text or JSON output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .check import DEFAULT_ANON_JUDGE, DEFAULT_HTTPS_TARGET, DEFAULT_JUDGE
from .fetch import fetch_all
from .ops import Context, find_one, preload, recheck
from .proxy import ALL_PROTOCOLS, Protocol, Result, parse_protocol
from .sources import INDEX, SOURCES
from .store import STATUS_WORKING, Filters, Store, default_path
from .ui import Renderer


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="getproxy",
        description="Fresh free proxies from 17 public sources (45 feeds), no API keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  getproxy                       open the interactive menu\n"
            "  getproxy --get -c RU           hand out one working proxy from Russia\n"
            "  getproxy --recheck             recheck recent proxies (dropped → dead)\n"
            "  getproxy -p socks5 -l 300 -o out   preload socks5, save into ./out\n"
            "  getproxy --no-check --json     quick raw-list dump as JSON\n"
            "  getproxy --sources             source registry\n"
        ),
    )
    # Modes.
    p.add_argument("--menu", action="store_true", help="force the interactive menu")
    p.add_argument("--no-menu", action="store_true", help="never open the menu")
    p.add_argument("-g", "--get", action="store_true", help="hand out one working proxy under the filters")
    p.add_argument("-r", "--recheck", action="store_true", help="recheck recent proxies from the store")
    p.add_argument("--no-check", action="store_true", help="do not check — dump the raw list")
    p.add_argument("--purge-dead", action="store_true", help="delete dead records from the store and exit")
    p.add_argument("--sources", action="store_true", help="show the source registry and exit")

    # Filters.
    p.add_argument("-p", "--protocols", default="all", help="http,socks4,socks5 or all (default all)")
    p.add_argument("-c", "--country", default="", metavar="CC", help="ISO country code, e.g. RU")
    p.add_argument("-a", "--anonymous", action="store_true", help="anonymous only (exit != my IP)")
    p.add_argument("--https-only", action="store_true",
                   help="only proxies that passed the TLS probe (implies --verify-https)")
    p.add_argument("--elite", action="store_true",
                   help="only proxies adding no proxy headers (implies --check-anonymity)")
    p.add_argument("--max-latency", type=int, default=0, metavar="MS", help="max latency, ms")
    p.add_argument("-l", "--limit", type=int, default=0, help="max proxies per protocol (0 = all)")

    # Run parameters.
    p.add_argument("-t", "--timeout", type=float, default=8.0, help="per-proxy read timeout, s (8)")
    p.add_argument("--connect-timeout", type=float, default=5.0, help="per-proxy TCP connect timeout, s (5)")
    p.add_argument("--fetch-timeout", type=float, default=20.0, help="per-source fetch timeout, s (20)")
    p.add_argument("-w", "--workers", type=int, default=200, help="parallel checks (200)")
    p.add_argument("-j", "--judge", default=DEFAULT_JUDGE, help="http judge echoing IP+country")
    p.add_argument("--max-fails", type=int, default=3, help="failures before marking dead (default 3)")
    p.add_argument("--revive-after", type=int, default=7, metavar="DAYS",
                   help="retry dead proxies untouched for this long, 0 = never (7)")
    p.add_argument("--verify-https", action="store_true",
                   help="also probe whether the proxy can carry TLS (slower)")
    p.add_argument("--https-target", default=DEFAULT_HTTPS_TARGET, metavar="URL",
                   help="endpoint for the TLS probe")
    p.add_argument("--check-anonymity", action="store_true",
                   help="grade elite/anonymous/transparent via a header-echoing judge")
    p.add_argument("--anon-judge", default=DEFAULT_ANON_JUDGE, metavar="URL",
                   help="header-echoing judge for the anonymity grade")
    p.add_argument("--db", default="", metavar="PATH", help=f"DB path (default {default_path()})")

    # Output.
    p.add_argument("-o", "--out", metavar="DIR", help="save the result into a directory")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--raw", action="store_true",
                   help="print bare proxy URLs, one per line (for $(...) and pipes)")
    p.add_argument("--no-color", action="store_true", help="disable colour")
    p.add_argument("-V", "--version", action="version", version=f"getproxy {__version__}")
    return p.parse_args(argv)


def _https_target(args: argparse.Namespace) -> str:
    """The TLS probe endpoint, or "" when the probe is off."""
    return args.https_target if (args.verify_https or args.https_only) else ""


def _context(args: argparse.Namespace) -> Context:
    """The one place run parameters become a Context.

    Every mode and the menu go through here, so a new knob is wired once
    instead of at each call site.
    """
    return Context.build(
        args.judge, timeout=args.timeout, connect_timeout=args.connect_timeout,
        fetch_timeout=args.fetch_timeout, workers=args.workers,
        max_fails=args.max_fails, revive_days=args.revive_after,
        https_target=_https_target(args), anon_judge_url=_anon_judge(args))


def _anon_judge(args: argparse.Namespace) -> str:
    """The header-echoing judge URL, or "" when grading is off."""
    return args.anon_judge if (args.check_anonymity or args.elite) else ""


def _wanted(spec: str) -> set[Protocol] | None:
    spec = spec.strip().lower()
    if spec in ("", "all"):
        return None
    want: set[Protocol] = set()
    for token in spec.split(","):
        proto = parse_protocol(token)
        if proto is None:
            raise SystemExit(f"getproxy: unknown protocol: {token!r}")
        want.add(proto)
    return want


def _order(want: set[Protocol] | None) -> list[Protocol]:
    return [p for p in ALL_PROTOCOLS if want is None or p in want]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _filters(args: argparse.Namespace, want: set[Protocol] | None) -> Filters:
    return Filters(
        protocols=want,
        country_code=args.country,
        anonymous_only=args.anonymous,
        https_only=args.https_only,
        elite_only=args.elite,
        max_latency_ms=args.max_latency,
        limit=args.limit,
    )


def _wants_menu(args: argparse.Namespace) -> bool:
    """Whether to open the interactive menu: a bare interactive run, no actions."""
    if args.menu:
        return True
    if args.no_menu or args.json or args.raw:
        return False
    action_flags = (args.get, args.recheck, args.no_check, args.purge_dead, bool(args.out))
    if any(action_flags):
        return False
    if args.protocols != "all" or args.limit or args.country or args.anonymous or args.max_latency:
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def _print_sources(r: Renderer) -> None:
    r.banner()
    r.line(f"  Sources: {len(INDEX)}  ({len(SOURCES)} feeds)\n")
    r.line(f"  {'SOURCE':<28} {'PROTOCOLS':<26} UPDATED")
    r.line(f"  {'-' * 28} {'-' * 26} {'-' * 14}")
    for repo in INDEX:
        r.line(f"  {repo.name:<28} {repo.kinds:<26} {repo.cadence}")


def _save(out_dir: str, results: list[Result], r: Renderer) -> None:
    os.makedirs(out_dir, exist_ok=True)
    by_proto: dict[str, list[str]] = {}
    for res in results:
        by_proto.setdefault(str(res.proxy.protocol), []).append(res.proxy.addr)
    for proto, addrs in by_proto.items():
        with open(os.path.join(out_dir, f"working_{proto}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(addrs) + "\n")
    with open(os.path.join(out_dir, "working.json"), "w", encoding="utf-8") as f:
        json.dump([res.to_dict() for res in results], f, ensure_ascii=False, indent=2)
    r.good(f"Saved to {out_dir}/")


# --- modes ------------------------------------------------------------------

def _mode_get(args, store, want, r) -> int:
    ctx = _context(args)
    res = find_one(store, ctx, _filters(args, want))
    if args.raw:
        # Nothing but the URL on stdout, so `export HTTP_PROXY=$(getproxy -g --raw)`
        # works; the empty case stays silent and is signalled by the exit code.
        if res is not None:
            print(res.proxy.url)
    elif args.json:
        json.dump(res.to_dict() if res else None, sys.stdout, ensure_ascii=False, indent=2)
        print()
    elif res is None:
        r.warn("No live proxy for the filters — try preload (getproxy -p http -l 300).")
    else:
        r.good(f"Proxy: {res.proxy.url}  [{res.country_code or '--'}]  {res.latency_ms}ms")
    return 0 if res else 1


def _mode_recheck(args, store, r) -> int:
    ctx = _context(args)
    cb = None if args.json else (lambda d, t: r.progress("recheck", d, t))
    out = recheck(store, ctx, on_progress=cb)
    if args.json:
        json.dump({"checked": out.checked, "still_working": out.still_working,
                   "newly_dead": out.newly_dead}, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        r.good(f"Checked {out.checked}: alive {out.still_working}, dropped {out.newly_dead} (→ dead)")
    return 0


def _mode_no_check(args, store, want, r) -> int:
    pool = fetch_all(want, timeout=args.fetch_timeout, workers=32)
    selected: dict[Protocol, list] = {}
    for proto in _order(want):
        proxies = pool.proxies.get(proto, [])
        selected[proto] = proxies[:args.limit] if args.limit > 0 else proxies
    if args.json:
        json.dump({
            "generated_at": _now(), "checked": False,
            "counts": {str(p): len(v) for p, v in selected.items()},
            "proxies": {str(p): [x.url for x in v] for p, v in selected.items()},
        }, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        for proto in _order(want):
            r.line(f"\n  {proto} — {len(selected[proto])}")
            for x in selected[proto]:
                r.line(f"    {x.addr}")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for proto, proxies in selected.items():
            with open(os.path.join(args.out, f"all_{proto}.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(p.addr for p in proxies) + "\n")
        r.good(f"Saved to {args.out}/")
    return 0


def _mode_preload(args, store, want, r) -> int:
    quiet = args.json or args.raw
    if not quiet:
        r.banner()
        r.info(f"Fetching sources ({'all' if want is None else ', '.join(map(str, _order(want)))})…")
    ctx = _context(args)
    if not quiet:
        r.info(f"My external IP: {ctx.my_ip or 'unknown'}  |  judge: {ctx.judge.url}")

    out = preload(
        store, ctx, want, limit=args.limit,
        on_fetch_done=None if quiet else (
            lambda total, ok, all_: r.good(f"Collected {total} proxies from {ok}/{all_} feeds")),
        on_progress=None if quiet else (lambda proto, d, t: r.progress(f"check {proto}", d, t)),
    )
    alive = [x for x in out.results if x.ok]

    if args.raw:
        for res in alive:
            print(res.proxy.url)
    elif args.json:
        json.dump({
            "generated_at": _now(), "checked": True, "my_ip": ctx.my_ip, "judge": ctx.judge.url,
            "working": len(alive), "results": [x.to_dict() for x in alive],
        }, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        r.line(f"\n  {'TOP WORKING (by latency)':<40}\n  {'-' * 60}")
        for res in alive[:25]:
            r.result_line(str(res), ok=True)
        skipped = f"  (skipped {out.skipped_dead} known-dead)" if out.skipped_dead else ""
        r.line(f"\n  Total alive: {len(alive)}  (saved to the store){skipped}")
    if args.out:
        _save(args.out, alive, r)
    return 0


def run(argv: list[str]) -> int:
    args = _parse_args(argv)
    r = Renderer(color=not args.no_color and not args.json and not args.raw)

    if args.sources:
        _print_sources(r)
        return 0

    want = _wanted(args.protocols)
    store = Store(args.db or None)
    try:
        if args.purge_dead:
            r.good(f"Dead records removed: {store.purge_dead()}")
            return 0
        if _wants_menu(args):
            from .menu import Menu
            return Menu(store, lambda: _context(args)).run()
        if args.get:
            return _mode_get(args, store, want, r)
        if args.recheck:
            return _mode_recheck(args, store, r)
        if args.no_check:
            return _mode_no_check(args, store, want, r)
        return _mode_preload(args, store, want, r)
    finally:
        store.close()


def main() -> None:
    try:
        sys.exit(run(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\ngetproxy: interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
