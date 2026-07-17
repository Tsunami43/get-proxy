"""Argument parsing and the getproxy pipeline: fetch → (check) → output/save."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .check import DEFAULT_JUDGE, Judge, check_all, local_ip
from .fetch import fetch_all
from .proxy import ALL_PROTOCOLS, Protocol, Result, parse_protocol
from .sources import INDEX, SOURCES
from .ui import Renderer


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="getproxy",
        description="Fresh free proxies from 17+ public sources — no API keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  getproxy                       fetch and check all proxies\n"
            "  getproxy -p socks5 -o out      socks5 only, save into ./out\n"
            "  getproxy --no-check --json     quick raw-list dump as JSON\n"
            "  getproxy --sources             show the source registry\n"
        ),
    )
    parser.add_argument("-p", "--protocols", default="all",
                        help="comma-separated: http,socks4,socks5 or all (default all)")
    parser.add_argument("--no-check", action="store_true",
                        help="do not check liveness — dump the raw aggregated list")
    parser.add_argument("-t", "--timeout", type=float, default=8.0,
                        help="per-proxy check timeout, s (default 8)")
    parser.add_argument("--fetch-timeout", type=float, default=20.0,
                        help="per-source fetch timeout, s (default 20)")
    parser.add_argument("-w", "--workers", type=int, default=200,
                        help="parallel checks (default 200)")
    parser.add_argument("-l", "--limit", type=int, default=0,
                        help="max proxies per protocol to check (0 = no limit)")
    parser.add_argument("-j", "--judge", default=DEFAULT_JUDGE,
                        help=f"http endpoint echoing the IP (default {DEFAULT_JUDGE})")
    parser.add_argument("-o", "--out", metavar="DIR",
                        help="save the result into a directory (working_*.txt + working.json)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON to stdout")
    parser.add_argument("--sources", action="store_true", help="show the source registry and exit")
    parser.add_argument("--no-color", action="store_true", help="disable colour")
    parser.add_argument("-V", "--version", action="version", version=f"getproxy {__version__}")
    return parser.parse_args(argv)


def _wanted_protocols(spec: str) -> set[Protocol] | None:
    """Parse the ``--protocols`` spec into a set (None = all)."""
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


def _print_sources(r: Renderer) -> None:
    r.banner()
    r.line(f"  Sources: {len(INDEX)}  ({len(SOURCES)} feeds)\n")
    r.line(f"  {'SOURCE':<28} {'PROTOCOLS':<26} UPDATED")
    r.line(f"  {'-' * 28} {'-' * 26} {'-' * 14}")
    for repo in INDEX:
        r.line(f"  {repo.name:<28} {repo.kinds:<26} {repo.cadence}")


def _order(want: set[Protocol] | None) -> list[Protocol]:
    return [p for p in ALL_PROTOCOLS if want is None or p in want]


def _save(out_dir: str, results: list[Result] | None, pool_by_proto: dict[Protocol, list], r: Renderer) -> None:
    """Save the working (or raw) proxies into a directory."""
    os.makedirs(out_dir, exist_ok=True)
    if results is not None:
        by_proto: dict[str, list[str]] = {}
        for res in results:
            by_proto.setdefault(str(res.proxy.protocol), []).append(res.proxy.addr)
        for proto, addrs in by_proto.items():
            path = os.path.join(out_dir, f"working_{proto}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(addrs) + "\n")
        with open(os.path.join(out_dir, "working.json"), "w", encoding="utf-8") as f:
            json.dump([res.to_dict() for res in results], f, ensure_ascii=False, indent=2)
    else:
        for proto, proxies in pool_by_proto.items():
            path = os.path.join(out_dir, f"all_{proto}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(p.addr for p in proxies) + "\n")
    r.good(f"Saved to {out_dir}/")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run(argv: list[str]) -> int:
    args = _parse_args(argv)
    r = Renderer(color=not args.no_color and not args.json)

    if args.sources:
        _print_sources(r)
        return 0

    want = _wanted_protocols(args.protocols)
    order = _order(want)

    if not args.json:
        r.banner()
        r.info(f"Fetching sources ({'all' if want is None else ', '.join(map(str, order))})…")

    pool = fetch_all(want, timeout=args.fetch_timeout, workers=32)
    ok_feeds = sum(1 for s in pool.stats if not s.error)
    if not args.json:
        r.good(f"Collected {pool.total} unique proxies from {ok_feeds}/{len(pool.stats)} feeds")

    # Apply the per-protocol limit.
    selected: dict[Protocol, list] = {}
    for proto in order:
        proxies = pool.proxies.get(proto, [])
        if args.limit > 0:
            proxies = proxies[:args.limit]
        selected[proto] = proxies

    # No-check mode: dump the raw aggregated list.
    if args.no_check:
        if args.json:
            payload = {
                "generated_at": _now(),
                "checked": False,
                "counts": {str(p): len(v) for p, v in selected.items()},
                "proxies": {str(p): [x.url for x in v] for p, v in selected.items()},
            }
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            print()
        else:
            for proto in order:
                r.line(f"\n  {proto} — {len(selected[proto])}")
                for p in selected[proto]:
                    r.line(f"    {p.addr}")
        if args.out:
            _save(args.out, None, selected, r)
        return 0

    # Check mode.
    judge = Judge.parse(args.judge)
    my_ip = local_ip(judge, args.timeout)
    if not args.json:
        r.info(f"My external IP: {my_ip or 'unknown'}  |  judge: {judge.url}")

    all_results: list[Result] = []
    for proto in order:
        proxies = selected[proto]
        if not proxies:
            continue
        cb = None
        if not args.json:
            cb = lambda done, total, _p=proto: r.progress(f"check {_p}", done, total)
        results = check_all(
            proxies, judge,
            timeout=args.timeout, workers=args.workers, my_ip=my_ip, on_progress=cb,
        )
        all_results.extend(results)
        if not args.json:
            anon = sum(1 for x in results if x.anonymous)
            r.good(f"{proto}: alive {len(results)}/{len(proxies)}  (anonymous {anon})")

    all_results.sort(key=lambda x: x.latency_ms)

    if args.json:
        payload = {
            "generated_at": _now(),
            "checked": True,
            "my_ip": my_ip,
            "judge": judge.url,
            "working": len(all_results),
            "results": [x.to_dict() for x in all_results],
        }
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        r.line(f"\n  {'TOP WORKING (by latency)':<40}")
        r.line(f"  {'-' * 60}")
        for res in all_results[:25]:
            r.result_line(str(res), ok=True)
        r.line(f"\n  Total alive: {len(all_results)}")

    if args.out:
        _save(args.out, all_results, selected, r)
    return 0


def main() -> None:
    try:
        sys.exit(run(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\ngetproxy: interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
