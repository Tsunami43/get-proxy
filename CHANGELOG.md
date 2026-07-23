# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Anonymity grading (`--check-anonymity`): fetches a header-echoing judge through
  the proxy and reports `elite` / `anonymous` / `transparent`. The old `anonymous`
  flag only compared exit addresses and could not see an `X-Forwarded-For` leak.
  `--elite` filters to proxies that add no proxy headers at all.
- TLS verification (`--verify-https`): probes CONNECT plus a handshake to
  `--https-target`, because relaying port 80 does not imply tunnelling 443.
  `--https-only` filters on it. A failed probe does not fail the proxy.
- `--raw` prints bare proxy URLs, so `export HTTP_PROXY=$(getproxy -g --raw)`
  needs no `jq`.
- `--revive-after DAYS` (7) returns long-dead proxies to `unknown` instead of
  leaving `dead` permanent.
- Schema migration: new columns are added to existing stores rather than
  requiring the database to be deleted.
- Tests for `ops` and the CLI output modes, both previously uncovered.

### Fixed
- Dropped proxies are now actually recorded as `dead`. `check_all` used to
  discard every failed check, so `--recheck` never persisted a `dead` status and
  the "no longer checked" promise was not kept. Failures now flow to the store.
- A rate-limited judge no longer kills healthy proxies. ip-api answers
  `{"status":"fail"}` or 429 when throttled; that was recorded as a proxy
  failure and, with `--max-fails` defaulting to 1, marked the proxy permanently
  dead. Judge refusals are now separated from proxy failures and leave the
  record untouched.
- `preload` records the whole fetched pool, not only what `--limit` reached, so
  a limited run no longer discards the rest of the feeds.
- `Store.best()` rebuilt `Filters` positionally, so adding a field would have
  silently shifted the others.
- `Renderer` captured `sys.stdout` as a default argument at import time and
  ignored later redirection.
- Ctrl+C during a scan now exits at once. The thread pool was joined on the way
  out, so a single interrupt hung for up to a full timeout while in-flight
  sockets drained, and a second interrupt landed mid-join and printed a
  threading traceback.
- The interactive menu no longer flickers on each keystroke: the screen is
  repainted in place instead of being cleared before every frame.

### Changed
- `--get` scans the feeds as a stream instead of in fixed batches, returning the
  instant the first matching proxy answers. It no longer waits for a whole batch
  of 200 to drain — where the slowest dead proxy stalled the rest at its connect
  timeout — so the common case (an empty store, first working proxy) is several
  times faster.
- `--max-fails` defaults to 3 instead of 1. Free proxies are flaky, and with
  judge noise filtered out the counter now measures the proxy.
- Preload and `--get` skip known-dead proxies before checking, so accumulated
  `dead` records make every subsequent run faster instead of re-testing corpses.
- Split TCP connect from read timeout for SOCKS checks (`--connect-timeout`,
  default 5s). Dead proxies fail at connect and are dropped sooner without
  shortening the read budget for proxies that answer.
- `record_many` commits once per batch instead of once per proxy (thousands of
  fsyncs → one), which matters now that failures are recorded too.

## [0.2.0] - 2026-07-18

### Added
- Interactive menu (opencode-style): opens when run with no flags on a terminal.
  Arrow/`jk` navigation, rounded boxes. Entries: get a proxy, get by filters,
  recheck recent, preload, statistics, sources.
- Persistent store on `sqlite3`: every found/checked proxy is saved with its status
  (`working`/`unknown`/`dead`), country, latency and timestamps. Path —
  `$XDG_DATA_HOME/getproxy/proxies.db`.
- Recheck recent (`--recheck`): reruns previously found proxies; anything that drops
  is marked `dead` and is no longer checked or handed out.
- Country detection: the default judge is now `ip-api.com`, which reports the exit-node
  country. Added the `-c/--country` filter.
- Hand out one proxy (`--get`) under the `-c/--country`, `-a/--anonymous`,
  `--max-latency`, `-p/--protocols` filters; when the store is empty, a quick feed scan.
- Flags `--db`, `--max-fails`, `--purge-dead`, `--menu/--no-menu`.
- `tui` module (raw mode via `termios`) and `test_store`, `test_check` suites.

### Changed
- The one-shot run (`getproxy -p …`) now also writes live proxies to the store.
- `Result` gained `country_code`/`country` fields.

## [0.1.0] - 2026-07-17

### Added
- First release. Collects fresh free proxies from 17 public sources (45 feeds):
  auto-updated GitHub repositories + ProxyScrape and Geonode APIs.
- Liveness checking with no third-party dependencies: HTTP proxies via `urllib`,
  SOCKS4/SOCKS5 via a hand-rolled handshake over a bare `socket`.
- Latency measurement and exit-IP detection via a judge endpoint.
- CLI: protocol selection, limit, worker count, timeouts, text/JSON output,
  `working_*.txt` + `working.json` export, source registry (`--sources`).
- `unittest` suite, CI on the Python 3.10–3.13 matrix, standard library only.
