# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Dropped proxies are now actually recorded as `dead`. `check_all` used to
  discard every failed check, so `--recheck` never persisted a `dead` status and
  the "no longer checked" promise was not kept. Failures now flow to the store.

### Changed
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
