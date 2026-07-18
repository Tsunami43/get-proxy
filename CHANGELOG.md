# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-18

### Added
- **Interactive menu** (opencode-style): opens when run with no flags on a terminal.
  Arrow/`jk` navigation, rounded boxes, truecolor theme. Entries: get a proxy, get by
  filters, recheck recent, preload, statistics, sources.
- **Persistent store** on `sqlite3`: every found/checked proxy is saved with its status
  (`working`/`unknown`/`dead`), country, latency and timestamps. Path —
  `$XDG_DATA_HOME/getproxy/proxies.db`.
- **Recheck recent** (`--recheck`): reruns previously found proxies; anything that drops
  is marked `dead` and is **no longer checked** or handed out.
- **Country detection**: default judge is now `ip-api.com`, which reports the exit-node
  country. Added the `-c/--country` filter.
- **Hand out one proxy** (`--get`) under the `-c/--country`, `-a/--anonymous`,
  `--max-latency`, `-p/--protocols` filters; when the store is empty, a quick feed scan.
- Flags `--db`, `--max-fails`, `--purge-dead`, `--menu/--no-menu`.
- `tui` module (raw mode via `termios`) and `test_store`, `test_check` suites.

### Changed
- The one-shot run (`getproxy -p …`) now also writes live proxies to the store.
- `Result` gained `country_code`/`country` fields.

## [0.1.0] - 2026-07-17

### Added
- First release. Collects fresh free proxies from **17 public sources** (45 feeds):
  auto-updated GitHub repositories + ProxyScrape and Geonode APIs.
- Liveness checking with **no third-party dependencies**: HTTP proxies via `urllib`,
  SOCKS4/SOCKS5 via a hand-rolled handshake over a bare `socket`.
- Latency measurement and exit-IP detection via a judge endpoint.
- CLI: protocol selection, limit, worker count, timeouts, text/JSON output,
  `working_*.txt` + `working.json` export, source registry (`--sources`).
- `unittest` suite, CI on the Python 3.10–3.13 matrix, standard library only.
