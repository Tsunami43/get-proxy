# Changelog

All notable changes to this project are documented in this file.

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
