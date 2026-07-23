"""Proxy liveness checking with no third-party dependencies.

HTTP proxies are checked through ``urllib`` with :class:`urllib.request.ProxyHandler`;
SOCKS4/SOCKS5 use a minimal hand-rolled handshake over a bare ``socket``. Every
check sends a request to a judge endpoint that echoes our "exit" IP, so we learn
the latency and whether the proxy hides the real address.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from . import __version__
from .proxy import Protocol, Proxy, Result, is_ipv4

_USER_AGENT = f"getproxy/{__version__} (+https://github.com/Tsunami43/getproxy)"
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Judge-side back-pressure: the endpoint is up but declining to answer right now.
_JUDGE_BUSY_CODES = frozenset({429, 503})
_JUDGE_BUSY_RE = re.compile(rb"^HTTP/1\.[01] (?:429|503)\b")

# Default judge: ip-api.com returns JSON with query (IP) and countryCode. The
# request goes THROUGH the proxy, so the country is that of the exit node — just
# what the country filter needs. ip-api's rate limit is keyed by the requesting
# IP (the proxy IP), so the shared limit does not get in our way.
DEFAULT_JUDGE = "http://ip-api.com/json/?fields=status,query,countryCode,country"

# Fallback judge without geo data — echoes a bare IPv4.
FALLBACK_JUDGE = "http://api.ipify.org/"

# Target for the optional TLS probe. The judge is plain HTTP (ip-api serves TLS
# only on its paid tier), so verifying CONNECT needs a separate https endpoint;
# this one is tiny, unauthenticated and almost universally reachable.
DEFAULT_HTTPS_TARGET = "https://www.cloudflare.com/cdn-cgi/trace"

# Judge for the optional anonymity grade. ip-api reports the exit address but
# not our request headers, so header leaks (X-Forwarded-For and friends) are
# invisible to it; grading needs an endpoint that echoes what it received.
DEFAULT_ANON_JUDGE = "http://azenv.net/"


@dataclass(frozen=True, slots=True)
class Judge:
    """An endpoint that echoes the client IP (for latency and anonymity checks)."""

    url: str
    host: str
    port: int
    path: str

    @classmethod
    def parse(cls, url: str) -> "Judge":
        parts = urlsplit(url)
        if parts.scheme != "http":
            # Plain HTTP works uniformly for every proxy type (http relay and
            # socks tunnel); HTTPS would need CONNECT+TLS with no upside here.
            raise ValueError("judge must be an http:// URL")
        host = parts.hostname or ""
        port = parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return cls(url=url, host=host, port=port, path=path)


class JudgeError(Exception):
    """The judge refused to answer — this says nothing about the proxy.

    ip-api replies ``{"status":"fail"}`` when it rate-limits or dislikes a query,
    and serves 429 once the per-IP quota is spent. Treating either as a proxy
    failure would mark healthy proxies dead, so these are reported separately.
    """


def _extract_ip(body: bytes) -> str:
    """Pull the first valid IPv4 out of a judge response body."""
    m = _IPV4_RE.search(body)
    if m and is_ipv4(m.group().decode()):
        return m.group().decode()
    return ""


def _parse_body(body: bytes) -> tuple[str, str, str]:
    """Parse a judge body into (ip, country_code, country).

    Understands ip-api JSON ({"query","countryCode","country"}) and plain text
    with a bare IP (ipify). Country stays empty when the judge does not provide it.

    Raises :class:`JudgeError` when the body is a judge-side refusal rather than
    an answer about the proxy.
    """
    text = body.strip()
    if text[:1] == b"{":
        try:
            d = json.loads(text)
        except Exception:
            return _extract_ip(body), "", ""
        if d.get("status") == "fail":
            raise JudgeError(f"judge refused: {d.get('message') or 'unknown reason'}")
        ip = d.get("query") or _extract_ip(body)
        return ip, (d.get("countryCode") or ""), (d.get("country") or "")
    return _extract_ip(body), "", ""


def local_ip(judge: Judge, timeout: float) -> str:
    """Resolve our real external IP directly (no proxy) for comparison.

    Returns an empty string if the judge is unreachable — then proxy anonymity
    simply is not assessed.
    """
    try:
        req = urllib.request.Request(judge.url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return _parse_body(resp.read(8192))[0]
    except Exception:
        return ""


# --- SOCKS: minimal CONNECT tunnel over a bare socket -----------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise if the connection closes early."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed during handshake")
        buf.extend(chunk)
    return bytes(buf)


def _socks5_connect(sock: socket.socket, host: str, port: int) -> None:
    """Open a SOCKS5 tunnel to host:port (no auth, domain mode)."""
    sock.sendall(b"\x05\x01\x00")
    greet = _recv_exact(sock, 2)
    if greet[0] != 0x05 or greet[1] != 0x00:
        raise OSError("socks5: server rejected no-auth method")
    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
    rep = _recv_exact(sock, 4)
    if rep[1] != 0x00:
        raise OSError(f"socks5: CONNECT refused (code {rep[1]})")
    atyp = rep[3]
    if atyp == 0x01:      # IPv4
        _recv_exact(sock, 4)
    elif atyp == 0x03:    # domain name
        _recv_exact(sock, _recv_exact(sock, 1)[0])
    elif atyp == 0x04:    # IPv6
        _recv_exact(sock, 16)
    _recv_exact(sock, 2)  # bound port — discarded


def _socks4_connect(sock: socket.socket, host: str, port: int) -> None:
    """Open a SOCKS4a tunnel to host:port (the proxy resolves the domain)."""
    # DSTIP 0.0.0.1 (last octet != 0) signals SOCKS4a mode.
    req = b"\x04\x01" + port.to_bytes(2, "big") + b"\x00\x00\x00\x01" + b"\x00" + host.encode() + b"\x00"
    sock.sendall(req)
    rep = _recv_exact(sock, 8)
    if rep[1] != 0x5A:
        raise OSError(f"socks4: CONNECT refused (code {rep[1]})")


def _get_via_socks(proxy: Proxy, host: str, port: int, path: str,
                   timeout: float, connect_timeout: float) -> bytes:
    """GET ``path`` through a SOCKS proxy and return the raw response body.

    The TCP connect uses ``connect_timeout`` (usually shorter): most dead proxies
    fail right at the handshake, so a tighter connect budget drops them faster
    without shortening the read budget for proxies that do answer.
    """
    with socket.create_connection((proxy.host, proxy.port), timeout=connect_timeout) as sock:
        sock.settimeout(timeout)
        if proxy.protocol is Protocol.SOCKS5:
            _socks5_connect(sock, host, port)
        else:
            _socks4_connect(sock, host, port)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request)

        data = bytearray()
        while len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)

    head, _, body = bytes(data).partition(b"\r\n\r\n")
    if not body:
        raise OSError("empty response over socks")
    if _JUDGE_BUSY_RE.search(head):
        raise JudgeError("judge rate-limited the request")
    return body


def _check_socks(proxy: Proxy, judge: Judge, timeout: float, connect_timeout: float) -> tuple[str, str, str]:
    """Send a judge request through a SOCKS proxy, return (ip, cc, country)."""
    return _parse_body(
        _get_via_socks(proxy, judge.host, judge.port, judge.path, timeout, connect_timeout))


def _check_http(proxy: Proxy, judge: Judge, timeout: float) -> tuple[str, str, str]:
    """Send a judge request through an HTTP proxy, return (ip, cc, country)."""
    return _parse_body(_get_via_http(proxy, judge.url, timeout))


def _get_via_http(proxy: Proxy, url: str, timeout: float) -> bytes:
    """GET ``url`` through an HTTP proxy and return the raw response body."""
    proxy_url = f"http://{proxy.addr}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read(65536)
    except urllib.error.HTTPError as exc:
        if exc.code in _JUDGE_BUSY_CODES:
            raise JudgeError(f"judge returned HTTP {exc.code}") from exc
        raise


# Headers a proxy adds to announce itself or to pass the client address on.
# Normalised to dashes and upper case before matching, so azenv-style
# HTTP_X_FORWARDED_FOR and a JSON "X-Forwarded-For" key both hit.
_FORWARD_HEADERS = (
    b"X-FORWARDED-FOR", b"X-FORWARDED", b"FORWARDED-FOR", b"FORWARDED",
    b"VIA", b"PROXY-CONNECTION", b"X-PROXY-ID", b"CLIENT-IP", b"X-REAL-IP",
)


def _classify_anonymity(body: bytes, my_ip: str) -> str:
    """Grade a header-echoing judge response: transparent / anonymous / elite.

    ``transparent`` — our address is in there somewhere, so the proxy passed it on.
    ``anonymous``   — no address of ours, but forwarding headers reveal a proxy.
    ``elite``       — the request looks like it came straight from the exit node.
    """
    normalised = body.replace(b"_", b"-").upper()
    if my_ip and my_ip.encode() in body:
        return "transparent"
    if any(h in normalised for h in _FORWARD_HEADERS):
        return "anonymous"
    return "elite"


def _probe_anonymity(proxy: Proxy, judge: Judge, my_ip: str,
                     timeout: float, connect_timeout: float) -> str:
    """Ask a header-echoing judge what the far end actually sees."""
    if proxy.protocol is Protocol.HTTP:
        body = _get_via_http(proxy, judge.url, timeout)
    else:
        body = _get_via_socks(proxy, judge.host, judge.port, judge.path,
                              timeout, connect_timeout)
    return _classify_anonymity(body, my_ip)


def _probe_https(proxy: Proxy, target: str, timeout: float, connect_timeout: float) -> None:
    """Raise unless the proxy can carry a TLS session to ``target``.

    Plain-HTTP relaying says nothing about CONNECT: a proxy can happily forward
    port 80 and refuse 443, which is the case users actually care about. The
    handshake completing is the whole assertion — the response body is ignored.
    """
    parts = urlsplit(target)
    host = parts.hostname or ""
    port = parts.port or 443
    ssl_ctx = ssl.create_default_context()

    if proxy.protocol is Protocol.HTTP:
        handler = urllib.request.ProxyHandler({"https": f"http://{proxy.addr}"})
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(target, headers={"User-Agent": _USER_AGENT})
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310
            resp.read(512)
        return

    with socket.create_connection((proxy.host, proxy.port), timeout=connect_timeout) as sock:
        sock.settimeout(timeout)
        if proxy.protocol is Protocol.SOCKS5:
            _socks5_connect(sock, host, port)
        else:
            _socks4_connect(sock, host, port)
        # wrap_socket performs the handshake; a refused CONNECT fails before it.
        with ssl_ctx.wrap_socket(sock, server_hostname=host):
            pass


def check_one(proxy: Proxy, judge: Judge, timeout: float, my_ip: str = "",
              connect_timeout: float | None = None, *,
              https_target: str = "", anon_judge: Judge | None = None) -> Result:
    """Check a single proxy and return a :class:`Result` with latency and exit IP.

    ``connect_timeout`` bounds the TCP connect for SOCKS proxies; it falls back
    to ``timeout`` so a single budget covers both phases when only one is given.
    """
    if connect_timeout is None:
        connect_timeout = timeout
    result = Result(proxy=proxy)
    started = time.monotonic()
    try:
        if proxy.protocol is Protocol.HTTP:
            exit_ip, cc, country = _check_http(proxy, judge, timeout)
        else:
            exit_ip, cc, country = _check_socks(proxy, judge, timeout, connect_timeout)
    except JudgeError as exc:
        # The proxy carried the request; the judge declined to answer. Verdict
        # unknown, so leave the record's status and fail_count alone.
        result.judge_error = True
        result.error = str(exc)
        return result
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.latency_ms = int((time.monotonic() - started) * 1000)
    if not exit_ip:
        result.error = "judge returned no IP"
        return result

    result.ok = True
    result.exit_ip = exit_ip
    result.country_code = cc
    result.country = country
    result.anonymous = bool(my_ip) and exit_ip != my_ip

    if anon_judge is not None:
        try:
            result.anonymity = _probe_anonymity(proxy, anon_judge, my_ip,
                                                timeout, connect_timeout)
        except Exception:
            # Grading is best-effort; a judge that is down must not fail a proxy
            # that already answered the main check.
            result.anonymity = ""

    if https_target:
        try:
            _probe_https(proxy, https_target, timeout, connect_timeout)
            result.https = True
        except Exception:
            # Plain HTTP still works, so the proxy stays ok — it just cannot
            # be trusted with TLS, which the https flag now records.
            result.https = False
    return result


def check_all(
    proxies: list[Proxy],
    judge: Judge,
    *,
    timeout: float = 8.0,
    workers: int = 200,
    my_ip: str = "",
    connect_timeout: float | None = None,
    https_target: str = "",
    anon_judge: Judge | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[Result]:
    """Check proxies in parallel, returning every result, live ones first.

    Failures are included so the store can mark them ``dead`` and skip them on
    later runs. Live results come first, sorted by latency; failures follow.
    Callers that only want live proxies filter with ``[r for r in results if r.ok]``.

    ``on_progress(done, total)`` (when given) is called after each finished check
    for a live counter in the UI.
    """
    total = len(proxies)
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(check_one, p, judge, timeout, my_ip, connect_timeout,
                             https_target=https_target, anon_judge=anon_judge)
                   for p in proxies]
        for done, fut in enumerate(as_completed(futures), start=1):
            results.append(fut.result())
            if on_progress is not None:
                on_progress(done, total)
    # Live first (by latency), then the failures.
    results.sort(key=lambda r: (not r.ok, r.latency_ms))
    return results
