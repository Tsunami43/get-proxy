"""Proxy liveness checking with no third-party dependencies.

HTTP proxies are checked through ``urllib`` with :class:`urllib.request.ProxyHandler`;
SOCKS4/SOCKS5 use a minimal hand-rolled handshake over a bare ``socket``. Every
check sends a request to a judge endpoint that echoes our "exit" IP, so we learn
the latency and whether the proxy hides the real address.
"""

from __future__ import annotations

import re
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from .proxy import Protocol, Proxy, Result, is_ipv4

_USER_AGENT = "getproxy/0.1 (+https://github.com/Tsunami43/getproxy)"
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Default judge: echoes a bare IPv4 in the response body over plain HTTP.
DEFAULT_JUDGE = "http://api.ipify.org/"


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


def _extract_ip(body: bytes) -> str:
    """Pull the first valid IPv4 out of a judge response body."""
    m = _IPV4_RE.search(body)
    if m and is_ipv4(m.group().decode()):
        return m.group().decode()
    return ""


def local_ip(judge: Judge, timeout: float) -> str:
    """Resolve our real external IP directly (no proxy) for comparison.

    Returns an empty string if the judge is unreachable — then proxy anonymity
    simply is not assessed.
    """
    try:
        req = urllib.request.Request(judge.url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return _extract_ip(resp.read(4096))
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


def _check_socks(proxy: Proxy, judge: Judge, timeout: float) -> str:
    """Send a judge request through a SOCKS proxy, return the exit IP."""
    with socket.create_connection((proxy.host, proxy.port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if proxy.protocol is Protocol.SOCKS5:
            _socks5_connect(sock, judge.host, judge.port)
        else:
            _socks4_connect(sock, judge.host, judge.port)

        request = (
            f"GET {judge.path} HTTP/1.1\r\n"
            f"Host: {judge.host}\r\n"
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
        raise OSError("empty judge response over socks")
    return _extract_ip(body)


def _check_http(proxy: Proxy, judge: Judge, timeout: float) -> str:
    """Send a judge request through an HTTP proxy, return the exit IP."""
    proxy_url = f"http://{proxy.addr}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(judge.url, headers={"User-Agent": _USER_AGENT})
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310
        return _extract_ip(resp.read(4096))


def check_one(proxy: Proxy, judge: Judge, timeout: float, my_ip: str = "") -> Result:
    """Check a single proxy and return a :class:`Result` with latency and exit IP."""
    result = Result(proxy=proxy)
    started = time.monotonic()
    try:
        if proxy.protocol is Protocol.HTTP:
            exit_ip = _check_http(proxy, judge, timeout)
        else:
            exit_ip = _check_socks(proxy, judge, timeout)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.latency_ms = int((time.monotonic() - started) * 1000)
    if not exit_ip:
        result.error = "judge returned no IP"
        return result

    result.ok = True
    result.exit_ip = exit_ip
    result.anonymous = bool(my_ip) and exit_ip != my_ip
    return result


def check_all(
    proxies: list[Proxy],
    judge: Judge,
    *,
    timeout: float = 8.0,
    workers: int = 200,
    my_ip: str = "",
    on_progress: Callable[[int, int], None] | None = None,
) -> list[Result]:
    """Check proxies in parallel, returning only the live ones sorted by latency.

    ``on_progress(done, total)`` (when given) is called after each finished check
    for a live counter in the UI.
    """
    total = len(proxies)
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(check_one, p, judge, timeout, my_ip) for p in proxies]
        for done, fut in enumerate(as_completed(futures), start=1):
            res = fut.result()
            if res.ok:
                results.append(res)
            if on_progress is not None:
                on_progress(done, total)
    results.sort(key=lambda r: r.latency_ms)
    return results
