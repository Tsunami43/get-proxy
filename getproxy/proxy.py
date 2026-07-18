"""Core proxy value type: protocol, address parsing and check result.

Standard library only, no third-party dependencies.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum


class Protocol(str, Enum):
    """Supported proxy protocols."""

    HTTP = "http"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"

    def __str__(self) -> str:  # so f-strings render "http", not "Protocol.HTTP"
        return self.value


# Display order of protocols across all reports.
ALL_PROTOCOLS = (Protocol.HTTP, Protocol.SOCKS4, Protocol.SOCKS5)

# Schemes stripped from the start of a raw line before parsing host:port.
_SCHEMES = (
    "socks5h://",
    "socks5://",
    "socks4a://",
    "socks4://",
    "https://",
    "http://",
)


def parse_protocol(token: str) -> Protocol | None:
    """Map a free-form token (CLI flag or API field) to a known protocol.

    ``https`` collapses to HTTP and ``socks5h`` to SOCKS5 — the same wire
    protocol as far as checking is concerned.
    """
    t = token.strip().lower()
    if t in ("http", "https"):
        return Protocol.HTTP
    if t in ("socks4", "socks4a"):
        return Protocol.SOCKS4
    if t in ("socks5", "socks5h"):
        return Protocol.SOCKS5
    return None


@dataclass(frozen=True, slots=True)
class Proxy:
    """A single reachable proxy endpoint."""

    host: str
    port: int
    protocol: Protocol

    @property
    def addr(self) -> str:
        """The ``host:port`` pair used for dialling."""
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """Canonical ``protocol://host:port`` form."""
        return f"{self.protocol}://{self.addr}"

    @property
    def key(self) -> str:
        """Deduplication key (protocol + address)."""
        return f"{self.protocol}|{self.addr}"

    def __str__(self) -> str:
        return self.url


def parse(line: str, protocol: Protocol) -> Proxy | None:
    """Parse a single raw list line into a :class:`Proxy` for the given protocol.

    Tolerates a leading scheme, surrounding whitespace and trailing columns
    (``ip:port country`` / ``ip:port\\tlatency``). Returns ``None`` for blank
    lines, comments and malformed entries.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Some lists append a " country" or "\tlatency" column — keep the first field.
    for sep in (" ", "\t"):
        idx = line.find(sep)
        if idx >= 0:
            line = line[:idx]

    low = line.lower()
    for scheme in _SCHEMES:
        if low.startswith(scheme):
            line = line[len(scheme):]
            break

    host, sep, port_str = line.rpartition(":")
    if not sep or not host:
        return None
    try:
        port = int(port_str)
    except ValueError:
        return None
    if not (1 <= port <= 65535):
        return None

    return Proxy(host=host, port=port, protocol=protocol)


def is_ipv4(value: str) -> bool:
    """Report whether the string is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


@dataclass(slots=True)
class Result:
    """Outcome of checking a single proxy against a judge endpoint."""

    proxy: Proxy
    ok: bool = False
    latency_ms: int = 0
    exit_ip: str = ""
    country_code: str = ""
    country: str = ""
    anonymous: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        """Serialisable representation for the JSON report."""
        return {
            "proxy": self.proxy.url,
            "host": self.proxy.host,
            "port": self.proxy.port,
            "protocol": str(self.proxy.protocol),
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "exit_ip": self.exit_ip,
            "country_code": self.country_code,
            "country": self.country,
            "anonymous": self.anonymous,
            "error": self.error,
        }

    def __str__(self) -> str:
        if not self.ok:
            return f"{self.proxy.url:<25}  down ({self.error})"
        tag = "anonymous" if self.anonymous else "transparent"
        geo = f"[{self.country_code}] " if self.country_code else ""
        return f"{self.proxy.url:<25}  {self.latency_ms:>5}ms  {tag:<11}  {geo}exit={self.exit_ip}"
