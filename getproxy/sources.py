"""Registry of the free, key-less proxy feeds that getproxy aggregates.

These are public GitHub repositories that republish proxy lists on a schedule
(via GitHub Actions) plus a couple of public JSON/text APIs. Every source is
free, needs no token or registration, and is refreshed upstream anywhere from
every few minutes to once a day.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .proxy import Protocol


class Kind(Enum):
    """How a source body is decoded into proxies."""

    TEXT = auto()      # plain list of "ip:port" lines (leading scheme stripped)
    GEONODE = auto()   # geonode.com JSON API — entries carry their own protocols


@dataclass(frozen=True, slots=True)
class Source:
    """A single upstream feed."""

    url: str
    protocol: Protocol | None  # ignored for GEONODE, which is self-describing
    kind: Kind = Kind.TEXT


# Full set of feeds queried on every run: GitHub raw lists first (most numerous),
# then the aggregating APIs.
SOURCES: tuple[Source, ...] = (
    # TheSpeedX/PROXY-List — updated daily.
    Source("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", Protocol.SOCKS5),

    # monosans/proxy-list — hourly, with geolocation.
    Source("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", Protocol.SOCKS5),

    # ShiftyTR/Proxy-List — hourly.
    Source("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", Protocol.SOCKS5),

    # mmpx12/proxy-list.
    Source("https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt", Protocol.SOCKS5),

    # roosterkid/openproxylist — every 15 minutes.
    Source("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", Protocol.SOCKS5),

    # hookzof/socks5_list — SOCKS5 only, with geolocation.
    Source("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", Protocol.SOCKS5),

    # jetkai/proxy-list — hourly.
    Source("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", Protocol.SOCKS5),

    # proxifly/free-proxy-list — every 5 minutes (lines carry a scheme prefix).
    Source("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", Protocol.SOCKS5),

    # vakhov/fresh-proxy-list — every 5-20 minutes.
    Source("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt", Protocol.SOCKS5),

    # clarketm/proxy-list — daily (mixed list, treated as HTTP candidates).
    Source("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", Protocol.HTTP),

    # sunny9577/proxy-scraper.
    Source("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt", Protocol.SOCKS5),

    # prxchk/proxy-list — hourly.
    Source("https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt", Protocol.SOCKS5),

    # MuRongPIG/Proxy-Master.
    Source("https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt", Protocol.SOCKS5),

    # zloi-user/hideip.me.
    Source("https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt", Protocol.SOCKS5),

    # Zaeem20/FREE_PROXIES_LIST.
    Source("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt", Protocol.HTTP),
    Source("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt", Protocol.SOCKS4),
    Source("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt", Protocol.SOCKS5),

    # ProxyScrape API v2 — plain text, refreshed every ~5 minutes.
    Source("https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", Protocol.HTTP),
    Source("https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all", Protocol.SOCKS4),
    Source("https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all", Protocol.SOCKS5),

    # Geonode API — JSON, self-describing protocols, up to 500 entries per page.
    Source("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc", None, Kind.GEONODE),
)


@dataclass(frozen=True, slots=True)
class Repo:
    """Human-readable registry entry for ``getproxy --sources`` and the README."""

    name: str
    kinds: str
    cadence: str


# Human-readable description of the feeds, in the same order as SOURCES.
INDEX: tuple[Repo, ...] = (
    Repo("TheSpeedX/PROXY-List", "http/socks4/socks5", "daily"),
    Repo("monosans/proxy-list", "http/socks4/socks5 + geo", "hourly"),
    Repo("ShiftyTR/Proxy-List", "http/socks4/socks5", "hourly"),
    Repo("mmpx12/proxy-list", "http/socks4/socks5", "hourly"),
    Repo("roosterkid/openproxylist", "https/socks4/socks5", "every 15 min"),
    Repo("hookzof/socks5_list", "socks5 + geo", "regularly"),
    Repo("jetkai/proxy-list", "all, many formats", "hourly"),
    Repo("proxifly/free-proxy-list", "http/socks4/socks5 + API", "every 5 min"),
    Repo("vakhov/fresh-proxy-list", "all, many formats", "5-20 min"),
    Repo("clarketm/proxy-list", "mixed list", "daily"),
    Repo("sunny9577/proxy-scraper", "all", "regularly"),
    Repo("prxchk/proxy-list", "http/socks4/socks5", "hourly"),
    Repo("MuRongPIG/Proxy-Master", "http/socks4/socks5", "regularly"),
    Repo("zloi-user/hideip.me", "http/socks4/socks5", "regularly"),
    Repo("Zaeem20/FREE_PROXIES_LIST", "http/socks4/socks5", "regularly"),
    Repo("ProxyScrape API v2", "http/socks4/socks5", "every 5 min"),
    Repo("Geonode API", "mixed + geo/anonymity", "every few min"),
)
