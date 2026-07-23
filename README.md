```
 ██████╗ ███████╗████████╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
██║  ███╗█████╗     ██║   ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
██║   ██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
╚██████╔╝███████╗   ██║   ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

**Grab a working free proxy in one command.**

getproxy gathers fresh free proxies from 17 public lists (45 feeds), checks
which ones actually work, and hands you a live one, filtered by country if you
like. It records what works and marks what dies, so the next run starts from
proxies it already trusts instead of re-testing the whole list.

Runs on the Python standard library alone: no signup, no API key, no `pip
install` of anything else.

## Quick start

```sh
git clone https://github.com/Tsunami43/getproxy.git
cd getproxy
python -m getproxy
```

That opens the menu:

```
╭─ main menu ────────────────────────────────────────────────╮
│ working in store: 12                                        │
│                                                             │
│ ❯  Get a proxy         first working                        │
│    Get by filters      country · protocol · anonymity       │
│    Recheck recent      dropped → dead                       │
│    Preload             fetch and check everything           │
│    Statistics          store status                         │
│    Sources             feed registry                        │
│    Quit                                                     │
╰─────────────────────────────────────────────────────────────╯
  ↑/↓ move · enter select · q quit
```

## From the command line

```sh
getproxy --get                 # one working proxy, right now
getproxy --get -c RU           # one from Russia
getproxy --get -p socks5 -a    # anonymous SOCKS5 only
getproxy --recheck             # re-test what you found before
getproxy -p socks5 -l 300 -o out   # collect a batch, save to ./out
getproxy --sources             # where the proxies come from
```

Run `getproxy --help` for every flag.

## A word of caution

Free proxies are run by strangers — they can watch or tamper with your traffic.
**Never send passwords or payments through them.** getproxy marks which proxies
are anonymous and which leak your real IP, but treat them as throwaway.

## License

MIT — see [LICENSE](LICENSE).
