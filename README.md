```
 ██████╗ ███████╗████████╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
██║  ███╗█████╗     ██║   ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
██║   ██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
╚██████╔╝███████╗   ██║   ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

**Find working free proxies, fast.**

getproxy pulls fresh free proxies from 17+ public lists and checks which ones
actually work, sorted by speed. No signup, no API keys, no dependencies.

---

## What you get

- 🌐 Fresh proxies from **17 public sources** (HTTP / SOCKS4 / SOCKS5)
- ✅ Every proxy **checked** for real, sorted fastest-first
- 🧾 Plain text or **JSON** output, save to files
- 🪶 **Nothing to install** — pure Python standard library

---

## Quick start

```sh
git clone https://github.com/Tsunami43/getproxy.git
cd getproxy
python -m getproxy
```

```sh
python -m getproxy -p socks5 -o out     # collect socks5, save to ./out
python -m getproxy --no-check --json    # raw list as JSON, no checking
python -m getproxy --sources            # where the proxies come from
```

Run `python -m getproxy --help` for every flag.

---

## A word of caution

Free proxies are run by strangers — they can watch or tamper with your traffic.
**Never send passwords or payments through them.**

---

## License

MIT — see [LICENSE](LICENSE).
