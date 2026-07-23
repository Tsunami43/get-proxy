"""Output styling: a dependency-free ANSI palette, banner and progress line.

Colour is enabled only on a real TTY and when NO_COLOR is unset; piped or
redirected output degrades to plain text automatically.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

BANNER = """
 ██████╗ ███████╗████████╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
██║  ███╗█████╗     ██║   ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
██║   ██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
╚██████╔╝███████╗   ██║   ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
        fresh free proxies from 17 public sources
"""


@dataclass(frozen=True, slots=True)
class Palette:
    """ANSI codes. When colour is disabled every field is an empty string."""

    reset: str = ""
    bold: str = ""
    dim: str = ""
    red: str = ""
    green: str = ""
    yellow: str = ""
    cyan: str = ""


_ENABLED = Palette(
    reset="\033[0m",
    bold="\033[1m",
    dim="\033[2m",
    red="\033[31m",
    green="\033[32m",
    yellow="\033[33m",
    cyan="\033[36m",
)


def is_tty(stream=sys.stdout) -> bool:
    """Report whether the stream is attached to a terminal."""
    try:
        return stream.isatty()
    except Exception:
        return False


def palette(enabled: bool) -> Palette:
    """Return the colour palette, or an empty one (plain text)."""
    return _ENABLED if enabled else Palette()


class Renderer:
    """Prints the banner, progress and results, honouring the colour setting."""

    def __init__(self, color: bool = True, out=sys.stdout) -> None:
        # Colour only on a TTY, without NO_COLOR and unless explicitly disabled.
        self.color = color and is_tty(out) and os.environ.get("NO_COLOR", "") == ""
        self.p = palette(self.color)
        self.out = out

    def line(self, text: str = "") -> None:
        print(text, file=self.out)

    def banner(self) -> None:
        p = self.p
        self.line(f"{p.cyan}{p.bold}{BANNER}{p.reset}")

    def info(self, text: str) -> None:
        self.line(f"{self.p.cyan}›{self.p.reset} {text}")

    def warn(self, text: str) -> None:
        self.line(f"{self.p.yellow}!{self.p.reset} {text}")

    def good(self, text: str) -> None:
        self.line(f"{self.p.green}✓{self.p.reset} {text}")

    def progress(self, prefix: str, done: int, total: int, extra: str = "") -> None:
        """Single-line live counter (redrawn via ``\\r`` on a TTY)."""
        if not is_tty(self.out):
            return
        pct = (done / total * 100) if total else 100.0
        msg = f"  {prefix}: {done}/{total} ({pct:4.0f}%)"
        if extra:
            msg += f"  {extra}"
        end = "\n" if done >= total else ""
        print(f"\r\033[K{msg}", end=end, file=self.out, flush=True)

    def result_line(self, text: str, ok: bool = True) -> None:
        mark = f"{self.p.green}●{self.p.reset}" if ok else f"{self.p.red}○{self.p.reset}"
        self.line(f"  {mark} {text}")
