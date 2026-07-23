"""Tiny TUI on the pure standard library: 16-colour theme, boxes and an
arrow-key menu (opencode-style), with no third-party dependencies.

On a POSIX terminal it uses raw mode (`termios`) to read arrow keys; where a
terminal is unavailable (not a TTY, Windows) the helpers fall back to numbered
input.
"""

from __future__ import annotations

import os
import re
import select as _select
import sys
from dataclasses import dataclass

try:
    import termios
    import tty
    _RAW_OK = True
except ImportError:  # non-POSIX
    _RAW_OK = False

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


# --- palette (16-colour ANSI) ----------------------------------------------
#
# Colours are named, not RGB, so they resolve against whatever theme the user
# already runs in their terminal instead of imposing our own hues on it.
# One accent (cyan); everything else is either neutral or a status signal.

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

ACCENT = "\033[36m"   # cyan — the single accent
TEXT = "\033[39m"     # the terminal's default foreground
MUTED = "\033[90m"
GOOD = "\033[32m"
WARN = "\033[33m"
BAD = "\033[31m"


def _no_color() -> bool:
    return os.environ.get("NO_COLOR", "") != "" or not sys.stdout.isatty()


def color(code: str, text: str) -> str:
    """Wrap text in a colour when colour is enabled."""
    return text if _no_color() else f"{code}{text}{RESET}"


def visible_len(s: str) -> int:
    """Printable width of a string, ignoring ANSI escape sequences."""
    return len(_ANSI_RE.sub("", s))


def hide_cursor() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[?25l")


def show_cursor() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[?25h")


def clear() -> None:
    sys.stdout.write("\033[2J\033[3J\033[H")


# --- boxes ------------------------------------------------------------------

def panel(title: str, lines: list[str], *, width: int = 0, accent: str = ACCENT) -> str:
    """Build a rounded-corner box around the given lines."""
    inner = max([visible_len(x) for x in lines] + [visible_len(title) + 4, width])
    plain = _no_color()

    def a(text: str) -> str:
        return text if plain else f"{accent}{text}{RESET}"

    top = a("╭─ ") + (title if plain else f"{BOLD}{accent}{title}{RESET}") + " " + a("─" * (inner - visible_len(title) - 1) + "╮")
    out = [top]
    for ln in lines:
        pad = " " * (inner - visible_len(ln))
        out.append(a("│") + " " + ln + pad + " " + a("│"))
    out.append(a("╰" + "─" * (inner + 2) + "╯"))
    return "\n".join(out)


# --- key reading ------------------------------------------------------------

class KeyReader:
    """Raw-mode terminal context that reads semantic keys."""

    def __init__(self) -> None:
        self.enabled = _RAW_OK and sys.stdin.isatty()
        self.fd = sys.stdin.fileno() if self.enabled else -1
        self._old = None

    def __enter__(self) -> "KeyReader":
        if self.enabled:
            self._old = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        return self

    def __exit__(self, *exc) -> None:
        if self.enabled and self._old is not None:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self._old)

    def read(self) -> str:
        """Read one key: up/down/left/right/enter/esc/q or a character."""
        ch = os.read(self.fd, 1)
        if ch == b"\x1b":
            r, _, _ = _select.select([self.fd], [], [], 0.05)
            if r:
                seq = os.read(self.fd, 2)
                return {b"[A": "up", b"[B": "down", b"[C": "right", b"[D": "left"}.get(seq, "esc")
            return "esc"
        if ch in (b"\r", b"\n"):
            return "enter"
        if ch == b"\x03":
            raise KeyboardInterrupt
        try:
            return ch.decode("utf-8", "ignore").lower()
        except Exception:
            return ""


# --- menu selection ---------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Option:
    label: str
    hint: str = ""


def select(title: str, options: list[Option], *, subtitle: str = "",
           header: str = "") -> int | None:
    """Show a menu and return the chosen index (or None on cancel).

    On a real TTY: navigate with arrows/↑↓/jk, enter to pick; q or esc to cancel.
    Otherwise: numbered input.
    """
    reader = KeyReader()
    if not reader.enabled:
        return _select_fallback(title, options, subtitle)

    idx = 0
    with reader:
        hide_cursor()
        try:
            while True:
                _render(title, options, idx, subtitle, header)
                key = reader.read()
                if key in ("up", "k"):
                    idx = (idx - 1) % len(options)
                elif key in ("down", "j"):
                    idx = (idx + 1) % len(options)
                elif key == "enter":
                    return idx
                elif key in ("q", "esc"):
                    return None
                elif key.isdigit():
                    n = int(key)
                    if 1 <= n <= len(options):
                        return n - 1
        finally:
            show_cursor()
            clear()


def _render(title: str, options: list[Option], idx: int, subtitle: str, header: str) -> None:
    clear()
    if header:
        sys.stdout.write(color(ACCENT + BOLD, header) + "\n")
    labelw = max(visible_len(o.label) for o in options)
    lines: list[str] = []
    if subtitle:
        lines.append(color(MUTED, subtitle))
        lines.append("")
    for i, opt in enumerate(options):
        selected = i == idx
        pointer = color(ACCENT + BOLD, "❯") if selected else " "
        label = opt.label + " " * (labelw - visible_len(opt.label))
        if selected:
            label = color(BOLD + ACCENT, label)
            hint = color(TEXT, opt.hint)
        else:
            label = color(TEXT, label)
            hint = color(MUTED, opt.hint)
        lines.append(f"{pointer}  {label}   {hint}")
    sys.stdout.write(panel(title, lines) + "\n")
    sys.stdout.write(color(MUTED, "  ↑/↓ move · enter select · q quit") + "\n")
    sys.stdout.flush()


def _select_fallback(title: str, options: list[Option], subtitle: str) -> int | None:
    print(f"\n{title}")
    if subtitle:
        print(f"  {subtitle}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt.label}   {opt.hint}")
    try:
        raw = input("Choice (number, empty to quit): ").strip()
    except EOFError:
        return None
    if not raw:
        return None
    try:
        n = int(raw)
        if 1 <= n <= len(options):
            return n - 1
    except ValueError:
        pass
    return None


def prompt(text: str, default: str = "") -> str:
    """Single-line input with a default-value hint."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(color(ACCENT, "› ") + text + color(MUTED, suffix) + ": ").strip()
    except EOFError:
        return default
    return val or default


def pause() -> None:
    try:
        input(color(MUTED, "\n  ↵ Enter — back to menu"))
    except EOFError:
        pass
