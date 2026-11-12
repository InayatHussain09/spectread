"""
SpectreAD :: config.py
Palette, banner, defaults.

Author : Inayat Hussain  ( Red Team Operator & Penetration Tester )
"""

from __future__ import annotations

import os
import sys

TOOL_NAME = "SpectreAD"
VERSION = "2.1.0"
TAGLINE = "Active Directory Attack Path Framework"
SCOPE = "enumeration · credentials · lateral · attack paths"
AUTHOR = "Inayat Hussain"
AUTHOR_ROLE = "Red Team Operator & Penetration Tester"

DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0.0
DEFAULT_JITTER = 1.0
STORE_PATH = "loot.db"
OUT_DIR = "out"
PROG = "spectread.py"

_FONT = {
    "S": ["  ____  ", " / ___| ", " \\___ \\ ", "  ___) |", " |____/ "],
    "P": [" ____  ", "|  _ \\ ", "| |_) |", "|  __/ ", "|_|    "],
    "E": [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
    "C": ["  ____ ", " / ___|", "| |    ", "| |___ ", " \\____|"],
    "T": [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
    "R": [" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"],
    "A": ["    _    ", "   / \\   ", "  / _ \\  ", " / ___ \\ ", "/_/   \\_\\"],
    "D": [" ____  ", "|  _ \\ ", "| | | |", "| |_| |", "|____/ "],
}

BANNER = [" ".join(_FONT[c][row] for c in "SPECTREAD") for row in range(5)]

BANNER_META = [
    TAGLINE,
    SCOPE,
    "",
    "By " + AUTHOR,
    "( " + AUTHOR_ROLE + " )",
    "v" + VERSION,
]


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


def no_color() -> bool:
    if _truthy("NO_COLOR") or _truthy("SPECTREAD_NO_COLOR"):
        return True
    return not sys.stdout.isatty()


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    ACCENT = "\033[38;5;111m"
    ACCENT2 = "\033[38;5;180m"
    DIM = "\033[38;5;240m"


def paint(text, *styles) -> str:
    if no_color():
        return str(text)
    return "".join(styles) + str(text) + C.RESET
