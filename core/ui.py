"""
SpectreAD :: core/ui.py
Tables, cards, findings, progress.

Author : Inayat Hussain
"""

from __future__ import annotations

import sys

from config import C, paint

SEV_COLOR = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW, "low": C.CYAN, "info": C.GREY}


def info(msg: str) -> None:
    print(paint("[*] ", C.CYAN) + msg)


def ok(msg: str) -> None:
    print(paint("[+] ", C.GREEN) + msg)


def warn(msg: str) -> None:
    print(paint("[!] ", C.YELLOW) + msg)


def fail(msg: str) -> None:
    print(paint("[-] ", C.RED) + msg)


def edge(msg: str) -> None:
    print(paint("[>] ", C.ACCENT2) + msg)


def stage(n: int, total: int, msg: str) -> None:
    print()
    print(paint(f"  [{n}/{total}] ", C.BOLD, C.ACCENT2) + paint(msg.upper(), C.WHITE, C.BOLD))
    print(paint("  " + "─" * 62, C.DIM))


def die(msg: str, code: int = 1) -> None:
    fail(msg)
    sys.exit(code)


def table(headers, rows, empty: str = "nothing found") -> None:
    rows = [list(map(str, r)) for r in rows]
    if not rows:
        warn(empty)
        return
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def rule(ch="-"):
        return paint("  +" + "+".join(ch * (w + 2) for w in widths) + "+", C.DIM)

    print(rule())
    print(paint("  |", C.DIM) + paint("|", C.DIM).join(
        " " + paint(h.ljust(widths[i]), C.BOLD, C.WHITE) + " " for i, h in enumerate(headers)
    ) + paint("|", C.DIM))
    print(rule("="))
    for r in rows:
        print(paint("  |", C.DIM) + paint("|", C.DIM).join(
            " " + cell.ljust(widths[i]) + " " for i, cell in enumerate(r)
        ) + paint("|", C.DIM))
    print(rule())


def card(title: str, pairs) -> None:
    print()
    print(paint("  " + title.upper(), C.BOLD, C.ACCENT2))
    print(paint("  " + "─" * max(len(title), 34), C.DIM))
    for k, v in pairs:
        print(paint("  " + str(k).ljust(22), C.GREY) + str(v))
    print()


def finding(severity: str, title: str, evidence: str = "") -> None:
    color = SEV_COLOR.get(severity.lower(), C.GREY)
    print(paint(f"  [{severity.upper():8}] ", color, C.BOLD) + title)
    if evidence:
        print(paint("             " + evidence, C.GREY))


def hop(n: int, source: str, edge_name: str, target: str, cmd: str) -> None:
    print(paint(f"  {n}. {source} ", C.WHITE)
          + paint(f"--[{edge_name}]--> ", C.ACCENT2)
          + paint(target, C.WHITE))
    print(paint("     " + cmd, C.GREY))


def bar(done: int, total: int, width: int = 30) -> None:
    if total <= 0:
        return
    filled = int(width * done / total)
    sys.stdout.write("\r  " + paint("#" * filled, C.ACCENT2) + paint("." * (width - filled), C.DIM)
                     + f" {done}/{total}")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
