"""
SpectreAD :: core/cli.py
Impacket-style help: yellow usage, yellow flags, banner on every run.

Author : Inayat Hussain
"""

from __future__ import annotations

import argparse
import re
import sys

from config import BANNER, BANNER_META, C, PROG, paint

Y = "\033[93m"
R = "\033[0m"


class SpectreParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        text = super().format_help()
        text = re.sub(r"(?m)^(usage:.*)$", lambda m: Y + m.group(1) + R, text)
        text = re.sub(r"(?<![\w-])(--?[A-Za-z][\w-]*)", lambda m: Y + m.group(1) + R, text)
        text = re.sub(
            r"(?m)^(positional arguments:|options:|required arguments:|"
            r"authentication:|target:|execution:|output:|spray options:|abuse:|.* options:)$",
            lambda m: paint(m.group(1), C.BOLD, C.WHITE),
            text,
        )
        return text

    def error(self, message: str) -> None:
        sys.stderr.write(f"{Y}{self.format_usage()}{R}")
        self.exit(2, f"{Y}{self.prog}: error: {message}{R}\n")


def banner() -> None:
    print()
    for line in BANNER:
        print(paint(line, C.ACCENT))
    print()
    for i, line in enumerate(BANNER_META):
        if not line:
            print()
        elif i == 0:
            print(paint("        " + line, C.WHITE, C.BOLD))
        elif i == 1:
            print(paint("        " + line, C.ACCENT2))
        else:
            print(paint("        " + line, C.GREY))
    print()


def add_auth_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("authentication")
    g.add_argument("-u", "--username", help="DOMAIN\\user or user@domain")
    g.add_argument("-p", "--password", help="password")
    g.add_argument("-H", "--hashes", help="LMHASH:NTHASH (pass-the-hash)")
    g.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos (ccache)")
    g.add_argument("-no-pass", dest="no_pass", action="store_true", help="prompt-free empty password")
    g.add_argument("-d", "--domain", help="target domain")
    g.add_argument("-dc-ip", dest="dc_ip", help="DC IP address")
    g.add_argument("-dc-host", dest="dc_host", help="DC FQDN (required for -k)")
    g.add_argument("-ts", "--timestamp", action="store_true", help="timestamp output")
    g.add_argument("-debug", action="store_true", help="verbose errors")


def add_target_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("target")
    g.add_argument("-target", help="single host (IP or name)")
    g.add_argument("-targets", help="file of hosts, one per line")
    g.add_argument("-threads", type=int, default=10, help="concurrency (default 10)")
    g.add_argument("-timeout", type=int, default=10, help="socket timeout")


def add_exec_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("execution")
    g.add_argument("-exec", dest="exec_cmd", default="whoami /all",
                   help="command to run (default: whoami /all)")
    g.add_argument("-shell", action="store_true", help="interactive shell")
    g.add_argument("-dry-run", dest="dry_run", action="store_true",
                   help="print what would run, change nothing")
    g.add_argument("-share", default="ADMIN$", help="remote share (default ADMIN$)")


def add_output_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("-store", default="loot.db", help="SQLite loot file (default loot.db)")
    g.add_argument("-o", dest="out_dir", default="out", help="artifact directory (default out)")
    g.add_argument("-json", dest="json_out", help="write JSON results")
    g.add_argument("-report", help="write markdown report")
    g.add_argument("-graph", help="write DOT graph")
    g.add_argument("-q", "--quiet", action="store_true", help="suppress banner")


def new_parser() -> SpectreParser:
    return SpectreParser(
        prog=PROG,
        add_help=True,
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
