"""
SpectreAD :: core/addcomputer.py
Machine account creation bounded by MachineAccountQuota.

Author : Inayat Hussain
"""

from __future__ import annotations

import secrets

from core import ui
from core.creds import resolve
from core.store import open_store


def _quota(conn, root) -> int:
    from core.ldap import _paged
    entries = _paged(conn, root, "(objectClass=domainDNS)", ["ms-DS-MachineAccountQuota"])
    if not entries:
        return 0
    return int(entries[0]["ms-DS-MachineAccountQuota"] or 0)


def run(args) -> None:
    from core.ldap import base_dn, connect

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = connect(args.dc_ip or args.target, cred)
        root = base_dn(conn, args.domain)

        quota = _quota(conn, root)
        if quota <= 0:
            ui.die("MachineAccountQuota is 0")
        ui.info(f"MachineAccountQuota = {quota}")

        name = (args.name or f"SPECTRE{secrets.token_hex(3).upper()}").rstrip("$")
        password = args.password or f"Spectre!{secrets.token_hex(8)}"
        dn = f"CN={name},{args.ou or root}"

        ui.card("machine account", [("name", name + "$"), ("dn", dn),
                                    ("password", password)])
        if args.dry_run:
            return

        conn.add(dn, attributes={
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": name,
            "sAMAccountName": name + "$",
            "dNSHostName": f"{name}.{args.domain}",
            "userAccountControl": 0x1020,
            "unicodePwd": f'"{password}"'.encode("utf-16-le"),
        })
        if conn.result["result"] != 0:
            ui.fail(conn.result.get("message", "add failed"))
            return

        ui.ok(f"created {name}$")
        store.add_machine(name + "$", password, dn)
        store.add_cred(args.domain, name + "$", password, "password", "addcomputer")
        store.log("addcomputer", "created", dn, name + "$", cred.identity())
