"""
SpectreAD :: core/shell.py
Interactive LDAP shell and SMB client.

Author : Inayat Hussain
"""

from __future__ import annotations

import os
import shlex

from core import ui
from core.creds import resolve
from core.store import open_store


def ldap_shell(args) -> None:
    import readline  # noqa: F401
    from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

    from core.ldap import _paged, base_dn, connect, find_object

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = connect(args.dc_ip or args.target, cred)
        root = base_dn(conn, args.domain)
        ui.ok(f"bound as {cred.identity()}")
        ui.info("type 'help'")

        while True:
            try:
                raw = input(ui.paint("ldap> ", "\033[38;5;111m")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not raw:
                continue
            cmd, *rest = shlex.split(raw)
            cmd = cmd.lower()

            if cmd in ("exit", "quit", "q"):
                break
            if cmd == "help":
                ui.table(["command", "does"], [
                    ("search <filter>", "raw LDAP search"),
                    ("dump users|groups|computers", "list objects"),
                    ("addmember <group> <user>", "add to group"),
                    ("delmember <group> <user>", "remove from group"),
                    ("addspn <user> <spn>", "set an SPN"),
                    ("password <user> <new>", "force password change"),
                    ("owner <object> <principal>", "take ownership"),
                    ("rbcd <computer> <principal>", "write RBCD"),
                    ("sid <name>", "resolve objectSid"),
                ])
                continue

            try:
                if cmd == "search" and rest:
                    entries = _paged(conn, root, " ".join(rest),
                                     ["sAMAccountName", "distinguishedName"])
                    ui.table(["sam", "dn"],
                             [(str(e["sAMAccountName"]), str(e["distinguishedName"]))
                              for e in entries])
                elif cmd == "dump" and rest:
                    flt = {"users": "(objectClass=user)", "groups": "(objectClass=group)",
                           "computers": "(objectClass=computer)"}.get(rest[0].lower())
                    if not flt:
                        ui.warn("users | groups | computers")
                        continue
                    entries = _paged(conn, root, flt,
                                     ["sAMAccountName", "distinguishedName"])
                    ui.table(["sam", "dn"],
                             [(str(e["sAMAccountName"]), str(e["distinguishedName"]))
                              for e in entries])
                elif cmd == "addmember" and len(rest) == 2:
                    g, u = find_object(conn, root, rest[0]), find_object(conn, root, rest[1])
                    conn.modify(str(g["distinguishedName"]),
                                {"member": [(MODIFY_ADD, str(u["distinguishedName"]))]})
                    ui.ok("added") if conn.result["result"] == 0 else ui.fail(conn.result["message"])
                elif cmd == "delmember" and len(rest) == 2:
                    g, u = find_object(conn, root, rest[0]), find_object(conn, root, rest[1])
                    conn.modify(str(g["distinguishedName"]),
                                {"member": [(MODIFY_DELETE, str(u["distinguishedName"]))]})
                    ui.ok("removed") if conn.result["result"] == 0 else ui.fail(conn.result["message"])
                elif cmd == "addspn" and len(rest) == 2:
                    t = find_object(conn, root, rest[0])
                    conn.modify(str(t["distinguishedName"]),
                                {"servicePrincipalName": [(MODIFY_ADD, rest[1])]})
                    ui.ok("spn set") if conn.result["result"] == 0 else ui.fail(conn.result["message"])
                elif cmd == "password" and len(rest) == 2:
                    t = find_object(conn, root, rest[0])
                    conn.modify(str(t["distinguishedName"]),
                                {"unicodePwd": [(MODIFY_REPLACE,
                                                 f'"{rest[1]}"'.encode("utf-16-le"))]})
                    ui.ok("password set") if conn.result["result"] == 0 else ui.fail(conn.result["message"])
                elif cmd == "owner" and len(rest) == 2:
                    t, p = find_object(conn, root, rest[0]), find_object(conn, root, rest[1])
                    conn.modify(str(t["distinguishedName"]),
                                {"owner": [(MODIFY_REPLACE, p["objectSid"].raw_values[0])]})
                    ui.ok("owned") if conn.result["result"] == 0 else ui.fail(conn.result["message"])
                elif cmd == "rbcd" and len(rest) == 2:
                    from core.acl import _sd_with_generic_all
                    t, p = find_object(conn, root, rest[0]), find_object(conn, root, rest[1])
                    conn.modify(str(t["distinguishedName"]),
                                {"msDS-AllowedToActOnBehalfOfOtherIdentity":
                                 [(MODIFY_REPLACE,
                                   _sd_with_generic_all(p["objectSid"].raw_values[0]))]})
                    ui.ok("rbcd written") if conn.result["result"] == 0 else ui.fail(conn.result["message"])
                elif cmd == "sid" and rest:
                    o = find_object(conn, root, rest[0])
                    print(o["objectSid"].raw_values[0].hex() if o else "not found")
                else:
                    ui.warn(f"unknown or incomplete: {cmd}")
            except Exception as exc:
                ui.fail(str(exc))

        conn.unbind()


def smbclient(args) -> None:
    import readline  # noqa: F401

    from core.transport import smb

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = smb(args.target, cred)
        share = args.share or "C$"
        cwd = ""

        ui.ok(f"connected to {args.target} as {cred.identity()}")
        try:
            conn.connectTree(share)
        except Exception as exc:
            ui.die(f"cannot mount {share}: {exc}")
        ui.info("ls, cd, get, put, rm, mkdir, shares, exit")

        while True:
            try:
                raw = input(ui.paint(f"smb:{share}\\{cwd}> ", "\033[38;5;111m")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not raw:
                continue
            cmd, *rest = shlex.split(raw)
            cmd = cmd.lower()

            if cmd in ("exit", "quit", "q"):
                break
            try:
                if cmd == "shares":
                    ui.table(["share", "remark"],
                             [(s["shi1_netname"][:-1], s["shi1_remark"][:-1])
                              for s in conn.listShares()])
                elif cmd == "ls":
                    path = f"{cwd}\\{rest[0]}" if rest else (cwd or "")
                    rows = []
                    for f in conn.listPath(share, (path + "\\*") if path else "*"):
                        n = f.get_longname()
                        if n in (".", ".."):
                            continue
                        rows.append((n, "dir" if f.is_directory() else f.get_filesize()))
                    ui.table(["name", "size"], rows)
                elif cmd == "cd":
                    if rest and rest[0] == "..":
                        cwd = "\\".join(cwd.split("\\")[:-1])
                    elif rest:
                        cwd = f"{cwd}\\{rest[0]}" if cwd else rest[0]
                elif cmd == "get" and rest:
                    remote = f"{cwd}\\{rest[0]}" if cwd else rest[0]
                    local = rest[1] if len(rest) > 1 else os.path.basename(rest[0])
                    with open(local, "wb") as fh:
                        conn.getFile(share, remote, fh.write)
                    ui.ok(f"{os.path.getsize(local)} bytes -> {local}")
                elif cmd == "put" and rest:
                    name = os.path.basename(rest[0])
                    remote = f"{cwd}\\{name}" if cwd else name
                    with open(rest[0], "rb") as fh:
                        conn.putFile(share, remote, fh.read)
                    ui.ok(f"uploaded {remote}")
                elif cmd == "rm" and rest:
                    conn.deleteFile(share, f"{cwd}\\{rest[0]}" if cwd else rest[0])
                    ui.ok("deleted")
                elif cmd == "mkdir" and rest:
                    conn.createDirectory(share, f"{cwd}\\{rest[0]}" if cwd else rest[0])
                    ui.ok("created")
                else:
                    ui.warn(f"unknown or incomplete: {cmd}")
            except Exception as exc:
                ui.fail(str(exc))

        conn.logoff()
