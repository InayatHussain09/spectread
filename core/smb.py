"""
SpectreAD :: core/smb.py
Share enum, null session, signing audit, SMBv1 probe.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import ui
from core.creds import Cred
from core.store import Store
from core.transport import anon_smb, smb


def audit(host: str, cred: Cred | None, store: Store, timeout: int = 8) -> None:
    signing, smbv1, shares = "", None, []

    try:
        conn = smb(host, cred, timeout) if cred else anon_smb(host, timeout)
    except Exception as exc:
        ui.fail(f"{host}: {exc}")
        return

    try:
        signing = "required" if conn.isSigningRequired() else "NOT required"
        if conn.isSigningRequired():
            ui.info(f"{host}: signing required — relay not possible")
        else:
            ui.warn(f"{host}: signing NOT required — relay candidate")
            store.add_finding("high", "SMB signing disabled",
                              f"{host} accepts unsigned SMB", host=host)
        try:
            conn.connectTree("IPC$")
            smbv1 = 1 if conn.getDialect() == 0x0202 else 0
        except Exception:
            pass

        for share in conn.listShares():
            shares.append((share["shi1_netname"][:-1], share["shi1_remark"][:-1]))

        store.add_host(host, conn.getServerName() or "", signing=signing, smbv1=smbv1)
        ui.table(["share", "remark"], shares)

        readable = []
        for name, _ in shares:
            if name.upper() in ("IPC$", "PRINT$"):
                continue
            try:
                conn.connectTree(name)
                readable.append(name)
            except Exception:
                pass
        if readable:
            ui.ok(f"{host}: readable: {', '.join(readable)}")
    except Exception as exc:
        ui.fail(f"{host}: {exc}")
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
