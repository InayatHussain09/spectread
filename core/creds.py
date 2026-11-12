"""
SpectreAD :: core/creds.py
Credential object, cache fallback, clock-skew gate.

Author : Inayat Hussain
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass

from core import ui
from core.store import Store

SKEW_LIMIT = 300


@dataclass
class Cred:
    domain: str = ""
    username: str = ""
    secret: str = ""
    kind: str = "password"
    source: str = "cli"

    @property
    def lmhash(self) -> str:
        return self.secret.split(":")[0] if self.kind == "hash" else ""

    @property
    def nthash(self) -> str:
        return self.secret.split(":")[-1] if self.kind == "hash" else ""

    @property
    def ccache(self) -> str:
        return self.secret if self.kind == "ticket" else ""

    def identity(self) -> str:
        who = f"{self.domain}\\{self.username}" if self.domain else self.username
        if self.kind == "hash":
            return f"{who} [hash {self.nthash[:8]}]"
        if self.kind == "ticket":
            return f"{who} [ccache]"
        return f"{who} [password]"

    def to_impacket(self):
        return (self.domain, self.username,
                self.secret if self.kind == "password" else "",
                self.lmhash, self.nthash)

    def apply_env(self) -> None:
        if self.kind == "ticket":
            os.environ["KRB5CCNAME"] = f"FILE:{self.ccache}"

    def persist(self, store: Store, valid=None) -> None:
        if self.username and self.secret:
            store.add_cred(self.domain, self.username, self.secret, self.kind, self.source, valid)


def skew_check(dc_ip: str, limit: int = SKEW_LIMIT) -> bool:
    import socket
    pkt = b"\x1b" + 47 * b"\0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        s.sendto(pkt, (dc_ip, 123))
        data, _ = s.recvfrom(1024)
        s.close()
    except OSError:
        return True
    if len(data) < 48:
        return True
    secs = struct.unpack("!12I", data[0:48])[10]
    delta = abs(time.time() - (secs - 2208988800))
    if delta > limit:
        ui.fail(f"clock skew {int(delta)}s > {limit}s — Kerberos will fail")
        ui.info(f"fix: sudo ntpdate {dc_ip}")
        return False
    return True


def resolve(args, store: Store | None = None, required: bool = True) -> Cred | None:
    raw = getattr(args, "username", None) or ""
    domain = getattr(args, "domain", None) or ""
    if "\\" in raw:
        domain, raw = raw.split("\\", 1)
    elif "@" in raw and not domain:
        raw, domain = raw.split("@", 1)

    hashes = getattr(args, "hashes", None)
    password = getattr(args, "password", None)
    kerberos = getattr(args, "kerberos", False)

    if kerberos:
        dc_ip = getattr(args, "dc_ip", None)
        if not getattr(args, "dc_host", None):
            ui.warn("Kerberos without -dc-host — KDC wants an SPN-valid FQDN")
        if dc_ip and not skew_check(dc_ip):
            ui.die("clock skew too large")

    if hashes:
        if ":" not in hashes:
            hashes = ":" + hashes
        cred = Cred(domain, raw, hashes, "hash")
    elif kerberos:
        cc = os.environ.get("KRB5CCNAME", "").replace("FILE:", "")
        if not cc or not os.path.exists(cc):
            ui.die("Kerberos requested but no valid KRB5CCNAME (run: ptt -ccache <file>)")
        cred = Cred(domain, raw, cc, "ticket")
    elif password is not None:
        cred = Cred(domain, raw, password, "password")
    elif getattr(args, "no_pass", False):
        cred = Cred(domain, raw, "", "password")
    elif store is not None:
        rows = store.creds(valid_only=True)
        if raw:
            rows = [r for r in rows if r["username"].lower() == raw.lower()]
        if not rows:
            if required:
                ui.die("no credential given and cache holds none for that user")
            return None
        r = rows[-1]
        cred = Cred(r["domain"], r["username"], r["secret"], r["kind"], "cache")
    elif required:
        ui.die("no credential given (-u/-p, -H, -k, -no-pass)")
        return None
    else:
        return None

    cred.apply_env()
    return cred
