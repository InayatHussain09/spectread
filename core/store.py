"""
SpectreAD :: core/store.py
SQLite loot, credential cache, attack log, DPAPI and machine tables.

Author : Inayat Hussain
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from config import STORE_PATH

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS hosts(ip TEXT PRIMARY KEY, hostname TEXT, ports TEXT,
    signing TEXT, smbv1 INTEGER, dc INTEGER, first_seen TEXT, last_seen TEXT);

CREATE TABLE IF NOT EXISTS users(sam TEXT PRIMARY KEY, domain TEXT, dn TEXT, enabled INTEGER,
    admincount INTEGER, dontreqpreauth INTEGER, spn TEXT, pwdlastset TEXT, descr TEXT,
    delegation INTEGER, constrained TEXT);

CREATE TABLE IF NOT EXISTS groups(sam TEXT PRIMARY KEY, domain TEXT, dn TEXT, members TEXT);
CREATE TABLE IF NOT EXISTS computers(sam TEXT PRIMARY KEY, domain TEXT, dn TEXT, os TEXT,
    signing TEXT, rbcd INTEGER, delegation INTEGER);
CREATE TABLE IF NOT EXISTS ous(dn TEXT PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS gpos(dn TEXT PRIMARY KEY, name TEXT, path TEXT);
CREATE TABLE IF NOT EXISTS trusts(name TEXT PRIMARY KEY, direction TEXT, flavor TEXT);

CREATE TABLE IF NOT EXISTS policy(domain TEXT PRIMARY KEY, lockout_threshold INTEGER,
    lockout_duration INTEGER, observation_window INTEGER, min_len INTEGER, history INTEGER,
    max_age INTEGER);

CREATE TABLE IF NOT EXISTS creds(id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT,
    username TEXT, secret TEXT, kind TEXT, source TEXT, valid INTEGER, created TEXT,
    UNIQUE(domain, username, secret, kind));

CREATE TABLE IF NOT EXISTS aces(source TEXT, edge TEXT, target TEXT,
    PRIMARY KEY(source, edge, target));
CREATE TABLE IF NOT EXISTS adcs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT,
    esc TEXT, enrollable INTEGER, evidence TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT,
    severity TEXT, title TEXT, evidence TEXT, cred TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS attack_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
    stage TEXT, action TEXT, target TEXT, result TEXT, cred TEXT);
CREATE TABLE IF NOT EXISTS owned(principal TEXT PRIMARY KEY, ts TEXT, how TEXT);

CREATE TABLE IF NOT EXISTS masterkeys(id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid TEXT, guid TEXT, path TEXT, blob BLOB, decrypted INTEGER);
CREATE TABLE IF NOT EXISTS dpapi_secrets(id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT, kind TEXT, target TEXT, secret TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS machines(name TEXT PRIMARY KEY, password TEXT,
    dn TEXT, created TEXT);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str = STORE_PATH):
        self.path = path
        fresh = not os.path.exists(path)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        if fresh:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def batch(self):
        self.db.execute("BEGIN")
        try:
            yield self
        finally:
            self.db.execute("COMMIT")

    # -- meta -------------------------------------------------------------
    def set_meta(self, key: str, value) -> None:
        v = value if isinstance(value, str) else json.dumps(value)
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, v))

    def get_meta(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return row["value"]

    # -- hosts ------------------------------------------------------------
    def add_host(self, ip: str, hostname: str = "", ports=None, signing: str = "",
                 smbv1=None, dc: bool = False) -> None:
        self.db.execute(
            "INSERT INTO hosts(ip,hostname,ports,signing,smbv1,dc,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
            "hostname=COALESCE(NULLIF(excluded.hostname,''),hosts.hostname),"
            "ports=COALESCE(NULLIF(excluded.ports,''),hosts.ports),"
            "signing=COALESCE(NULLIF(excluded.signing,''),hosts.signing),"
            "smbv1=COALESCE(excluded.smbv1,hosts.smbv1),dc=MAX(excluded.dc,hosts.dc),"
            "last_seen=excluded.last_seen",
            (ip, hostname, json.dumps(sorted(ports or [])), signing, smbv1, int(dc),
             _now(), _now()))

    def hosts(self):
        return self.db.execute("SELECT * FROM hosts ORDER BY ip").fetchall()

    def dcs(self):
        return self.db.execute("SELECT * FROM hosts WHERE dc=1").fetchall()

    # -- principals -------------------------------------------------------
    def add_user(self, sam, domain, dn, enabled=True, admincount=False, dontreqpreauth=False,
                 spn="", pwdlastset="", descr="", delegation=False, constrained="") -> None:
        self.db.execute(
            "INSERT INTO users(sam,domain,dn,enabled,admincount,dontreqpreauth,spn,"
            "pwdlastset,descr,delegation,constrained) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(sam) DO UPDATE SET domain=excluded.domain, dn=excluded.dn, "
            "enabled=excluded.enabled, admincount=excluded.admincount, "
            "dontreqpreauth=excluded.dontreqpreauth, spn=excluded.spn, "
            "pwdlastset=excluded.pwdlastset, descr=excluded.descr, "
            "delegation=excluded.delegation, constrained=excluded.constrained",
            (sam, domain, dn, int(enabled), int(admincount), int(dontreqpreauth), spn,
             pwdlastset, descr, int(delegation), constrained))

    def add_group(self, sam, domain, dn, members=None) -> None:
        self.db.execute(
            "INSERT INTO groups(sam,domain,dn,members) VALUES(?,?,?,?) "
            "ON CONFLICT(sam) DO UPDATE SET members=excluded.members",
            (sam, domain, dn, json.dumps(members or [])))

    def add_computer(self, sam, domain, dn, os_="", signing="", rbcd=False,
                     delegation=False) -> None:
        self.db.execute(
            "INSERT INTO computers(sam,domain,dn,os,signing,rbcd,delegation) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(sam) DO UPDATE SET os=excluded.os, "
            "signing=excluded.signing, rbcd=excluded.rbcd, delegation=excluded.delegation",
            (sam, domain, dn, os_, signing, int(rbcd), int(delegation)))

    def add_ou(self, dn, name) -> None:
        self.db.execute("INSERT OR REPLACE INTO ous(dn,name) VALUES(?,?)", (dn, name))

    def add_gpo(self, dn, name, path="") -> None:
        self.db.execute("INSERT OR REPLACE INTO gpos(dn,name,path) VALUES(?,?,?)",
                        (dn, name, path))

    def add_trust(self, name, direction="", flavor="") -> None:
        self.db.execute("INSERT OR REPLACE INTO trusts(name,direction,flavor) VALUES(?,?,?)",
                        (name, direction, flavor))

    def users(self):
        return self.db.execute("SELECT * FROM users ORDER BY sam").fetchall()

    def enabled_users(self):
        return self.db.execute("SELECT * FROM users WHERE enabled=1").fetchall()

    def roastable(self):
        return self.db.execute("SELECT * FROM users WHERE dontreqpreauth=1 OR spn<>''").fetchall()

    def computers(self):
        return self.db.execute("SELECT * FROM computers").fetchall()

    def groups(self):
        return self.db.execute("SELECT * FROM groups").fetchall()

    # -- policy -----------------------------------------------------------
    def set_policy(self, domain, threshold, duration, window, min_len, history, max_age) -> None:
        self.db.execute(
            "INSERT INTO policy(domain,lockout_threshold,lockout_duration,observation_window,"
            "min_len,history,max_age) VALUES(?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET "
            "lockout_threshold=excluded.lockout_threshold, "
            "lockout_duration=excluded.lockout_duration, "
            "observation_window=excluded.observation_window, min_len=excluded.min_len, "
            "history=excluded.history, max_age=excluded.max_age",
            (domain, threshold, duration, window, min_len, history, max_age))

    def policy(self, domain):
        return self.db.execute("SELECT * FROM policy WHERE domain=?", (domain,)).fetchone()

    # -- creds ------------------------------------------------------------
    def add_cred(self, domain, username, secret, kind="password", source="cli",
                 valid=None) -> None:
        self.db.execute(
            "INSERT INTO creds(domain,username,secret,kind,source,valid,created) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(domain,username,secret,kind) DO UPDATE SET "
            "valid=COALESCE(excluded.valid,creds.valid)",
            (domain, username, secret, kind, source,
             None if valid is None else int(valid), _now()))

    def creds(self, valid_only: bool = False):
        q = "SELECT * FROM creds" + (" WHERE valid=1" if valid_only else "")
        return self.db.execute(q + " ORDER BY id").fetchall()

    def mark_cred(self, domain, username, secret, valid: bool) -> None:
        self.db.execute("UPDATE creds SET valid=? WHERE domain=? AND username=? AND secret=?",
                        (int(valid), domain, username, secret))

    # -- graph ------------------------------------------------------------
    def add_ace(self, source, edge_name, target) -> None:
        self.db.execute("INSERT OR IGNORE INTO aces(source,edge,target) VALUES(?,?,?)",
                        (source, edge_name, target))

    def aces(self):
        return self.db.execute("SELECT * FROM aces").fetchall()

    def add_adcs(self, name, esc, enrollable, evidence="") -> None:
        self.db.execute("INSERT INTO adcs(name,esc,enrollable,evidence) VALUES(?,?,?,?)",
                        (name, esc, int(enrollable), evidence))

    def adcs(self):
        return self.db.execute("SELECT * FROM adcs ORDER BY esc").fetchall()

    # -- owned ------------------------------------------------------------
    def add_owned(self, principal, how="") -> None:
        self.db.execute("INSERT OR IGNORE INTO owned(principal,ts,how) VALUES(?,?,?)",
                        (principal, _now(), how))

    def owned(self):
        return [r["principal"] for r in self.db.execute("SELECT principal FROM owned")]

    # -- findings / log ---------------------------------------------------
    def add_finding(self, severity, title, evidence="", host="", cred="") -> None:
        self.db.execute(
            "INSERT INTO findings(host,severity,title,evidence,cred,ts) VALUES(?,?,?,?,?,?)",
            (host, severity, title, evidence, cred, _now()))

    def findings(self):
        return self.db.execute("SELECT * FROM findings ORDER BY id").fetchall()

    def log(self, stage, action, target="", result="", cred="") -> None:
        self.db.execute("INSERT INTO attack_log(ts,stage,action,target,result,cred) "
                        "VALUES(?,?,?,?,?,?)", (_now(), stage, action, target, result, cred))

    def attack_log(self):
        return self.db.execute("SELECT * FROM attack_log ORDER BY id").fetchall()

    # -- dcsync / dpapi / machines ----------------------------------------
    def add_masterkey(self, sid, guid, path, blob) -> None:
        self.db.execute("INSERT INTO masterkeys(sid,guid,path,blob,decrypted) "
                        "VALUES(?,?,?,?,0)", (sid, guid, path, blob))

    def masterkeys(self, decrypted_only: bool = False):
        q = "SELECT * FROM masterkeys" + (" WHERE decrypted=1" if decrypted_only else "")
        return self.db.execute(q).fetchall()

    def mark_masterkey(self, guid) -> None:
        self.db.execute("UPDATE masterkeys SET decrypted=1 WHERE guid=?", (guid,))

    def add_dpapi(self, user, kind, target, secret) -> None:
        self.db.execute("INSERT INTO dpapi_secrets(user,kind,target,secret,ts) "
                        "VALUES(?,?,?,?,?)", (user, kind, target, secret, _now()))

    def dpapi_secrets(self):
        return self.db.execute("SELECT * FROM dpapi_secrets").fetchall()

    def add_machine(self, name, password, dn="") -> None:
        self.db.execute("INSERT OR REPLACE INTO machines(name,password,dn,created) "
                        "VALUES(?,?,?,?)", (name, password, dn, _now()))

    def machines(self):
        return self.db.execute("SELECT * FROM machines").fetchall()

    def summary(self) -> dict:
        def q(t):
            return self.db.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
        return {t: q(t) for t in ("hosts", "users", "groups", "computers", "creds",
                                  "aces", "adcs", "findings", "owned", "machines",
                                  "dpapi_secrets")}


@contextmanager
def open_store(path: str = STORE_PATH):
    s = Store(path)
    try:
        yield s
    finally:
        s.close()
