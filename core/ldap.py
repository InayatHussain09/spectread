"""
SpectreAD :: core/ldap.py
LDAPS-first enumeration with paging.

Author : Inayat Hussain
"""

from __future__ import annotations

from ldap3 import ALL, BASE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from core import ui
from core.creds import Cred
from core.store import Store

ATTRS_USER = ["sAMAccountName", "distinguishedName", "userAccountControl", "adminCount",
              "servicePrincipalName", "pwdLastSet", "description", "msDS-AllowedToDelegateTo"]
ATTRS_GROUP = ["sAMAccountName", "distinguishedName", "member"]
ATTRS_COMPUTER = ["sAMAccountName", "distinguishedName", "operatingSystem",
                  "userAccountControl", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
ATTRS_POLICY = ["lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
                "minPwdLength", "pwdHistoryLength", "maxPwdAge"]

UAC_TRUSTED_FOR_DELEGATION = 0x80000


def _server(dc: str, ldaps: bool):
    tls = Tls(validate=0) if ldaps else None
    return Server(dc, port=636 if ldaps else 389, get_info=ALL,
                  use_ssl=ldaps, tls=tls, connect_timeout=10)


def connect(dc: str, cred: Cred | None, anon: bool = False, ldaps: bool = True) -> Connection:
    last = None
    for use_ssl in ([True, False] if ldaps else [False]):
        try:
            srv = _server(dc, use_ssl)
            if anon or cred is None:
                conn = Connection(srv, auto_bind=True, receive_timeout=20)
            else:
                domain, user, pwd, lm, nt = cred.to_impacket()
                if cred.kind == "ticket":
                    conn = Connection(srv, authentication="GSSAPI", auto_bind=True,
                                      receive_timeout=20)
                else:
                    conn = Connection(srv, user=f"{domain}\\{user}", password=pwd or nt,
                                      authentication="NTLM", auto_bind=True,
                                      receive_timeout=20)
            if use_ssl:
                ui.info("bound over LDAPS (636)")
            return conn
        except (LDAPException, OSError) as exc:
            last = exc
    raise LDAPException(f"cannot bind {dc}: {last}")


def base_dn(conn: Connection, domain: str) -> str:
    try:
        conn.search("", "(objectClass=*)", BASE,
                    attributes=["defaultNamingContext", "rootDomainNamingContext"])
        if conn.entries:
            dn = str(conn.entries[0]["defaultNamingContext"])
            if dn:
                return dn
    except (LDAPException, IndexError):
        pass
    return ",".join(f"DC={p}" for p in domain.split("."))


def _paged(conn: Connection, dn: str, flt: str, attrs) -> list:
    out, cookie = [], None
    while True:
        try:
            conn.search(dn, flt, SUBTREE, attributes=attrs, paged_size=500,
                        paged_cookie=cookie)
        except LDAPException as exc:
            ui.fail(f"search failed: {exc}")
            return out
        out += list(conn.entries)
        cookie = conn.result.get("controls", {}).get(
            "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
        if not cookie:
            return out


def _flags(uac: int):
    return not bool(uac & 0x2), not bool(uac & 0x400000)


def enumerate_all(domain: str, dc: str, cred: Cred | None, store: Store,
                  anon: bool = False, ldaps: bool = True) -> dict:
    conn = connect(dc, cred, anon, ldaps)
    root = base_dn(conn, domain)
    store.set_meta("base_dn", root)
    out = {"users": [], "groups": [], "computers": [], "trusts": []}

    with store.batch():
        for e in _paged(conn, root, "(&(objectCategory=person)(objectClass=user))", ATTRS_USER):
            sam = str(e["sAMAccountName"])
            if not sam:
                continue
            uac = int(e["userAccountControl"] or 0)
            enabled, preauth = _flags(uac)
            spn = ",".join(str(s) for s in e["servicePrincipalName"]) if e["servicePrincipalName"] else ""
            cons = ",".join(str(s) for s in e["msDS-AllowedToDelegateTo"]) \
                if e["msDS-AllowedToDelegateTo"] else ""
            store.add_user(sam, domain, str(e["distinguishedName"]), enabled,
                           bool(e["adminCount"]), preauth, spn,
                           str(e["pwdLastSet"] or ""), str(e["description"] or ""),
                           bool(uac & UAC_TRUSTED_FOR_DELEGATION), cons)
            out["users"].append((sam, "yes" if enabled else "no",
                                 "yes" if preauth else "",
                                 "yes" if e["adminCount"] else "",
                                 "yes" if uac & UAC_TRUSTED_FOR_DELEGATION else "",
                                 spn[:38]))

        for e in _paged(conn, root, "(objectCategory=group)", ATTRS_GROUP):
            sam = str(e["sAMAccountName"])
            if not sam:
                continue
            members = [str(m) for m in e["member"]] if e["member"] else []
            store.add_group(sam, domain, str(e["distinguishedName"]), members)
            out["groups"].append((sam, len(members)))

        for e in _paged(conn, root, "(objectCategory=computer)", ATTRS_COMPUTER):
            sam = str(e["sAMAccountName"])
            if not sam:
                continue
            uac = int(e["userAccountControl"] or 0)
            rbcd = bool(e["msDS-AllowedToActOnBehalfOfOtherIdentity"])
            store.add_computer(sam, domain, str(e["distinguishedName"]),
                               str(e["operatingSystem"] or ""), "", rbcd,
                               bool(uac & UAC_TRUSTED_FOR_DELEGATION))
            out["computers"].append((sam, str(e["operatingSystem"] or ""),
                                     "yes" if rbcd else ""))

        for e in _paged(conn, root, "(objectClass=organizationalUnit)",
                        ["distinguishedName", "name"]):
            store.add_ou(str(e["distinguishedName"]), str(e["name"]))

        for e in _paged(conn, root, "(objectClass=groupPolicyContainer)",
                        ["displayName", "gPCFileSysPath"]):
            store.add_gpo(str(e["distinguishedName"]), str(e["displayName"]),
                          str(e["gPCFileSysPath"]))

        for e in _paged(conn, root, "(objectClass=trustedDomain)",
                        ["trustPartner", "trustDirection", "trustType"]):
            store.add_trust(str(e["trustPartner"]), str(e["trustDirection"]),
                            str(e["trustType"]))
            out["trusts"].append((str(e["trustPartner"]), str(e["trustDirection"])))

    policy(conn, root, domain, store)
    conn.unbind()
    return out


def policy(conn: Connection, root: str, domain: str, store: Store) -> None:
    entries = _paged(conn, root, "(objectClass=domainDNS)", ATTRS_POLICY)
    if not entries:
        ui.warn("policy unreadable (needs authenticated bind)")
        return
    e = entries[0]
    threshold = int(e["lockoutThreshold"] or 0)
    duration = int(e["lockoutDuration"] or 0)
    window = int(e["lockOutObservationWindow"] or 0)
    store.set_policy(domain, threshold, duration, window,
                     int(e["minPwdLength"] or 0), int(e["pwdHistoryLength"] or 0),
                     int(e["maxPwdAge"] or 0))
    ui.card("domain password policy", [
        ("lockoutThreshold", threshold or "never"),
        ("lockoutDuration", duration),
        ("observationWindow", window),
        ("minPwdLength", int(e["minPwdLength"] or 0)),
        ("pwdHistoryLength", int(e["pwdHistoryLength"] or 0)),
    ])
    if threshold:
        ui.ok(f"spray budget: {threshold - 1} attempt(s) per user per window")
    else:
        ui.warn("lockoutThreshold=0 — unlimited attempts")


def spns(conn: Connection, root: str) -> list[tuple]:
    rows = []
    for e in _paged(conn, root,
                    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                    ["sAMAccountName", "servicePrincipalName"]):
        sam = str(e["sAMAccountName"])
        if sam.endswith("$"):
            continue
        rows.append((sam, ",".join(str(s) for s in e["servicePrincipalName"])[:60]))
    return rows


def find_object(conn: Connection, root: str, value: str):
    if value.startswith("CN=") or value.startswith("OU="):
        flt = f"(distinguishedName={escape_filter_chars(value)})"
    elif value.startswith("S-1-"):
        flt = f"(objectSid={escape_filter_chars(value)})"
    else:
        flt = (f"(|(&(objectClass=user)(sAMAccountName={escape_filter_chars(value)}))"
               f"(&(objectClass=group)(sAMAccountName={escape_filter_chars(value)}))"
               f"(&(objectClass=computer)(sAMAccountName={escape_filter_chars(value)})))")
    entries = _paged(conn, root, flt, ["distinguishedName", "objectSid", "sAMAccountName"])
    return entries[0] if entries else None


def open_conn(domain: str, dc: str, cred: Cred | None, anon: bool = False,
              ldaps: bool = True):
    conn = connect(dc, cred, anon, ldaps)
    return conn, base_dn(conn, domain)
