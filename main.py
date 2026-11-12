#!/usr/bin/env python3
"""
SpectreAD :: main.py
Every module wired, lazy-imported.

Author : Inayat Hussain  ( Red Team Operator & Penetration Tester )
"""

from __future__ import annotations

import importlib
import sys

from config import VERSION
from core import ui
from core.cli import (add_auth_flags, add_exec_flags, add_output_flags,
                      add_target_flags, banner, new_parser)

COMMANDS: dict[str, tuple[str, callable]] = {}

AUTH_TARGET = {"ldap", "passpol", "spn"}
AUTH_TARGET_EXEC = {"psexec", "smbexec", "wmiexec", "atexec", "winrm", "ssh", "rdp",
                    "secrets", "sam", "lsa"}
AUTH_TARGET_PLAIN = {"spray", "asrep", "kerb", "acl", "graph", "paths", "adcs",
                     "delegation", "auto"}
AUTH_TARGET_PROTO = {"dcsync", "dpapi", "addcomputer", "raisechild", "mssql", "vss",
                     "wmi", "ipmi", "exchange", "sccm", "smbclient", "ldap-shell"}


def cmd(name, help_):
    def deco(fn):
        COMMANDS[name] = (help_, fn)
        return fn
    return deco


def _mod(p):
    return importlib.import_module(p)


def _targets(args):
    out = [args.target] if getattr(args, "target", None) else []
    if getattr(args, "targets", None):
        with open(args.targets) as fh:
            out += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    return out


# ------------------------------------------------------------------ recon
@cmd("hosts", "ICMP + TCP sweep on AD service ports")
def r_hosts(args):
    from core.hosts import expand, sweep
    from core.store import open_store
    targets = expand(_targets(args))
    if not targets:
        ui.die("no -target / -targets")
    with open_store(args.store) as store:
        for r in sweep(targets, args.threads, 2.0):
            store.add_host(r["ip"], r["hostname"], r["ports"], dc=r["dc"])


@cmd("ldap", "enumerate users, groups, computers, OUs, GPOs, trusts, policy")
def r_ldap(args):
    from core.creds import resolve
    from core.ldap import enumerate_all
    from core.store import open_store
    with open_store(args.store) as store:
        cred = resolve(args, store, required=not args.anon)
        out = enumerate_all(args.domain, args.dc_ip or args.target, cred, store, args.anon)
        ui.table(["user", "en", "nopreauth", "admin", "deleg", "spn"], out["users"])
        ui.table(["group", "members"], out["groups"])
        ui.table(["computer", "os", "rbcd"], out["computers"])
        ui.table(["trust", "direction"], out["trusts"])


@cmd("smb", "share enum, null session, signing audit, SMBv1")
def r_smb(args):
    from core.creds import resolve
    from core.smb import audit
    from core.store import open_store
    with open_store(args.store) as store:
        cred = resolve(args, store, required=False)
        for t in _targets(args):
            audit(t, cred, store, args.timeout)


@cmd("dns", "AXFR, SRV discovery, NBNS")
def r_dns(args):
    from core.dns import enum
    from core.store import open_store
    with open_store(args.store) as store:
        for t in _targets(args):
            enum(t, args.domain, store)


@cmd("passpol", "read lockout/password policy before spraying")
def r_passpol(args):
    from core.creds import resolve
    from core.ldap import open_conn, policy
    from core.store import open_store
    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn, root = open_conn(args.domain, args.dc_ip or args.target, cred)
        policy(conn, root, args.domain, store)
        conn.unbind()


@cmd("spn", "list SPN accounts (roast candidates)")
def r_spn(args):
    from core.creds import resolve
    from core.ldap import open_conn, spns
    from core.store import open_store
    with open_store(args.store) as store:
        cred = resolve(args, store)
        conn, root = open_conn(args.domain, args.dc_ip or args.target, cred)
        ui.table(["account", "spn"], spns(conn, root))
        conn.unbind()


# ------------------------------------------------------------- credentials
@cmd("spray", "lockout-aware password spray")
def r_spray(args):
    _mod("core.spray").run(args)


@cmd("asrep", "AS-REP roast accounts without preauth")
def r_asrep(args):
    _mod("core.roast").asrep(args)


@cmd("kerb", "Kerberoast every SPN account")
def r_kerb(args):
    _mod("core.roast").kerb(args)


@cmd("ptt", "inject ccache/kirbi into the session")
def r_ptt(args):
    _mod("core.roast").ptt(args)


# -------------------------------------------------------------- lateral
for _n, _h in (
    ("psexec", "SMB service execution"),
    ("smbexec", "SMB semi-interactive, no binary drop"),
    ("wmiexec", "WMI semi-interactive"),
    ("atexec", "Task Scheduler execution"),
    ("winrm", "WinRM / PSRP"),
    ("ssh", "SSH reachability"),
    ("rdp", "RDP reachability"),
):
    def _mk(name=_n):
        def run(args):
            _mod("core.lateral").run(name, args)
        return run
    COMMANDS[_n] = (_h, _mk())


# -------------------------------------------------------------- harvest
@cmd("secrets", "SAM + LSA + cached credentials")
def r_secrets(args):
    _mod("core.dump").secrets(args)


@cmd("sam", "dump local account hashes")
def r_sam(args):
    _mod("core.dump").sam(args)


@cmd("lsa", "dump LSA secrets")
def r_lsa(args):
    _mod("core.dump").lsa(args)


@cmd("gpp", "cpassword from SYSVOL Groups.xml")
def r_gpp(args):
    _mod("core.dump").gpp(args)


@cmd("dcsync", "replicate hashes via DRSUAPI")
def r_dcsync(args):
    _mod("core.dcsync").run(args)


@cmd("dpapi", "masterkey harvest, CredMan, Chrome store")
def r_dpapi(args):
    _mod("core.dpapi").run(args)


@cmd("addcomputer", "create a machine account")
def r_addcomputer(args):
    _mod("core.addcomputer").run(args)


@cmd("raisechild", "child domain -> parent domain")
def r_raisechild(args):
    _mod("core.raisechild").run(args)


# ---------------------------------------------------------- attack paths
@cmd("acl", "enumerate abusable ACEs")
def r_acl(args):
    _mod("core.acl").enumerate_aces(args)


@cmd("abuse", "execute the abuse for a chosen edge")
def r_abuse(args):
    _mod("core.acl").abuse(args)


@cmd("graph", "build and export the principal graph")
def r_graph(args):
    _mod("core.graph").build(args)


@cmd("paths", "shortest path from owned to Domain Admin")
def r_paths(args):
    _mod("core.graph").paths(args)


@cmd("adcs", "enumerate ESC1/2/3/6/8")
def r_adcs(args):
    _mod("core.adcs").enumerate_esc(args)


@cmd("delegation", "report unconstrained / constrained / RBCD")
def r_deleg(args):
    _mod("core.delegation").report(args)


@cmd("s4u", "S4U2Self + S4U2Proxy ticket request")
def r_s4u(args):
    _mod("core.delegation").s4u(args)


@cmd("relay", "LLMNR/NBNS poison + ntlmrelayx")
def r_relay(args):
    _mod("core.relay").relay(args)


# -------------------------------------------------------------- protocols
@cmd("mssql", "MSSQL query and xp_cmdshell")
def r_mssql(args):
    _mod("core.protocols").mssql(args)


@cmd("vss", "shadow copy enumeration")
def r_vss(args):
    _mod("core.protocols").vss(args)


@cmd("wmi", "WMI query")
def r_wmi(args):
    _mod("core.protocols").wmi(args)


@cmd("ipmi", "IPMI default credential sweep")
def r_ipmi(args):
    _mod("core.protocols").ipmi(args)


@cmd("exchange", "Exchange endpoint and autodiscover enum")
def r_exchange(args):
    _mod("core.protocols").exchange(args)


@cmd("sccm", "SCCM distribution point probe")
def r_sccm(args):
    _mod("core.protocols").sccm(args)


# ---------------------------------------------------------------- shells
@cmd("ldap-shell", "interactive LDAP with live modification")
def r_ldapshell(args):
    _mod("core.shell").ldap_shell(args)


@cmd("smbclient", "interactive SMB get/put/ls")
def r_smbclient(args):
    _mod("core.shell").smbclient(args)


# ---------------------------------------------------------------- output
@cmd("report", "write markdown / json deliverables")
def r_report(args):
    _mod("core.report").write(args)


@cmd("auto", "full unattended kill chain")
def r_auto(args):
    _mod("core.auto").run(args)


# ---------------------------------------------------------------- parser
def _configure(sp, name: str) -> None:
    add_output_flags(sp)

    if name in ("hosts", "smb", "dns"):
        add_target_flags(sp)
        return

    if name in AUTH_TARGET:
        add_auth_flags(sp)
        add_target_flags(sp)
    elif name in AUTH_TARGET_EXEC:
        add_auth_flags(sp)
        add_target_flags(sp)
        add_exec_flags(sp)
    elif name in AUTH_TARGET_PLAIN:
        add_auth_flags(sp)
        add_target_flags(sp)
    elif name in AUTH_TARGET_PROTO:
        add_auth_flags(sp)
        add_target_flags(sp)
        sp.add_argument("-dry-run", dest="dry_run", action="store_true",
                        help="print what would run, change nothing")
    elif name == "abuse":
        add_auth_flags(sp)
        sp.add_argument("-target", required=True, help="object to abuse")
        sp.add_argument("-dry-run", dest="dry_run", action="store_true",
                        help="print what would run, change nothing")
    elif name == "s4u":
        add_auth_flags(sp)
    elif name == "relay":
        add_target_flags(sp)

    if name == "ldap":
        sp.add_argument("-anon", action="store_true", help="null bind")
    if name == "spray":
        sp.add_argument("-passes", type=int, default=1, help="password count")
        sp.add_argument("-delay", type=float, default=0.0, help="seconds between attempts")
        sp.add_argument("-jitter", type=float, default=1.0, help="+/- jitter seconds")
        sp.add_argument("-users", help="userlist file (default: LDAP cache)")
        sp.add_argument("-passwords", help="password list (default: built-in)")
        sp.add_argument("-dry-run", dest="dry_run", action="store_true", help="plan only")
    if name in ("asrep", "kerb"):
        sp.add_argument("-wordlist", help="wordlist for hashcat")
        sp.add_argument("-crack", action="store_true", help="crack after roasting")
    if name == "ptt":
        sp.add_argument("-ccache", help=".ccache file")
        sp.add_argument("-kirbi", help=".kirbi file")
    if name == "abuse":
        sp.add_argument("-edge", required=True,
                        choices=["GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
                                 "ForceChangePassword", "AddMember", "AllowedToAct",
                                 "AddKeyCredentialLink"])
        sp.add_argument("-source", required=True, help="principal you control")
        sp.add_argument("-action", default="",
                        choices=["", "forcechange", "addmember", "writeowner",
                                 "writedacl", "setspn", "rbcd", "shadowcred"])
        sp.add_argument("-new-password", dest="new_password", default="SpectreAD!2026")
    if name == "paths":
        sp.add_argument("-owned", help="comma list of owned principals (default: store)")
    if name == "auto":
        sp.add_argument("-wordlist", default="wordlists/passwords.txt")
        sp.add_argument("-yes", action="store_true", help="skip confirmation")
        sp.add_argument("-dry-run", dest="dry_run", action="store_true", help="plan only")
    if name == "relay":
        sp.add_argument("-relay-targets", dest="relay_targets", help="comma hosts")
        sp.add_argument("-poison-ip", dest="poison_ip", help="your IP")
        sp.add_argument("-seconds", type=int, default=300)
        sp.add_argument("-socks", action="store_true")
        sp.add_argument("-dump", action="store_true")
    if name == "s4u":
        sp.add_argument("-spn", required=True)
        sp.add_argument("-impersonate", required=True)
    if name == "adcs":
        sp.add_argument("-request", action="store_true", help="request cert via certipy")
        sp.add_argument("-ca", help="CA name")
        sp.add_argument("-template", help="template name")
        sp.add_argument("-dns", help="SAN dns name")
    if name == "dcsync":
        sp.add_argument("-target-user", dest="target_user", help="single account")
        sp.add_argument("-just-ntlm", dest="just_ntlm", action="store_true",
                        help="hashes only, no cleartext")
    if name == "dpapi":
        sp.add_argument("-target-user", dest="target_user", required=True,
                        help="user whose secrets to decrypt")
    if name == "addcomputer":
        sp.add_argument("-name", help="computer name (default: random)")
        sp.add_argument("-password", help="password (default: random)")
        sp.add_argument("-ou", help="target OU DN")
    if name == "raisechild":
        sp.add_argument("-parent", help="parent domain (default: strip first label)")
        sp.add_argument("-parent-dc", dest="parent_dc", required=True, help="parent DC IP")
    if name == "mssql":
        sp.add_argument("-query", help="SQL to run")
        sp.add_argument("-database", help="USE this database first")


def build():
    p = new_parser()
    p.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    for name, (help_, _fn) in sorted(COMMANDS.items()):
        sp = sub.add_parser(name, help=help_, description=help_, allow_abbrev=False)
        sp.set_defaults(func=_fn)
        _configure(sp, name)

    return p


def main(argv=None) -> int:
    parser = build()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        banner()
        parser.print_help()
        return 0
    if not getattr(args, "quiet", False):
        banner()
    try:
        args.func(args)
    except KeyboardInterrupt:
        ui.warn("interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
