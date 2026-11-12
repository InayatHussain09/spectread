"""
SpectreAD :: core/report.py
Markdown + JSON deliverables.

Author : Inayat Hussain
"""

from __future__ import annotations

import json
import os

from config import AUTHOR, TOOL_NAME, VERSION
from core import ui
from core.store import open_store


def write(args) -> None:
    with open_store(args.store) as store:
        if args.report:
            _markdown(store, args.report)
        if args.json_out:
            _json(store, args.json_out)


def _markdown(store, path: str) -> None:
    s = store.summary()
    lines = [
        f"# {TOOL_NAME} engagement report", "",
        f"Author: {AUTHOR}  ",
        f"Tool: {TOOL_NAME} v{VERSION}", "",
        "## Summary", "",
        f"- hosts: {s['hosts']}",
        f"- users: {s['users']}",
        f"- computers: {s['computers']}",
        f"- credentials: {s['creds']}",
        f"- abusable ACEs: {s['aces']}",
        f"- ADCS findings: {s['adcs']}",
        f"- machine accounts created: {s['machines']}",
        f"- DPAPI secrets: {s['dpapi_secrets']}",
        f"- owned principals: {s['owned']}", "",
        "## Findings", "",
    ]
    for f in store.findings():
        lines += [
            f"### [{f['severity'].upper()}] {f['title']}", "",
            f"- host: `{f['host']}`",
            f"- credential: `{f['cred']}`",
            f"- time: {f['ts']}", "",
            "```", f"{f['evidence']}", "```", "",
        ]

    lines += ["## Abusable ACLs", "", "| source | edge | target |", "|---|---|---|"]
    for a in store.aces():
        lines.append(f"| `{a['source']}` | {a['edge']} | `{a['target']}` |")

    lines += ["", "## ADCS", "", "| template | ESC |", "|---|---|"]
    for a in store.adcs():
        lines.append(f"| {a['name']} | {a['esc']} |")

    lines += ["", "## Machine accounts", "", "| name | dn |", "|---|---|"]
    for m in store.machines():
        lines.append(f"| `{m['name']}` | `{m['dn']}` |")

    lines += ["", "## DPAPI secrets", "", "| user | kind | target | secret |",
              "|---|---|---|---|"]
    for d in store.dpapi_secrets():
        lines.append(f"| `{d['user']}` | {d['kind']} | `{d['target']}` | `{d['secret']}` |")

    lines += ["", "## Attack log", "", "| time | stage | action | target | result |",
              "|---|---|---|---|---|"]
    for l in store.attack_log():
        lines.append(f"| {l['ts']} | {l['stage']} | {l['action']} | "
                     f"`{l['target']}` | {l['result']} |")

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    ui.ok(f"report -> {path}")


def _json(store, path: str) -> None:
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "author": AUTHOR,
        "summary": store.summary(),
        "findings": [dict(f) for f in store.findings()],
        "aces": [dict(a) for a in store.aces()],
        "adcs": [dict(a) for a in store.adcs()],
        "machines": [dict(m) for m in store.machines()],
        "dpapi": [dict(d) for d in store.dpapi_secrets()],
        "creds": [{k: v for k, v in dict(c).items() if k != "secret"}
                  for c in store.creds()],
        "log": [dict(l) for l in store.attack_log()],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    os.chmod(path, 0o600)
    ui.ok(f"json -> {path}")
