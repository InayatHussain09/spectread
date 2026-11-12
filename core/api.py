"""
SpectreAD :: core/api.py
Library facade.

Author : Inayat Hussain
"""

from __future__ import annotations

from types import SimpleNamespace

from core.store import open_store

DEFAULTS = dict(
    store="loot.db", out_dir="out", domain="", dc_ip=None, dc_host=None,
    username=None, password=None, hashes=None, kerberos=False, no_pass=False,
    target=None, targets=None, threads=10, timeout=10, dry_run=False,
    quiet=True, timestamp=False, debug=False, exec_cmd="whoami /all",
    shell=False, share="ADMIN$", json_out=None, report=None, graph=None,
    target_user=None, just_ntlm=False, history=False, query=None, database=None,
    name=None, ou=None, parent=None, parent_dc=None,
)


def opts(**kwargs) -> SimpleNamespace:
    merged = dict(DEFAULTS)
    merged.update(kwargs)
    return SimpleNamespace(**merged)


def spray(domain, dc_ip, **kw):
    from core import spray as m
    m.run(opts(domain=domain, dc_ip=dc_ip, **kw))


def asrep(domain, dc_ip, **kw):
    from core import roast
    roast.asrep(opts(domain=domain, dc_ip=dc_ip, **kw))


def kerb(domain, dc_ip, username, password=None, hashes=None, **kw):
    from core import roast
    roast.kerb(opts(domain=domain, dc_ip=dc_ip, username=username,
                    password=password, hashes=hashes, **kw))


def dcsync(domain, dc_ip, username, password=None, hashes=None, **kw):
    from core import dcsync as m
    m.run(opts(domain=domain, dc_ip=dc_ip, username=username,
               password=password, hashes=hashes, **kw))


def acl(domain, dc_ip, username, password=None, hashes=None, **kw):
    from core import acl as m
    m.enumerate_aces(opts(domain=domain, dc_ip=dc_ip, username=username,
                          password=password, hashes=hashes, **kw))


def paths(domain, dc_ip, **kw):
    from core import graph
    graph.paths(opts(domain=domain, dc_ip=dc_ip, **kw))


def report(store="loot.db", md="out/report.md", js="out/report.json"):
    from core import report as m
    m.write(opts(store=store, report=md, json_out=js))


def summary(store="loot.db") -> dict:
    with open_store(store) as s:
        return s.summary()
