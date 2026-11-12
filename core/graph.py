"""
SpectreAD :: core/graph.py
Attack graph, shortest path to Domain Admin, DOT export.

Author : Inayat Hussain
"""

from __future__ import annotations

import networkx as nx

from core import ui
from core.store import open_store

DA_NAMES = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
            "SCHEMA ADMINS", "ACCOUNT OPERATORS", "BACKUP OPERATORS")

COST = {"GenericAll": 1, "WriteDACL": 1, "WriteOwner": 2, "ForceChangePassword": 1,
        "AddMember": 1, "AllowedToAct": 2, "AddKeyCredentialLink": 2}


def _graph(store) -> nx.DiGraph:
    g = nx.DiGraph()
    for row in store.aces():
        g.add_edge(row["source"], row["target"], edge=row["edge"],
                   weight=COST.get(row["edge"], 3))
    return g


def build(args) -> None:
    with open_store(args.store) as store:
        g = _graph(store)
        ui.info(f"{g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
        if args.graph:
            nx.nx_pydot.write_dot(g, args.graph)
            ui.ok(f"dot -> {args.graph}")


def paths(args) -> None:
    with open_store(args.store) as store:
        g = _graph(store)
        owned = store.owned()
        if getattr(args, "owned", None):
            owned = [o.strip() for o in args.owned.split(",")]
        if not owned:
            ui.die("no owned principals — spray/roast first, or pass -owned")

        da_nodes = [n for n in g.nodes if n.upper() in DA_NAMES]
        if not da_nodes:
            ui.die("no Domain Admin node in graph — run acl first")

        ui.info(f"owned: {len(owned)}; targets: {', '.join(da_nodes)}")
        found = 0
        for start in owned:
            if start not in g:
                continue
            for da in da_nodes:
                try:
                    chain = nx.dijkstra_path(g, start, da, weight="weight")
                except nx.NetworkXNoPath:
                    continue
                found += 1
                _print_chain(g, chain)
                store.add_finding("critical", "Path to Domain Admin", " -> ".join(chain))

        if found:
            ui.ok(f"{found} path(s) found")
        else:
            ui.warn("no path from owned principals")


def _print_chain(g, chain) -> None:
    print()
    ui.edge(f"path ({len(chain) - 1} hops)")
    for i, (a, b) in enumerate(zip(chain, chain[1:]), 1):
        e = g[a][b]["edge"]
        ui.hop(i, a, e, b, f"spectread.py abuse -edge {e} -source {a} -target '{b}'")
    print()
