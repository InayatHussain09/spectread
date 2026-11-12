"""
SpectreAD :: core/dns.py
AXFR, SRV discovery, NBNS.

Author : Inayat Hussain
"""

from __future__ import annotations

import socket
import struct

from core import ui
from core.store import Store


def axfr(domain: str, ns: str) -> list[str]:
    try:
        import dns.query
        import dns.zone
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
        return [str(n) for n in zone.nodes.keys()]
    except Exception as exc:
        ui.fail(f"AXFR {domain} @{ns}: {exc}")
        return []


def srv(domain: str, dc: str) -> list[tuple]:
    rows = []
    try:
        import dns.resolver
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [dc]
        res.timeout = 5
        for q in ("_ldap._tcp.dc._msdcs", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp"):
            try:
                for a in res.resolve(f"{q}.{domain}", "SRV"):
                    rows.append((q, str(a.target), a.port))
            except Exception:
                pass
    except ImportError:
        ui.fail("dnspython missing")
    return rows


def nbns(host: str, timeout: float = 2.0) -> str:
    pkt = (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (host, 137))
        data, _ = s.recvfrom(2048)
        s.close()
    except OSError:
        return ""
    if len(data) < 57:
        return ""
    names, off = [], 57
    for _ in range(data[56]):
        if off + 18 > len(data):
            break
        raw = data[off:off + 15].decode("ascii", "ignore").strip()
        flags = struct.unpack("!H", data[off + 16:off + 18])[0]
        if raw and (flags >> 15) == 0:
            names.append(raw)
        off += 18
    return ",".join(sorted(set(names)))


def enum(target: str, domain: str, store: Store) -> None:
    names = nbns(target)
    if names:
        ui.ok(f"{target}: NetBIOS {names}")
        store.add_host(target, names.split(",")[0])

    if domain:
        rows = srv(domain, target)
        if rows:
            ui.table(["record", "target", "port"], rows)
            for _, tgt, _p in rows:
                store.add_host(tgt.rstrip("."), tgt)

        if names:
            records = axfr(domain, target)
            if records:
                ui.ok(f"{target}: AXFR {len(records)} records")
                for r in records:
                    store.add_host(r.rstrip("."), r)
