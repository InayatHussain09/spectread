"""
SpectreAD :: core/hosts.py
ICMP + TCP sweep on AD service ports.

Author : Inayat Hussain
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import ui
from core.transport import tcp_open

AD_PORTS = [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 3389, 5985, 5986, 9389]


def expand(targets: list[str]) -> list[str]:
    out: list[str] = []
    for raw in targets:
        t = raw.strip()
        if not t or t.startswith("#"):
            continue
        try:
            if "/" in t:
                out += [str(h) for h in ipaddress.ip_network(t, strict=False).hosts()]
            else:
                out.append(t)
        except ValueError:
            out.append(t)
    return out


def ping(host: str, timeout: int = 1) -> bool:
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", str(timeout), host],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def scan(host: str, ports=None, timeout: float = 2.0) -> list[int]:
    return [p for p in (ports or AD_PORTS) if tcp_open(host, p, timeout)]


def rev(ip: str) -> str:
    try:
        socket.setdefaulttimeout(2)
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def sweep(hosts: list[str], threads: int = 10, timeout: float = 2.0) -> list[dict]:
    results: list[dict] = []

    def work(h: str):
        if not ping(h) and not tcp_open(h, 445, timeout) and not tcp_open(h, 389, timeout):
            return None
        ports = scan(h, timeout=timeout)
        if not ports:
            return None
        return {"ip": h, "hostname": rev(h), "ports": ports,
                "dc": 88 in ports and 389 in ports}

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = [pool.submit(work, h) for h in hosts]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
                ui.ok(f"{r['ip']:<16} {r['hostname']:<26} {','.join(map(str, r['ports']))}"
                      + ("  [DC]" if r["dc"] else ""))
    return sorted(results, key=lambda r: r["ip"])
