"""
SpectreAD :: core/transport.py
SMB / RPC / WinRM transports behind one interface.

Author : Inayat Hussain
"""

from __future__ import annotations

import socket

from core.creds import Cred


def smb(host: str, cred: Cred, timeout: int = 10, port: int = 445):
    from impacket.smbconnection import SMBConnection

    domain, user, pwd, lm, nt = cred.to_impacket()
    conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
    if cred.kind == "ticket":
        conn.kerberosLogin(user, "", domain, "", lm, nt, useCache=True)
    elif cred.kind == "hash":
        conn.login(user, "", domain, lm, nt)
    elif pwd:
        conn.login(user, pwd, domain)
    else:
        conn.login("", "", "")
    return conn


def anon_smb(host: str, timeout: int = 8):
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host, sess_port=445, timeout=timeout)
    conn.login("", "", "")
    return conn


def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_cred(host: str, cred: Cred, timeout: int = 6) -> bool:
    try:
        conn = smb(host, cred, timeout)
        conn.logoff()
        return True
    except Exception:
        return False


def winrm_session(host: str, cred: Cred, timeout: int = 15):
    try:
        import winrm as pywinrm
    except ImportError:
        return None
    domain, user, pwd, lm, nt = cred.to_impacket()
    return pywinrm.Session(
        f"http://{host}:5985/wsman",
        auth=(f"{domain}\\{user}" if domain else user, pwd or nt),
        transport="ntlm",
        read_timeout_sec=timeout,
        operation_timeout_sec=max(5, timeout - 2),
    )
