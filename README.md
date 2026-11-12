# SpectreAD

```
 ██████ ██████ ███████  ██████ ███████ ██████ ███████  █████  ██████ 
██     ██████ ██      ██        ██    ██████ ██      ██   ██ ██████ 
 █████ ██   ██ █████  ██        ██    ██████ █████  ███████ ██   ██
     ██ ██████ ██     ██        ██    ██   ██ ██     ██   ██ ██   ██
██████  ██     ███████  ██████    ██   ██   ██ ███████ ██   ██ ██████ 
```

**Active Directory attack path framework.**

![version](https://img.shields.io/badge/version-2.1.0-blue)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![platform](https://img.shields.io/badge/platform-linux-lightgrey)

---

## Why this exists

Impacket is forty scripts and no memory. You pull a hash from one terminal, paste it into another, and lose the thread between the fifth and sixth tool. Nothing tells you that the account you just cracked has `GenericAll` over a group that sits two hops from Domain Admin.

SpectreAD is one binary that runs a kill chain and remembers what it learned. Credentials harvested once are reused by every module. ACLs are decoded into a traversable graph. The shortest path to DA is printed as commands you can paste.

It depends on Impacket for the SMB and Kerberos primitives. It owns the orchestration, the credential cache, the attack graph, and the OPSEC gating.

---

## Capabilities

### Reconnaissance

| Command | Does |
|---|---|
| `hosts` | ICMP + TCP sweep across 14 AD service ports, DC identification, reverse DNS |
| `dns` | NetBIOS node status, SRV discovery, zone transfer attempt |
| `ldap` | Users, groups, computers, OUs, GPOs, trusts, policy. LDAPS-first, paged, UAC-decoded |
| `passpol` | Lockout threshold, duration, observation window, password policy |
| `spn` | Every SPN account, machine accounts filtered |
| `smb` | Shares, null session, signing required/not-required, SMBv1, readable shares |

### Credential attacks

| Command | Does |
|---|---|
| `spray` | Lockout-aware spray, batched to `threshold - 1`, per-user counter, jitter |
| `asrep` | AS-REP roast, hashcat 18200 |
| `kerb` | Kerberoast, RC4 and AES separated |
| `ptt` | ccache / kirbi injection |

### Lateral movement

`psexec` · `smbexec` · `wmiexec` · `atexec` · `winrm` · `ssh` · `rdp`

Pass-the-hash by default. All accept `-exec`, `-shell`, `-dry-run`.

### Credential harvest

| Command | Gets |
|---|---|
| `secrets` | SAM + LSA secrets + cached credentials |
| `sam` / `lsa` | Local hashes / service secrets |
| `gpp` | `cpassword` from SYSVOL |
| `dcsync` | DRSUAPI replication, full domain or one account |
| `dpapi` | Masterkeys, Credential Manager, Chrome store |

### Attack paths

| Command | Does |
|---|---|
| `acl` | Enumerates every abusable ACE: `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `AllowedToAct`, `AddKeyCredentialLink` |
| `abuse` | Executes the edge |
| `graph` | Builds the principal graph, DOT export |
| `paths` | Dijkstra from owned principals to DA, each hop as a runnable command |

### ADCS, delegation, relay

| Command | Does |
|---|---|
| `adcs` | ESC1 / ESC2 / ESC3 / ESC6 / ESC8 enumeration |
| `delegation` | Unconstrained, constrained, RBCD reporting |
| `s4u` | S4U2Self + S4U2Proxy |
| `relay` | LLMNR/NBNS poisoning + ntlmrelayx |

### Protocol pack

`mssql` · `vss` · `wmi` · `ipmi` · `exchange` · `sccm`

### Interactive

`ldap-shell` · `smbclient`

### Automation

`auto` runs twelve stages in dependency order:

```
sweep → dns → policy → smb-audit → spray → roast → acl → delegation → adcs → paths → lateral → dcsync
```

Each stage is wrapped — a failure logs and the chain continues. The stop condition is Domain Admin ownership, checked after every stage. `-dry-run` prints the plan, `-yes` skips confirmation, everything is written to `attack_log`.

---

## Install

```bash
git clone https://github.com/<you>/spectread.git
cd spectread
./scripts/install.sh
source .venv/bin/activate
```

Requires Python 3.10+ and, on `PATH`: `hashcat`, `certipy-ad`, `impacket-ntlmrelayx`.

```bash
pipx install certipy-ad
sudo apt install -y hashcat
```

Verify the build:

```bash
./scripts/smoke.sh
```

Must end in `SMOKE PASS`.

---

## Quick start

```bash
# recon
./main.py hosts -targets scope.txt
./main.py ldap -d CORP.LOCAL -u user -p 'pass' -dc-ip 10.0.0.10
./main.py passpol -d CORP.LOCAL -u user -p 'pass' -dc-ip 10.0.0.10

# credentials — policy first, always
./main.py spray -d CORP.LOCAL -dc-ip 10.0.0.10 -passes 2 -delay 0.5 -dry-run
./main.py spray -d CORP.LOCAL -dc-ip 10.0.0.10 -passes 2 -delay 0.5
./main.py kerb -d CORP.LOCAL -dc-ip 10.0.0.10 -u user -p 'pass' -crack -wordlist rockyou.txt

# paths
./main.py acl -d CORP.LOCAL -dc-ip 10.0.0.10 -u user -p 'pass'
./main.py paths -d CORP.LOCAL -dc-ip 10.0.0.10 -u user -p 'pass'

# execute a hop
./main.py abuse -edge GenericAll -source user10 -target HELPDESK \
  -dc-ip 10.0.0.10 -u user10 -p 'pass'

# full domain
./main.py dcsync -d CORP.LOCAL -dc-ip 10.0.0.10 -u Administrator -p 'pass'

# deliverable
./main.py report -report out/report.md -json out/report.json
```

---

## Abuse reference

| Edge | Action |
|---|---|
| `ForceChangePassword` | Sets `unicodePwd` without the old password |
| `AddMember` | Adds a controlled principal |
| `WriteOwner` | Takes ownership via `objectSid` |
| `WriteDACL` | Grants `GenericAll` |
| `GenericAll` on user | Force change, or `-action setspn` for targeted roast, `-action shadowcred` for PKINIT |
| `AllowedToAct` | Writes `msDS-AllowedToActOnBehalfOfOtherIdentity` |

Every one supports `-dry-run`.

---

## State

One SQLite file per engagement, `chmod 600` on create.

| Table | Holds |
|---|---|
| `creds` | Credential cache with validity flag |
| `aces` | Abusable edges |
| `owned` | Compromised principals, feeds `paths` |
| `findings` | Severity, evidence, host, credential, timestamp |
| `attack_log` | Every action, for SIEM correlation |
| `masterkeys`, `dpapi_secrets`, `machines` | v2.1 additions |

`-json`, `-report`, `-graph`, `-o` control artifacts.

---

## Versus Impacket

| Dimension | Impacket | SpectreAD |
|---|---|---|
| State | None, manual hash juggling | Credential cache, reused across modules |
| Lockout safety | Policy-unaware | Reads threshold and observation window first |
| Attack paths | Separate tool | Built-in graph, runnable chains |
| ACL abuse | Manual descriptor parsing | Enumerated and executable |
| Consistency | Forty flag sets | One auth block, `-dry-run` everywhere |
| Chaining | Manual | `auto`, twelve stages |
| Protocol breadth | Wider | SMB, Kerberos, LDAP, MSSQL, WMI |

Impacket is better for a single one-off action and for anything interactive with its own shells. SpectreAD is better when you need the picture rather than the action.

---

## Design principles

- **Refuse to spray blind.** No cached policy, no spray.
- **Credentials once.** Harvested material is reused, not re-typed.
- **Least AV surface.** `auto` picks smbexec before psexec.
- **Everything logged.** Every state change carries a credential and a timestamp.
- **Dry-run by default in the dangerous paths.**

---

## Lab

`labs/Vagrantfile` and `labs/populate.ps1` build a single-DC lab with planted `GenericAll`, `WriteDACL`, `WriteOwner`, SPN accounts, an AS-REP-roastable account, a GPP `cpassword`, and a bounded lockout threshold.

For breadth, GOAD provides two forests with delegation and ESC cases.

---

## Limitations

- No EDR evasion, no beaconing, no in-memory execution
- Relay orchestrates `ntlmrelayx` rather than implementing its own engine
- Shadow credentials and certificate issuance delegate to `certipy-ad`
- One domain per run, no forest traversal
- No IPv6 poisoning
- RC4 Kerberoast needs RC4 enabled on the account

See `LIMITATIONS.md`.

---

## Author

**Inayat Hussain** — Senior Red Team Operator & Penetration Tester

---

## License

MIT. See `LICENSE`.

---

## Disclaimer

For authorised testing only. Use against systems you own or have written permission to assess. A spray against a production domain without reading its lockout policy first will lock out accounts.
