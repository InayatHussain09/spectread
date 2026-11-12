<div align="center">

<h1>SpectreAD</h1>

<p><strong>Active Directory Attack Path Framework</strong></p>

<p>RECONNAISSANCE · CREDENTIAL ACCESS · ACL ABUSE · ATTACK PATHS · DCSYNC</p>

<p>
  <img src="https://img.shields.io/badge/version-2.1.0-blue" alt="version" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="python" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license" />
  <img src="https://img.shields.io/badge/platform-linux-lightgrey" alt="platform" />
</p>

<p><strong>Developed by Inayat Hussain</strong><br />
Senior Red Team Operator | Penetration Tester</p>

</div>

---

## Overview

SpectreAD is a Python-based adversary simulation framework for Active Directory environments. It performs reconnaissance, credential attacks, ACL abuse, attack-path analysis and domain replication inside a single command-line workflow, against a single shared state file.

Impacket is a library of forty disconnected scripts. The operator carries the hash between them by hand and keeps the graph in a spreadsheet. SpectreAD is one binary that runs a chain, caches what it harvests, decodes every abusable ACE into a traversable graph, and prints the shortest path to Domain Admin as commands that can be executed directly.

It depends on Impacket for the SMB and Kerberos primitives. It owns the orchestration, the credential cache, the attack graph and the OPSEC gating.

## Core Capability Classes

| Class | Focus |
|---|---|
| Reconnaissance | Host sweep, NetBIOS, SRV discovery, LDAP object enumeration, policy read, signing audit |
| Credential Access | Lockout-aware spraying, AS-REP roasting, Kerberoasting, GPP `cpassword`, DPAPI masterkeys |
| ACL Abuse | Full ACE enumeration and execution across eight edge types |
| Attack Paths | Graph construction and shortest-path resolution to Domain Admin |
| Domain Replication | DRSUAPI replication, whole domain or a single account |
| Lateral Movement | Five transports over pass-the-hash, least AV surface first |
| ADCS | ESC1 / ESC2 / ESC3 / ESC6 / ESC8 enumeration |
| Relay | LLMNR and NBNS poisoning driving NTLM relay |

Every capability is individually invocable and independently `-dry-run` capable.

## Attack Path Model

ACLs are decoded from `nTSecurityDescriptor` on every user, group, computer, OU and domain object. Access masks and extended-right GUIDs are mapped to named edges, weighted by cost, and loaded into a directed graph.

| Edge | Execution |
|---|---|
| `ForceChangePassword` | Sets `unicodePwd` without the prior password |
| `AddMember` | Adds a controlled principal to the group |
| `WriteOwner` | Takes ownership via `objectSid` |
| `WriteDACL` | Writes a DACL granting `GenericAll` |
| `GenericAll` on user | Force change, targeted Kerberoast, or shadow credentials |
| `AllowedToAct` | Writes `msDS-AllowedToActOnBehalfOfOtherIdentity` |

`paths` resolves each hop with Dijkstra and emits the exact `abuse` invocation for it.

## Command Reference

**Reconnaissance**

```
hosts       ICMP + TCP sweep across 14 AD service ports
dns         NetBIOS node status, SRV discovery, zone transfer
ldap        users, groups, computers, OUs, GPOs, trusts, policy
passpol     lockout threshold, duration, observation window
spn         SPN account enumeration
smb         shares, null session, signing audit, SMBv1
```

**Credential Access**

```
spray       lockout-aware password spraying
asrep       AS-REP roast, hashcat 18200
kerb        Kerberoast, RC4 and AES separated
ptt         ccache / kirbi injection
gpp         SYSVOL cpassword extraction
dpapi       masterkeys, Credential Manager, Chrome store
```

**Attack Paths**

```
acl         abusable ACE enumeration
abuse       edge execution
graph       principal graph, DOT export
paths       shortest path to Domain Admin
```

**Domain and Lateral**

```
dcsync      DRSUAPI replication
secrets     SAM + LSA + cached credentials
sam         local account hashes
lsa         LSA secrets
psexec      SMB service execution
smbexec     SMB, no binary drop
wmiexec     WMI semi-interactive
atexec      Task Scheduler execution
winrm       WinRM / PSRP
```

**ADCS, Delegation, Relay**

```
adcs        ESC1 / ESC2 / ESC3 / ESC6 / ESC8
delegation  unconstrained, constrained, RBCD
s4u         S4U2Self + S4U2Proxy
relay       LLMNR/NBNS poisoning + ntlmrelayx
```

**Protocols and Interactive**

```
mssql  vss  wmi  ipmi  exchange  sccm
ldap-shell  smbclient
```

**Orchestration**

```
auto        twelve-stage kill chain
report      markdown and JSON deliverables
```

## Automation

`auto` sequences the full engagement in dependency order:

```
sweep → dns → policy → smb-audit → spray → roast → acl → delegation → adcs → paths → lateral → dcsync
```

Each stage is isolated — a failure logs and the chain continues. The stop condition is Domain Admin ownership, re-evaluated after every stage. The full run is written to the attack log with the credential used at each step.

## Installation

```bash
git clone https://github.com/InayatHussain09/spectread.git
cd spectread
./scripts/install.sh
source .venv/bin/activate
```

Python 3.10 or later. On `PATH`: `hashcat`, `certipy-ad`, `impacket-ntlmrelayx`.

```bash
pipx install certipy-ad
sudo apt install -y hashcat
```

Validate the build:

```bash
./scripts/smoke.sh
```

## Usage

```bash
# reconnaissance
./main.py hosts -targets scope.txt
./main.py ldap -d CORP.LOCAL -u user -p 'pass' -dc-ip 10.0.0.10
./main.py passpol -d CORP.LOCAL -u user -p 'pass' -dc-ip 10.0.0.10

# credential access — policy first, always
./main.py spray -d CORP.LOCAL -dc-ip 10.0.0.10 -passes 2 -delay 0.5 -dry-run
./main.py kerb -d CORP.LOCAL -dc-ip 10.0.0.10 -u user -p 'pass' -crack -wordlist rockyou.txt

# path resolution
./main.py acl -d CORP.LOCAL -dc-ip 10.0.0.10 -u user -p 'pass'
./main.py paths -d CORP.LOCAL -dc-ip 10.0.0.10 -u user -p 'pass'

# edge execution
./main.py abuse -edge GenericAll -source user10 -target HELPDESK -dc-ip 10.0.0.10 -u user10 -p 'pass'

# domain replication
./main.py dcsync -d CORP.LOCAL -dc-ip 10.0.0.10 -u Administrator -p 'pass'

# deliverables
./main.py report -report out/report.md -json out/report.json
```

## State

One SQLite file per engagement, permissions `0600` at creation.

| Table | Contents |
|---|---|
| `creds` | Credential cache with validity flag |
| `aces` | Abusable edges |
| `owned` | Compromised principals, feeds `paths` |
| `findings` | Severity, evidence, host, credential, timestamp |
| `attack_log` | Every action, for SIEM correlation |
| `masterkeys` `dpapi_secrets` `machines` | 2.1 additions |

## Lab

`labs/Vagrantfile` and `labs/populate.ps1` build a single-domain environment with planted `GenericAll`, `WriteDACL` and `WriteOwner` chains, two SPN accounts, an AS-REP-roastable account, a SYSVOL `cpassword` and a bounded lockout threshold.

For multi-domain breadth, GOAD provides two forests with delegation and ESC misconfigurations.

## Design Principles

- **No blind spraying.** No cached policy, no spray.
- **Credential once.** Harvested material is reused, never retyped.
- **Least AV surface.** `auto` prefers smbexec over psexec.
- **Everything logged.** Every state change carries a credential and a timestamp.
- **Dry-run on destructive paths.**

## Limitations

- No EDR evasion, beaconing, or in-memory execution
- Relay orchestrates `ntlmrelayx` rather than implementing an engine
- Shadow credentials and certificate issuance delegate to `certipy-ad`
- Single domain per run, no forest traversal
- No IPv6 poisoning

See `LIMITATIONS.md`.

## Author

**Inayat Hussain**
Senior Red Team Operator | Penetration Tester

## License

MIT. See `LICENSE`.

## Disclaimer

For authorised testing only. A spray against a production domain without reading its lockout policy first will lock accounts.
