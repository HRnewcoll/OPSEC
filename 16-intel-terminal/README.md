# 16 — OPSEC Intelligence Terminal

A **Palantir-inspired** command-line intelligence analysis platform for open-source threat intelligence, entity relationship tracking, and structured case management.

---

## Overview

The OPSEC Intel Terminal brings together all modules into a single analyst-facing interface. It models how platforms like **Palantir Gotham** and **Maltego** work — collecting intelligence on entities (IPs, domains, persons, emails), linking them in an entity graph, and producing structured reports — but runs entirely from your terminal with zero cloud dependency.

```
  ██████╗ ██████╗ ███████╗███████╗ ██████╗    ██╗███╗   ██╗████████╗███████╗██╗
 ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝    ██║████╗  ██║╚══██╔══╝██╔════╝██║
 ██║   ██║██████╔╝███████╗█████╗  ██║         ██║██╔██╗ ██║   ██║   █████╗  ██║
 ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║         ██║██║╚██╗██║   ██║   ██╔══╝  ██║
 ╚██████╔╝██║     ███████║███████╗╚██████╗    ██║██║ ╚████║   ██║   ███████╗███████╗
  ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-source OSINT** | IP geo/ASN/Shodan, domain RDAP/DNS/crt.sh, email MX/Gravatar/HIBP, username 19 platforms |
| **Entity graph** | Automatically links IPs ↔ domains ↔ emails ↔ usernames with relationship types |
| **Case management** | Create cases, assign entities, add analyst notes, close cases |
| **Intelligence timeline** | Chronological log of every query, scoped per case |
| **Live threat feeds** | CVEs from CIRCL, OTX pulses from AlienVault, security news from HN |
| **Report generation** | Markdown or JSON reports with entity tables, graph edges, timeline |
| **Interactive TUI** | Command prompt with case-scoped state, ANSI colour, auto-complete hints |
| **Persistent storage** | All data stored in `~/.opsec/intel/` as plain JSON (easy to grep/backup) |
| **Zero dependencies** | Runs with Python 3.10+ stdlib only |

---

## Quick Start

```bash
# Launch interactive terminal
python intel_terminal.py

# Or use CLI mode directly
python intel_terminal.py query ip 8.8.8.8
python intel_terminal.py query domain google.com
python intel_terminal.py feeds cve
```

---

## Interactive TUI Commands

```
intel> help

COMMANDS
  query ip <address>            IP geolocation, ASN, Shodan exposure
  query domain <domain>         DNS, RDAP, subdomains, threat intel
  query email <email>           MX, Gravatar, breach links
  query username <name>         Username presence across 19 platforms
  graph                         Show entity relationship graph
  graph --case <name>           Show graph filtered to a case
  timeline                      Show intelligence event timeline
  feeds cve                     Latest CVEs from CIRCL
  feeds otx                     AlienVault OTX threat pulses
  feeds news                    Security news from Hacker News
  case new <name>               Create a new case
  case list                     List all cases
  case note <name> <text>       Add note to a case
  case close <name>             Close a case
  case use <name>               Set active case (queries auto-tagged)
  report --case <name>          Generate Markdown intelligence report
  report --case <name> --json   Generate JSON report
  report --out report.md        Save report to file
  status                        Show entity/event/case counts
  help                          Show this help
  exit / q                      Exit terminal
```

---

## Example Session

```
intel> case new "Operation RedTeam"
  [+] Case created: Operation RedTeam
  [+] Active case set to: Operation RedTeam

[Operation RedTeam] intel> query ip 185.220.101.1
[*] IP Intelligence: 185.220.101.1
  Location : Frankfurt, Hesse, Germany
  ISP      : Frantech Solutions
  ASN      : AS53667 FranTech Solutions
  Ports    : 80, 443, 9001, 9030
  [+] Entity added to graph (ID: a3b1c9e2f4d8)

[Operation RedTeam] intel> query domain suspicious-domain.xyz
[*] Domain Intelligence: suspicious-domain.xyz
  A records : 104.21.45.67
  Registered: 2024-01-15
  Subdomains: 3 found via crt.sh
  [+] Entity added to graph (ID: 8f2a1d3e7c6b)

[Operation RedTeam] intel> graph
  Entity Graph (3 nodes, 2 edges)
  ─────────────────────────────────────────────────────
  🌐 185.220.101.1         ip               a3b1c9e2f4d8
  🌐 104.21.45.67          ip               b9d4e2f1a7c3
  🔗 suspicious-domain.xyz domain           8f2a1d3e7c6b

  Relationships:
    suspicious-domain.xyz ──[resolves_to]──▶ 104.21.45.67

[Operation RedTeam] intel> feeds cve
[*] Fetching recent CVEs …
  CVE-2024-1234             CVSS 9.8  Remote code execution in ...
  CVE-2024-1235             CVSS 7.5  SQL injection in ...

[Operation RedTeam] intel> report --out redteam_report.md
[+] Report → redteam_report.md
```

---

## Data Storage

All data is stored locally at `~/.opsec/intel/`:

| File | Contents |
|------|----------|
| `cases.json` | Case metadata, notes, status |
| `entity_graph.json` | Nodes (entities) and edges (relationships) |
| `timeline.json` | Chronological event log |
| `feeds_cache.json` | Cached feed responses |

---

## Integrations

The intel terminal integrates with other OPSEC toolkit modules:

```bash
# Run a network scan and feed results to the terminal
python ../13-network-scanner/network_scanner.py scan --target 10.0.0.0/24 --out scan.json
python intel_terminal.py query ip 10.0.0.1

# Check a hash IOC
python ../10-hash-tools/hash_tools.py identify --hash <hash>

# OSINT deep-dive
python ../09-osint-tools/osint.py report --target suspicious-domain.xyz --out osint.json
```

---

## Privacy & Security
- All data stored **locally** — no cloud, no telemetry
- Queries use passive/public APIs — no active probing unless you run a scan
- HIBP breach check uses k-anonymity (only first 5 chars of SHA-1 sent)
- Store your intel directory on an encrypted volume (see module 12)
