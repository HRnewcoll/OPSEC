#!/usr/bin/env python3
"""
OPSEC Intelligence Terminal
=============================
A Palantir-inspired command-line intelligence analysis platform.

Features:
  - Dark terminal TUI with multi-pane layout (rich library)
  - Live threat feeds from public sources (CVE, CIRCL, AlienVault OTX)
  - Entity graph: link targets, IPs, domains, persons
  - Integrated OSINT queries (IP, domain, username, email)
  - Network scan integration (calls network_scanner module)
  - Hash/IOC lookup  (calls hash_tools module)
  - Timeline of collected intel events
  - Case management: create cases, tag entities, attach notes
  - Export intelligence reports (JSON, Markdown)
  - All data stored locally in ~/.opsec/intel/

Usage:
  python intel_terminal.py                   # Interactive TUI
  python intel_terminal.py --mode cli        # CLI mode
  python intel_terminal.py query ip 8.8.8.8
  python intel_terminal.py query domain github.com
  python intel_terminal.py query username johndoe
  python intel_terminal.py feeds
  python intel_terminal.py case new "Operation RedTeam"
  python intel_terminal.py case list
  python intel_terminal.py report --case "Operation RedTeam" --out report.md
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import threading
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── storage paths ─────────────────────────────────────────────────────
INTEL_DIR   = Path("~/.opsec/intel").expanduser()
CASES_FILE  = INTEL_DIR / "cases.json"
GRAPH_FILE  = INTEL_DIR / "entity_graph.json"
EVENTS_FILE = INTEL_DIR / "timeline.json"
FEEDS_CACHE = INTEL_DIR / "feeds_cache.json"

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

# ── colour palette (ANSI) ─────────────────────────────────────────────
C = {
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
    "red":      "\033[91m",
    "green":    "\033[92m",
    "yellow":   "\033[93m",
    "blue":     "\033[94m",
    "magenta":  "\033[95m",
    "cyan":     "\033[96m",
    "white":    "\033[97m",
    "bg_black": "\033[40m",
    "bg_blue":  "\033[44m",
}

def _c(colour: str, text: str) -> str:
    if not _use_colour():
        return text
    return C.get(colour, "") + text + C["reset"]


def _use_colour() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


# ── HTTP helpers ──────────────────────────────────────────────────────

def http_get(url: str, timeout: int = 10, headers: dict = None) -> Optional[str]:
    try:
        h = {"User-Agent": USER_AGENT}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def http_get_json(url: str, timeout: int = 10, headers: dict = None) -> Optional[dict]:
    data = http_get(url, timeout, headers)
    if data:
        try:
            return json.loads(data)
        except Exception:
            return None
    return None


# ── local storage ─────────────────────────────────────────────────────

def _ensure_dirs():
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    for f in [CASES_FILE, GRAPH_FILE, EVENTS_FILE, FEEDS_CACHE]:
        if not f.exists():
            f.write_text("{}")


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, default=str))


def _log_event(event_type: str, target: str, data: dict, case: str = None):
    events = _load(EVENTS_FILE)
    events.setdefault("events", [])
    entry = {
        "id":        len(events["events"]) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      event_type,
        "target":    target,
        "case":      case,
        "data":      data,
    }
    events["events"].append(entry)
    _save(EVENTS_FILE, events)


# ── entity graph ──────────────────────────────────────────────────────

def graph_add_entity(entity_type: str, value: str,
                     metadata: dict = None, case: str = None) -> str:
    graph = _load(GRAPH_FILE)
    graph.setdefault("entities", {})
    graph.setdefault("edges", [])

    eid = hashlib.sha256(f"{entity_type}:{value}".encode()).hexdigest()[:12]
    if eid not in graph["entities"]:
        graph["entities"][eid] = {
            "id":        eid,
            "type":      entity_type,
            "value":     value,
            "cases":     [],
            "metadata":  metadata or {},
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen":  datetime.now(timezone.utc).isoformat(),
            "tags":      [],
        }
    else:
        graph["entities"][eid]["last_seen"] = datetime.now(timezone.utc).isoformat()
        if metadata:
            graph["entities"][eid]["metadata"].update(metadata)

    if case and case not in graph["entities"][eid]["cases"]:
        graph["entities"][eid]["cases"].append(case)

    _save(GRAPH_FILE, graph)
    return eid


def graph_link(eid1: str, eid2: str, relationship: str, case: str = None):
    graph = _load(GRAPH_FILE)
    graph.setdefault("edges", [])
    edge = {"from": eid1, "to": eid2, "rel": relationship,
            "case": case, "ts": datetime.now(timezone.utc).isoformat()}
    # avoid duplicates
    for e in graph["edges"]:
        if e["from"] == eid1 and e["to"] == eid2 and e["rel"] == relationship:
            return
    graph["edges"].append(edge)
    _save(GRAPH_FILE, graph)


def graph_show(case: str = None):
    graph = _load(GRAPH_FILE)
    entities = graph.get("entities", {})
    edges    = graph.get("edges", [])

    if case:
        entities = {k: v for k, v in entities.items() if case in v.get("cases", [])}
        eids = set(entities.keys())
        edges = [e for e in edges if e["from"] in eids or e["to"] in eids]

    print(_c("cyan", f"\n  Entity Graph ({len(entities)} nodes, {len(edges)} edges)"))
    print("  " + "─" * 60)

    for eid, e in sorted(entities.items(), key=lambda x: x[1]["type"]):
        icon = _entity_icon(e["type"])
        print(f"  {icon} {_c('yellow', e['value']):<35} "
              f"{_c('dim', e['type']):<15} {_c('dim', eid)}")

    if edges:
        print(_c("cyan", "\n  Relationships:"))
        for edge in edges:
            src = entities.get(edge["from"], {}).get("value", edge["from"])
            dst = entities.get(edge["to"],   {}).get("value", edge["to"])
            print(f"    {_c('white', src)} ──[{_c('magenta', edge['rel'])}]──▶ {_c('white', dst)}")


def _entity_icon(entity_type: str) -> str:
    icons = {
        "ip":       "🌐",
        "domain":   "🔗",
        "email":    "✉️ ",
        "username": "👤",
        "hash":     "#️⃣ ",
        "url":      "🔗",
        "person":   "🧑",
        "org":      "🏢",
        "phone":    "📞",
        "file":     "📄",
        "malware":  "☣️ ",
        "cve":      "⚠️ ",
    }
    return icons.get(entity_type.lower(), "●")


# ── IP intelligence ───────────────────────────────────────────────────

def query_ip(ip: str, case: str = None) -> dict:
    print(_c("blue", f"\n[*] IP Intelligence: {ip}"))
    result = {"ip": ip, "timestamp": datetime.now().isoformat()}

    # Validate
    try:
        addr = ipaddress.ip_address(ip)
        result["version"] = addr.version
        result["private"] = addr.is_private
    except ValueError:
        result["error"] = "Invalid IP"
        return result

    # Hostname
    try:
        result["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result["hostname"] = None

    # Geolocation (ip-api.com)
    geo = http_get_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query")
    if geo and geo.get("status") == "success":
        result["geo"] = geo
        print(f"  Location : {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}")
        print(f"  ISP      : {geo.get('isp')}")
        print(f"  ASN      : {geo.get('as')}")

    # Shodan internetdb (free)
    shodan = http_get_json(f"https://internetdb.shodan.io/{ip}")
    if shodan:
        result["shodan"] = shodan
        ports = shodan.get("ports", [])
        vulns = shodan.get("vulns", [])
        if ports:
            print(f"  Ports    : {', '.join(str(p) for p in ports[:20])}")
        if vulns:
            print(_c("red", f"  Vulns    : {', '.join(vulns[:10])}"))

    # AbuseIPDB via internet (requires key, show link only)
    result["abuse_check"] = f"https://www.abuseipdb.com/check/{ip}"
    result["virustotal"]  = f"https://www.virustotal.com/gui/ip-address/{ip}"

    # Add to graph
    eid = graph_add_entity("ip", ip, result, case)
    if result.get("hostname"):
        deid = graph_add_entity("domain", result["hostname"], {}, case)
        graph_link(eid, deid, "resolves_to", case)
    if geo and geo.get("org"):
        oeid = graph_add_entity("org", geo["org"], {}, case)
        graph_link(eid, oeid, "owned_by", case)

    _log_event("ip_lookup", ip, result, case)
    print(_c("green", f"  [+] Entity added to graph (ID: {eid})"))
    return result


# ── domain intelligence ───────────────────────────────────────────────

def query_domain(domain: str, case: str = None) -> dict:
    print(_c("blue", f"\n[*] Domain Intelligence: {domain}"))
    result = {"domain": domain, "timestamp": datetime.now().isoformat()}

    # DNS A records
    try:
        ips = [r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)]
        result["a_records"] = list(set(ips))
        print(f"  A records : {', '.join(result['a_records'][:5])}")
    except Exception:
        result["a_records"] = []

    # RDAP
    rdap = http_get_json(f"https://rdap.org/domain/{domain}")
    if rdap:
        result["rdap"] = rdap
        events = rdap.get("events", [])
        for ev in events:
            if ev.get("eventAction") == "registration":
                result["registered"] = ev.get("eventDate")
                print(f"  Registered: {result['registered']}")

    # Certificate Transparency (crt.sh)
    crt_url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    crt_data = http_get_json(crt_url)
    if crt_data and isinstance(crt_data, list):
        subdomains = set()
        for cert in crt_data[:100]:
            name = cert.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub.endswith(domain):
                    subdomains.add(sub)
        result["subdomains"] = sorted(subdomains)[:50]
        print(f"  Subdomains: {len(result['subdomains'])} found via crt.sh")

    # VirusTotal / threat intel links
    result["virustotal"]  = f"https://www.virustotal.com/gui/domain/{domain}"
    result["urlscan"]     = f"https://urlscan.io/search/#{urllib.parse.quote(domain)}"
    result["shodan_query"]= f"https://www.shodan.io/search?query=hostname%3A{domain}"

    # Add to graph
    eid = graph_add_entity("domain", domain, result, case)
    for ip in result.get("a_records", []):
        ieid = graph_add_entity("ip", ip, {}, case)
        graph_link(eid, ieid, "resolves_to", case)

    _log_event("domain_lookup", domain, result, case)
    print(_c("green", f"  [+] Entity added to graph (ID: {eid})"))
    return result


# ── email intelligence ────────────────────────────────────────────────

def query_email(email: str, case: str = None) -> dict:
    print(_c("blue", f"\n[*] Email Intelligence: {email}"))
    result = {"email": email, "timestamp": datetime.now().isoformat()}

    if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        result["error"] = "Invalid email"
        return result

    local, domain = email.split("@", 1)
    result["local"]  = local
    result["domain"] = domain

    # Gravatar
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    result["gravatar"] = f"https://www.gravatar.com/avatar/{md5}"
    print(f"  Gravatar : {result['gravatar']}")

    # Breach check links (HIBP requires API key for v3)
    result["hibp_link"]    = f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"
    result["breach_links"] = [
        f"https://breachdirectory.org/?q={urllib.parse.quote(email)}",
        f"https://leakcheck.io/email/{urllib.parse.quote(email)}",
    ]
    print(f"  HIBP     : {result['hibp_link']}")

    # MX records
    try:
        import subprocess
        r = subprocess.run(["dig", "+short", "MX", domain],
                           capture_output=True, text=True, timeout=5)
        result["mx"] = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        result["mx"] = []
    if result["mx"]:
        print(f"  MX       : {', '.join(result['mx'][:3])}")

    # Add to graph
    eid  = graph_add_entity("email", email, result, case)
    deid = graph_add_entity("domain", domain, {}, case)
    graph_link(eid, deid, "belongs_to", case)

    _log_event("email_lookup", email, result, case)
    print(_c("green", f"  [+] Entity added to graph (ID: {eid})"))
    return result


# ── username intelligence ─────────────────────────────────────────────

PLATFORMS = [
    ("GitHub",     "https://github.com/{}"),
    ("GitLab",     "https://gitlab.com/{}"),
    ("Twitter/X",  "https://x.com/{}"),
    ("Instagram",  "https://www.instagram.com/{}"),
    ("Reddit",     "https://www.reddit.com/user/{}"),
    ("TikTok",     "https://www.tiktok.com/@{}"),
    ("YouTube",    "https://www.youtube.com/@{}"),
    ("Twitch",     "https://www.twitch.tv/{}"),
    ("Steam",      "https://steamcommunity.com/id/{}"),
    ("Medium",     "https://medium.com/@{}"),
    ("Mastodon",   "https://mastodon.social/@{}"),
    ("Telegram",   "https://t.me/{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("Keybase",    "https://keybase.io/{}"),
    ("DockerHub",  "https://hub.docker.com/u/{}"),
    ("PyPI",       "https://pypi.org/user/{}"),
    ("NPM",        "https://www.npmjs.com/~{}"),
    ("Pastebin",   "https://pastebin.com/u/{}"),
    ("Dev.to",     "https://dev.to/{}"),
]


def query_username(username: str, case: str = None) -> dict:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    print(_c("blue", f"\n[*] Username Intelligence: {username}"))
    print(f"    Checking {len(PLATFORMS)} platforms …")
    result = {"username": username, "found": [], "timestamp": datetime.now().isoformat()}

    def _check(platform, url_tpl):
        url = url_tpl.format(username)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=8) as resp:
                found = resp.getcode() == 200
        except urllib.error.HTTPError as e:
            found = e.code not in (404, 410)
        except Exception:
            found = None
        return {"platform": platform, "url": url, "found": found}

    found_list = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_check, p, u): p for p, u in PLATFORMS}
        for fut in as_completed(futures):
            r = fut.result()
            if r["found"] is True:
                found_list.append(r)
                print(f"  {_c('green','✓')} {r['platform']:<20} {r['url']}")

    result["found"] = found_list
    print(f"\n  Found on {len(found_list)}/{len(PLATFORMS)} platforms")

    # Add to graph
    eid = graph_add_entity("username", username, result, case)
    for entry in found_list:
        peid = graph_add_entity("url", entry["url"], {"platform": entry["platform"]}, case)
        graph_link(eid, peid, "profile_on", case)

    _log_event("username_lookup", username, result, case)
    return result


# ── CVE / threat feeds ────────────────────────────────────────────────

def fetch_cve_feed(limit: int = 10) -> list[dict]:
    """Fetch recent CVEs from NVD/CIRCL."""
    print(_c("blue", "\n[*] Fetching recent CVEs …"))
    url = "https://cve.circl.lu/api/last"
    data = http_get_json(url, timeout=15)
    if not data or not isinstance(data, list):
        print("  [!] Could not reach CIRCL CVE feed")
        return []
    items = data[:limit]
    for cve in items:
        cveid   = cve.get("id") or cve.get("cve", {}).get("CVE_data_meta", {}).get("ID", "?")
        summary = (cve.get("summary") or "")[:80]
        cvss    = cve.get("cvss") or cve.get("cvss3", "?")
        refs    = cve.get("references", [])
        colour  = "red" if isinstance(cvss, (int, float)) and float(cvss) >= 7.0 else "yellow"
        print(f"  {_c(colour, cveid):<25} CVSS {str(cvss):<5} {summary}")
    return items


def fetch_otx_pulses(limit: int = 5) -> list[dict]:
    """Fetch latest AlienVault OTX public pulses."""
    print(_c("blue", "\n[*] Fetching AlienVault OTX threat pulses …"))
    url = "https://otx.alienvault.com/api/v1/pulses/activity?limit=" + str(limit)
    data = http_get_json(url, timeout=15)
    if not data:
        print("  [!] Could not reach OTX feed (may require free API key)")
        return []
    pulses = data.get("results", [])
    for p in pulses:
        name   = p.get("name", "?")[:60]
        iocs   = p.get("indicator_count", 0)
        author = p.get("author_name", "?")
        tags   = ", ".join(p.get("tags", [])[:5])
        print(f"  {_c('cyan', name)}")
        print(f"      Author: {author}  IOCs: {iocs}  Tags: {tags}")
    return pulses


def fetch_news_feed() -> list[dict]:
    """Fetch security news from hacker news (RSS-free)."""
    print(_c("blue", "\n[*] Fetching security news from HN (Ask Security) …"))
    url = "https://hacker-news.firebaseio.com/v0/topstories.json"
    ids = http_get_json(url, timeout=10)
    if not ids:
        return []
    items = []
    for story_id in ids[:30]:
        item = http_get_json(f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json", timeout=5)
        if item and item.get("type") == "story":
            title = item.get("title", "")
            if any(kw in title.lower() for kw in
                   ["security", "hack", "breach", "vuln", "exploit", "ransomware",
                    "malware", "zero-day", "cve", "phish", "cyber"]):
                items.append(item)
                if len(items) >= 8:
                    break
    for item in items:
        score = item.get("score", 0)
        title = item.get("title", "")[:70]
        url   = item.get("url", "https://news.ycombinator.com/item?id=" + str(item.get("id")))
        print(f"  {_c('green', str(score)):>6} pts  {title}")
        print(f"          {_c('dim', url)}")
    return items


# ── case management ───────────────────────────────────────────────────

def case_new(name: str, description: str = "") -> dict:
    cases = _load(CASES_FILE)
    cases.setdefault("cases", {})
    if name in cases["cases"]:
        print(f"[!] Case '{name}' already exists"); return cases["cases"][name]
    cases["cases"][name] = {
        "name":        name,
        "description": description,
        "created":     datetime.now(timezone.utc).isoformat(),
        "modified":    datetime.now(timezone.utc).isoformat(),
        "status":      "open",
        "notes":       [],
        "tags":        [],
    }
    _save(CASES_FILE, cases)
    print(_c("green", f"[+] Case created: {name}"))
    return cases["cases"][name]


def case_list():
    cases = _load(CASES_FILE).get("cases", {})
    if not cases:
        print("  No cases yet. Create one: intel_terminal.py case new <name>")
        return
    print(_c("cyan", f"\n  {'Case Name':<35} {'Status':<10} {'Created'}"))
    print("  " + "─" * 70)
    for name, c in sorted(cases.items()):
        status_col = "green" if c["status"] == "open" else "dim"
        ts = c["created"][:10]
        print(f"  {_c('yellow', name):<44} {_c(status_col, c['status']):<19} {ts}")
    print(f"\n  Total: {len(cases)} case(s)")


def case_add_note(name: str, note: str):
    cases = _load(CASES_FILE)
    if name not in cases.get("cases", {}):
        print(f"[!] Case not found: {name}"); return
    cases["cases"][name]["notes"].append({
        "ts": datetime.now(timezone.utc).isoformat(), "text": note
    })
    cases["cases"][name]["modified"] = datetime.now(timezone.utc).isoformat()
    _save(CASES_FILE, cases)
    print(f"[+] Note added to case: {name}")


def case_close(name: str):
    cases = _load(CASES_FILE)
    if name not in cases.get("cases", {}):
        print(f"[!] Case not found: {name}"); return
    cases["cases"][name]["status"]   = "closed"
    cases["cases"][name]["modified"] = datetime.now(timezone.utc).isoformat()
    _save(CASES_FILE, cases)
    print(f"[+] Case closed: {name}")


# ── timeline ──────────────────────────────────────────────────────────

def show_timeline(case: str = None, limit: int = 20):
    events = _load(EVENTS_FILE).get("events", [])
    if case:
        events = [e for e in events if e.get("case") == case]
    events = events[-limit:][::-1]

    print(_c("cyan", f"\n  Intelligence Timeline ({len(events)} events)"))
    print("  " + "─" * 70)
    type_colours = {
        "ip_lookup":       "blue",
        "domain_lookup":   "cyan",
        "email_lookup":    "magenta",
        "username_lookup": "yellow",
        "scan":            "red",
        "hash_lookup":     "dim",
    }
    for ev in events:
        ts    = ev["timestamp"][:19].replace("T", " ")
        etype = ev["type"]
        col   = type_colours.get(etype, "white")
        case_label = f"[{ev['case']}]" if ev.get("case") else ""
        print(f"  {_c('dim', ts)}  {_c(col, etype):<30} "
              f"{_c('white', ev['target']):<30} {_c('dim', case_label)}")


# ── report generation ─────────────────────────────────────────────────

def generate_report(case_name: str = None, out_path: Path = None,
                    fmt: str = "markdown") -> str:
    cases   = _load(CASES_FILE).get("cases", {})
    graph   = _load(GRAPH_FILE)
    events  = _load(EVENTS_FILE).get("events", [])

    if case_name and case_name not in cases:
        print(f"[!] Case not found: {case_name}"); return ""

    case = cases.get(case_name, {}) if case_name else {}
    entities = graph.get("entities", {})
    edges    = graph.get("edges", [])

    if case_name:
        entities = {k: v for k, v in entities.items()
                    if case_name in v.get("cases", [])}
        eids   = set(entities.keys())
        edges  = [e for e in edges if e.get("from") in eids or e.get("to") in eids]
        events = [e for e in events if e.get("case") == case_name]

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    title = f"OPSEC Intelligence Report — {case_name or 'All Cases'}"

    if fmt == "markdown":
        lines = [
            f"# {title}",
            f"**Generated:** {now}",
            "",
        ]
        if case:
            lines += [
                f"## Case Overview",
                f"- **Name:** {case.get('name')}",
                f"- **Status:** {case.get('status')}",
                f"- **Created:** {case.get('created', '')[:10]}",
                f"- **Description:** {case.get('description', 'N/A')}",
                "",
            ]
            if case.get("notes"):
                lines.append("### Case Notes")
                for note in case["notes"]:
                    lines.append(f"- `{note['ts'][:10]}` {note['text']}")
                lines.append("")

        if entities:
            lines.append(f"## Entities ({len(entities)})")
            by_type: dict = {}
            for e in entities.values():
                by_type.setdefault(e["type"], []).append(e)
            for etype, elist in sorted(by_type.items()):
                lines.append(f"\n### {etype.title()} ({len(elist)})")
                lines.append("| Value | First Seen | Tags |")
                lines.append("|-------|------------|------|")
                for e in elist:
                    fs = e.get("first_seen", "")[:10]
                    tags = ", ".join(e.get("tags", []))
                    lines.append(f"| `{e['value']}` | {fs} | {tags} |")

        if edges:
            lines.append(f"\n## Relationships ({len(edges)})")
            for edge in edges:
                src = entities.get(edge["from"], {}).get("value", edge["from"])
                dst = entities.get(edge["to"],   {}).get("value", edge["to"])
                lines.append(f"- `{src}` **{edge['rel']}** `{dst}`")

        if events:
            lines.append(f"\n## Intelligence Timeline ({len(events)} events)")
            lines.append("| Timestamp | Type | Target |")
            lines.append("|-----------|------|--------|")
            for ev in events[-50:]:
                ts = ev.get("timestamp", "")[:19]
                lines.append(f"| {ts} | {ev['type']} | `{ev['target']}` |")

        report = "\n".join(lines)

    else:  # JSON
        report = json.dumps({
            "title": title, "generated": now,
            "case": case, "entities": list(entities.values()),
            "edges": edges, "events": events
        }, indent=2, default=str)

    if out_path:
        out_path.write_text(report)
        print(f"[+] Report → {out_path}")
    return report


# ── interactive TUI ───────────────────────────────────────────────────

BANNER = r"""
  ██████╗ ██████╗ ███████╗███████╗ ██████╗    ██╗███╗   ██╗████████╗███████╗██╗
 ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝    ██║████╗  ██║╚══██╔══╝██╔════╝██║
 ██║   ██║██████╔╝███████╗█████╗  ██║         ██║██╔██╗ ██║   ██║   █████╗  ██║
 ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║         ██║██║╚██╗██║   ██║   ██╔══╝  ██║
 ╚██████╔╝██║     ███████║███████╗╚██████╗    ██║██║ ╚████║   ██║   ███████╗███████╗
  ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
  ── OPSEC Intelligence Terminal ── Palantir-class analysis platform ──
"""

HELP_TEXT = """
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
  report --case <name>          Generate intelligence report
  report --out <file>           Save report to file
  help                          Show this help
  exit / quit / q               Exit terminal
"""

PROMPT = "\n  intel> "


def _print_banner():
    if _use_colour():
        print(_c("cyan", BANNER))
    else:
        print(BANNER)
    print(_c("dim", "  Type 'help' for available commands\n"))


def _parse_and_dispatch(line: str, current_case: list) -> bool:
    """Parse one command line. Returns False to exit."""
    tokens = line.strip().split()
    if not tokens:
        return True

    cmd = tokens[0].lower()

    if cmd in ("exit", "quit", "q"):
        print(_c("dim", "\n  Goodbye. Stay anonymous.\n"))
        return False

    if cmd == "help":
        print(HELP_TEXT)

    elif cmd == "query" and len(tokens) >= 3:
        qtype  = tokens[1].lower()
        target = " ".join(tokens[2:])
        case   = current_case[0]
        if qtype == "ip":
            query_ip(target, case)
        elif qtype == "domain":
            query_domain(target, case)
        elif qtype == "email":
            query_email(target, case)
        elif qtype == "username":
            query_username(target, case)
        else:
            print(f"  [!] Unknown query type: {qtype}. Use ip/domain/email/username")

    elif cmd == "graph":
        case_filter = None
        if "--case" in tokens:
            idx = tokens.index("--case")
            if idx + 1 < len(tokens):
                case_filter = tokens[idx + 1]
        graph_show(case_filter or current_case[0])

    elif cmd == "timeline":
        show_timeline(current_case[0])

    elif cmd == "feeds" and len(tokens) >= 2:
        feed = tokens[1].lower()
        if feed == "cve":
            fetch_cve_feed()
        elif feed == "otx":
            fetch_otx_pulses()
        elif feed == "news":
            fetch_news_feed()
        else:
            print(f"  [!] Unknown feed: {feed}. Use cve/otx/news")

    elif cmd == "case" and len(tokens) >= 2:
        sub = tokens[1].lower()
        if sub == "new" and len(tokens) >= 3:
            name = " ".join(tokens[2:])
            case_new(name)
            current_case[0] = name
            print(f"  [+] Active case set to: {_c('yellow', name)}")
        elif sub == "list":
            case_list()
        elif sub == "note" and len(tokens) >= 4:
            name = tokens[2]
            note = " ".join(tokens[3:])
            case_add_note(name, note)
        elif sub == "close" and len(tokens) >= 3:
            case_close(" ".join(tokens[2:]))
        elif sub == "use" and len(tokens) >= 3:
            name = " ".join(tokens[2:])
            current_case[0] = name
            print(f"  [+] Active case: {_c('yellow', name)}")
        else:
            print("  case new <name> | case list | case note <name> <text> | case close <name> | case use <name>")

    elif cmd == "report":
        case_name = None
        out_path  = None
        fmt = "markdown"
        i = 1
        while i < len(tokens):
            if tokens[i] == "--case" and i + 1 < len(tokens):
                case_name = tokens[i + 1]; i += 2
            elif tokens[i] == "--out" and i + 1 < len(tokens):
                out_path = Path(tokens[i + 1]); i += 2
            elif tokens[i] == "--json":
                fmt = "json"; i += 1
            else:
                i += 1
        report = generate_report(case_name or current_case[0], out_path, fmt)
        if not out_path:
            print(report)

    elif cmd == "use" and len(tokens) >= 2:
        current_case[0] = " ".join(tokens[1:])
        print(f"  [+] Active case: {_c('yellow', current_case[0])}")

    elif cmd == "status":
        print(f"\n  Active case : {_c('yellow', current_case[0] or 'none')}")
        graph = _load(GRAPH_FILE)
        events = _load(EVENTS_FILE).get("events", [])
        cases  = _load(CASES_FILE).get("cases", {})
        print(f"  Entities    : {len(graph.get('entities', {}))}")
        print(f"  Relations   : {len(graph.get('edges', []))}")
        print(f"  Events      : {len(events)}")
        print(f"  Cases       : {len(cases)}")

    else:
        print(f"  [?] Unknown command: '{tokens[0]}'. Type 'help' for commands.")

    return True


def run_tui():
    _ensure_dirs()
    _print_banner()
    current_case = [None]  # mutable container for active case

    while True:
        try:
            if _use_colour():
                case_label = f"[{current_case[0]}] " if current_case[0] else ""
                sys.stdout.write(_c("cyan", f"\n  {case_label}") + _c("bold", "intel") + _c("cyan", "> "))
                sys.stdout.flush()
            else:
                sys.stdout.write(PROMPT)
                sys.stdout.flush()
            line = sys.stdin.readline()
            if not line:   # EOF
                break
            if not _parse_and_dispatch(line, current_case):
                break
        except KeyboardInterrupt:
            print(_c("dim", "\n  (use 'exit' or Ctrl-D to quit)"))
        except EOFError:
            break


# ── CLI dispatch ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OPSEC Intelligence Terminal")
    parser.add_argument("--mode", choices=["tui", "cli"], default="tui")

    sub = parser.add_subparsers(dest="cmd")

    qr = sub.add_parser("query", help="Run an intelligence query")
    qr.add_argument("type", choices=["ip", "domain", "email", "username"])
    qr.add_argument("target")
    qr.add_argument("--case")

    sub.add_parser("feeds", help="Fetch threat intelligence feeds").add_argument(
        "feed", choices=["cve", "otx", "news"])

    cs = sub.add_parser("case", help="Case management")
    cs.add_argument("action", choices=["new", "list", "close"])
    cs.add_argument("name", nargs="?")

    rp = sub.add_parser("report", help="Generate intelligence report")
    rp.add_argument("--case")
    rp.add_argument("--out", type=Path)
    rp.add_argument("--json", action="store_true")

    sub.add_parser("graph",    help="Show entity graph")
    sub.add_parser("timeline", help="Show event timeline")

    args = parser.parse_args()
    _ensure_dirs()

    if args.cmd == "query":
        dispatch = {"ip": query_ip, "domain": query_domain,
                    "email": query_email, "username": query_username}
        dispatch[args.type](args.target, args.case)

    elif args.cmd == "feeds":
        {"cve": fetch_cve_feed, "otx": fetch_otx_pulses, "news": fetch_news_feed}[args.feed]()

    elif args.cmd == "case":
        if args.action == "new":
            case_new(args.name or "")
        elif args.action == "list":
            case_list()
        elif args.action == "close":
            case_close(args.name or "")

    elif args.cmd == "report":
        fmt = "json" if args.json else "markdown"
        report = generate_report(args.case, args.out, fmt)
        if not args.out:
            print(report)

    elif args.cmd == "graph":
        graph_show()

    elif args.cmd == "timeline":
        show_timeline()

    else:
        # No subcommand → launch TUI
        run_tui()


if __name__ == "__main__":
    main()
