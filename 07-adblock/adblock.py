#!/usr/bin/env python3
"""
OPSEC Adblock & DNS Sinkhole Manager
=====================================
Aggregate multiple blocklists (ads, trackers, malware, telemetry),
generate /etc/hosts and Pi-hole / dnsmasq / unbound config files.

Usage:
  python adblock.py update                         # download all enabled sources
  python adblock.py build --format hosts           # write /etc/hosts style file
  python adblock.py build --format pihole          # Pi-hole AdList format
  python adblock.py build --format dnsmasq         # dnsmasq config
  python adblock.py build --format unbound         # unbound local-zone config
  python adblock.py stats
  python adblock.py whitelist --add google.com
  python adblock.py whitelist --remove google.com
  python adblock.py check --domain ads.example.com
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from datetime import datetime

CACHE_DIR = Path("~/.opsec/adblock").expanduser()
BLOCKLIST_DB = CACHE_DIR / "lists.json"
WHITELIST_FILE = CACHE_DIR / "whitelist.txt"

BUILTIN_SOURCES = [
    {
        "name": "StevenBlack Unified",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "category": "ads+trackers",
        "enabled": True,
    },
    {
        "name": "AdAway",
        "url": "https://adaway.org/hosts.txt",
        "category": "ads",
        "enabled": True,
    },
    {
        "name": "OISD Basic",
        "url": "https://hosts.oisd.nl/basic/",
        "category": "ads+trackers",
        "enabled": True,
    },
    {
        "name": "URLHaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "category": "malware",
        "enabled": True,
    },
    {
        "name": "Windows Telemetry",
        "url": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        "category": "telemetry",
        "enabled": True,
    },
    {
        "name": "Phishing Hosts",
        "url": "https://phishing.army/download/phishing_hosts.txt",
        "category": "phishing",
        "enabled": True,
    },
]


# ─────────────────────────── helpers ────────────────────────────────

def load_lists() -> list[dict]:
    if BLOCKLIST_DB.exists():
        db = json.loads(BLOCKLIST_DB.read_text())
        # Merge with any new built-in sources
        existing_urls = {s["url"] for s in db}
        for s in BUILTIN_SOURCES:
            if s["url"] not in existing_urls:
                db.append(s)
        return db
    return [s.copy() for s in BUILTIN_SOURCES]


def save_lists(lists: list[dict]):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    BLOCKLIST_DB.write_text(json.dumps(lists, indent=2))


def load_whitelist() -> set[str]:
    if WHITELIST_FILE.exists():
        return {line.strip().lower() for line in WHITELIST_FILE.read_text().splitlines()
                if line.strip() and not line.startswith("#")}
    return {"localhost", "local", "broadcasthost"}


def save_whitelist(wl: set[str]):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    WHITELIST_FILE.write_text("\n".join(sorted(wl)))


def parse_hosts_file(content: str) -> set[str]:
    """Parse a standard hosts file and extract blocked domains."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1"):
            domain = parts[1].lower()
            if domain not in ("localhost", "local", "broadcasthost", "0.0.0.0") and "." in domain:
                domains.add(domain)
        elif len(parts) == 1 and "." in parts[0]:
            domains.add(parts[0].lower())
    return domains


def parse_domain_list(content: str) -> set[str]:
    """Parse a simple newline-separated domain list."""
    return {line.strip().lower() for line in content.splitlines()
            if line.strip() and not line.startswith("#") and "." in line.strip()}


def download_list(source: dict) -> set[str]:
    """Download and parse a blocklist source."""
    url = source["url"]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        # Try both parsers
        domains = parse_hosts_file(content)
        if len(domains) < 100:
            domains = parse_domain_list(content)
        return domains
    except Exception as e:
        print(f"  [!] Failed to download {source['name']}: {e}")
        return set()


def load_cached_domains() -> set[str]:
    """Load all downloaded blocklists from cache."""
    all_domains = set()
    for f in CACHE_DIR.glob("list_*.txt"):
        all_domains.update(parse_hosts_file(f.read_text()))
    return all_domains


# ─────────────────────────── builders ───────────────────────────────

def build_hosts(domains: set[str], ip: str = "0.0.0.0") -> str:
    header = f"""# OPSEC Adblock Hosts File
# Generated: {datetime.now().isoformat()}
# Domains: {len(domains):,}
# Format: /etc/hosts

127.0.0.1 localhost
127.0.1.1 $(hostname)
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

"""
    return header + "\n".join(f"{ip} {d}" for d in sorted(domains))


def build_dnsmasq(domains: set[str]) -> str:
    header = f"# OPSEC dnsmasq blocklist — {datetime.now().isoformat()} — {len(domains):,} domains\n"
    return header + "\n".join(f"address=/{d}/0.0.0.0" for d in sorted(domains))


def build_unbound(domains: set[str]) -> str:
    header = f"# OPSEC unbound blocklist — {datetime.now().isoformat()} — {len(domains):,} domains\nserver:\n"
    return header + "\n".join(f'  local-zone: "{d}." always_nxdomain' for d in sorted(domains))


def build_pihole(domains: set[str]) -> str:
    """Pi-hole gravity list format."""
    return "\n".join(sorted(domains))


# ─────────────────────────── CLI commands ───────────────────────────

def cmd_update(args):
    lists = load_lists()
    enabled = [s for s in lists if s.get("enabled", True)]
    print(f"[*] Downloading {len(enabled)} blocklists …")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    total = 0
    for i, source in enumerate(enabled):
        print(f"  [{i+1}/{len(enabled)}] {source['name']} … ", end="", flush=True)
        domains = download_list(source)
        print(f"{len(domains):,} domains")
        cache_file = CACHE_DIR / f"list_{i:03d}_{source['name'].replace(' ', '_')}.txt"
        cache_file.write_text("\n".join(sorted(domains)))
        source["last_updated"] = datetime.now().isoformat()
        source["domain_count"] = len(domains)
        total += len(domains)

    save_lists(lists)
    all_domains = load_cached_domains()
    print(f"\n[+] Total unique domains: {len(all_domains):,}  (raw total: {total:,})")


def cmd_build(args):
    print("[*] Loading cached domains …")
    all_domains = load_cached_domains()
    if not all_domains:
        print("[!] No cached domains. Run 'update' first.")
        sys.exit(1)

    whitelist = load_whitelist()
    domains = all_domains - whitelist
    print(f"    Domains: {len(all_domains):,} → {len(domains):,} after whitelist ({len(whitelist)} entries)")

    out = Path(args.output)
    fmt = args.format

    if fmt == "hosts":
        content = build_hosts(domains, ip=args.ip)
    elif fmt == "dnsmasq":
        content = build_dnsmasq(domains)
    elif fmt == "unbound":
        content = build_unbound(domains)
    elif fmt == "pihole":
        content = build_pihole(domains)
    else:
        print(f"[!] Unknown format: {fmt}"); sys.exit(1)

    out.write_text(content)
    print(f"[+] Written: {out}  ({out.stat().st_size:,} bytes)")

    if fmt == "hosts":
        print("\nApply with:")
        print(f"  sudo cp {out} /etc/hosts")
        print("  sudo dscacheutil -flushcache  # macOS")
        print("  sudo resolvectl flush-caches   # Linux systemd-resolved")


def cmd_stats(args):
    lists = load_lists()
    all_domains = load_cached_domains()
    wl = load_whitelist()
    print(f"{'Name':<30} {'Category':<15} {'Domains':>10} {'Updated'}")
    print("-" * 80)
    for s in lists:
        dc = s.get("domain_count", "-")
        lu = s.get("last_updated", "never")[:19] if s.get("last_updated") else "never"
        status = "✓" if s.get("enabled") else "✗"
        print(f"{status} {s['name']:<28} {s.get('category',''):<15} {str(dc):>10} {lu}")
    print(f"\nTotal unique blocked: {len(all_domains):,}")
    print(f"Whitelist entries   : {len(wl)}")


def cmd_whitelist(args):
    wl = load_whitelist()
    if args.add:
        wl.add(args.add.lower())
        save_whitelist(wl)
        print(f"[+] Added to whitelist: {args.add}")
    elif args.remove:
        wl.discard(args.remove.lower())
        save_whitelist(wl)
        print(f"[-] Removed from whitelist: {args.remove}")
    elif args.list:
        for d in sorted(wl):
            print(d)
    else:
        print(f"Whitelist entries: {len(wl)}")
        for d in sorted(wl):
            print(f"  {d}")


def cmd_check(args):
    domain = args.domain.lower()
    all_domains = load_cached_domains()
    wl = load_whitelist()
    if domain in wl:
        print(f"[✓] {domain} — WHITELISTED")
    elif domain in all_domains:
        print(f"[✗] {domain} — BLOCKED")
        # Find which list
        for f in CACHE_DIR.glob("list_*.txt"):
            if domain in parse_hosts_file(f.read_text()):
                list_name = f.stem.split("_", 2)[-1].replace("_", " ")
                print(f"    Source: {list_name}")
                break
    else:
        print(f"[?] {domain} — NOT in blocklist")


def main():
    parser = argparse.ArgumentParser(description="OPSEC Adblock & DNS Sinkhole Manager")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("update", help="Download all enabled blocklists")

    bl = sub.add_parser("build", help="Build blocklist output file")
    bl.add_argument("--format", "-f", choices=["hosts", "dnsmasq", "unbound", "pihole"], default="hosts")
    bl.add_argument("--output", "-o", default="blocklist.txt")
    bl.add_argument("--ip", default="0.0.0.0", help="Redirect IP for hosts format")

    sub.add_parser("stats", help="Show stats for all blocklist sources")

    wl = sub.add_parser("whitelist", help="Manage whitelist")
    wl.add_argument("--add")
    wl.add_argument("--remove")
    wl.add_argument("--list", action="store_true")

    ck = sub.add_parser("check", help="Check if domain is blocked")
    ck.add_argument("--domain", required=True)

    args = parser.parse_args()
    dispatch = {
        "update": cmd_update, "build": cmd_build, "stats": cmd_stats,
        "whitelist": cmd_whitelist, "check": cmd_check,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
