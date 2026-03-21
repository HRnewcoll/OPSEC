#!/usr/bin/env python3
"""
OPSEC OSINT Intelligence Toolkit
==================================
Passive and active OSINT gathering tools for:
  - Email reconnaissance (breach check, header analysis)
  - Username enumeration across platforms
  - IP address geolocation and ASN lookup
  - WHOIS domain lookup
  - DNS enumeration (subdomains, records)
  - Reverse image search links
  - Social media profile discovery

Usage:
  python osint.py email --address user@example.com
  python osint.py username --name johndoe
  python osint.py ip --address 8.8.8.8
  python osint.py whois --domain example.com
  python osint.py dns --domain example.com --type all
  python osint.py phone --number "+1-555-123-4567"
  python osint.py report --target example.com --out report.json
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path


# ─────────────────────────── helpers ────────────────────────────────

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"


def http_get(url: str, timeout: int = 10) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def http_get_json(url: str, timeout: int = 10) -> dict | None:
    data = http_get(url, timeout)
    if data:
        try:
            return json.loads(data)
        except Exception:
            return None
    return None


# ─────────────────────────── username OSINT ─────────────────────────

PLATFORMS = [
    ("GitHub",          "https://github.com/{}"),
    ("GitLab",          "https://gitlab.com/{}"),
    ("Twitter/X",       "https://x.com/{}"),
    ("Instagram",       "https://www.instagram.com/{}"),
    ("Reddit",          "https://www.reddit.com/user/{}"),
    ("LinkedIn",        "https://www.linkedin.com/in/{}"),
    ("TikTok",          "https://www.tiktok.com/@{}"),
    ("YouTube",         "https://www.youtube.com/@{}"),
    ("Pinterest",       "https://www.pinterest.com/{}"),
    ("Twitch",          "https://www.twitch.tv/{}"),
    ("Steam",           "https://steamcommunity.com/id/{}"),
    ("Keybase",         "https://keybase.io/{}"),
    ("Mastodon",        "https://mastodon.social/@{}"),
    ("Telegram",        "https://t.me/{}"),
    ("Pastebin",        "https://pastebin.com/u/{}"),
    ("HackerNews",      "https://news.ycombinator.com/user?id={}"),
    ("Medium",          "https://medium.com/@{}"),
    ("Dev.to",          "https://dev.to/{}"),
    ("StackOverflow",   "https://stackoverflow.com/users/{}"),
    ("Gravatar",        "https://www.gravatar.com/{}"),
    ("DockerHub",       "https://hub.docker.com/u/{}"),
    ("NPM",             "https://www.npmjs.com/~{}"),
    ("PyPI",            "https://pypi.org/user/{}"),
    ("Replit",          "https://replit.com/@{}"),
    ("Codepen",         "https://codepen.io/{}"),
]


def check_username(username: str, platform: str, url_template: str) -> dict:
    url = url_template.format(username)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=8) as resp:
            code = resp.getcode()
            found = code == 200
    except urllib.error.HTTPError as e:
        found = e.code not in (404, 410)
    except Exception:
        found = None
    return {"platform": platform, "url": url, "found": found}


# ─────────────────────────── IP OSINT ───────────────────────────────

def ip_lookup(ip: str) -> dict:
    results = {"ip": ip}

    # Validate IP
    try:
        addr = ipaddress.ip_address(ip)
        results["type"] = "IPv6" if addr.version == 6 else "IPv4"
        results["private"] = addr.is_private
        results["loopback"] = addr.is_loopback
    except ValueError:
        results["error"] = "Invalid IP address"
        return results

    if addr.is_private or addr.is_loopback:
        results["note"] = "Private/loopback address — no geolocation available"
        return results

    # Reverse DNS
    try:
        results["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        results["hostname"] = None

    # ip-api.com (free, no key needed)
    geo = http_get_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query")
    if geo and geo.get("status") == "success":
        results["geo"] = geo

    # Shodan internetdb (no API key needed)
    shodan = http_get_json(f"https://internetdb.shodan.io/{ip}")
    if shodan:
        results["shodan"] = shodan

    return results


# ─────────────────────────── DNS OSINT ──────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn",
    "dev", "staging", "test", "qa", "prod", "api", "cdn", "static",
    "portal", "admin", "dashboard", "git", "gitlab", "github", "jenkins",
    "ci", "jira", "wiki", "docs", "kb", "support", "help",
    "shop", "store", "blog", "news", "media",
    "ns1", "ns2", "ns3", "ns4",
    "mx1", "mx2", "mail2",
    "webmail", "owa", "exchange",
    "remote", "rdp", "vpn2", "proxy",
    "grafana", "prometheus", "kibana", "elastic",
    "s3", "storage", "backup",
    "mobile", "m", "app",
]


def dns_lookup(domain: str, record_type: str = "A") -> list[str]:
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", f"-t{record_type}", domain],
            capture_output=True, text=True, timeout=10
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        pass
    try:
        if record_type == "A":
            return [str(r) for r in socket.getaddrinfo(domain, None, socket.AF_INET)]
        elif record_type == "AAAA":
            return [str(r[4][0]) for r in socket.getaddrinfo(domain, None, socket.AF_INET6)]
    except Exception:
        pass
    return []


def enumerate_subdomains(domain: str, wordlist: list[str] | None = None) -> list[str]:
    """Check common subdomains via DNS resolution."""
    wordlist = wordlist or COMMON_SUBDOMAINS
    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(3)
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
        except Exception:
            pass
    socket.setdefaulttimeout(None)
    return found


# ─────────────────────────── Email OSINT ────────────────────────────

def email_osint(email: str) -> dict:
    result = {"email": email}
    if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        result["error"] = "Invalid email address"
        return result

    local, domain = email.split("@", 1)
    result["local_part"] = local
    result["domain"] = domain

    # MX records
    result["mx_records"] = dns_lookup(domain, "MX")

    # Check HaveIBeenPwned (requires API key for v3, but we can link)
    result["breach_check_urls"] = [
        f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}",
        f"https://breachdirectory.org/?q={urllib.parse.quote(email)}",
        f"https://leakcheck.io/email/{urllib.parse.quote(email)}",
    ]

    # Gravatar
    import hashlib
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    result["gravatar_url"] = f"https://www.gravatar.com/avatar/{md5}"

    return result


# ─────────────────────────── WHOIS ──────────────────────────────────

def whois_lookup(domain: str) -> str:
    """Perform WHOIS lookup via subprocess or rdap."""
    # Try whois command
    try:
        import subprocess
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        if result.stdout:
            return result.stdout[:4000]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: RDAP
    clean_domain = domain.lstrip("www.").lstrip("*.")
    rdap_urls = [
        f"https://rdap.org/domain/{clean_domain}",
        f"https://rdap.iana.org/domain/{clean_domain}",
    ]
    for url in rdap_urls:
        data = http_get_json(url)
        if data:
            return json.dumps(data, indent=2)[:4000]

    return "WHOIS lookup failed. Try: whois " + domain


# ─────────────────────────── CLI commands ───────────────────────────

def cmd_email(args):
    print(f"[*] Email OSINT: {args.address}")
    result = email_osint(args.address)
    print(json.dumps(result, indent=2))


def cmd_username(args):
    username = args.name
    print(f"[*] Username search: {username}")
    print(f"    Checking {len(PLATFORMS)} platforms …\n")
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(check_username, username, p, url): p for p, url in PLATFORMS}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if r["found"] is True:
                print(f"  ✓ FOUND   {r['platform']:<20} {r['url']}")
            elif r["found"] is False:
                print(f"  ✗ not found  {r['platform']}")
            else:
                print(f"  ? unknown    {r['platform']}")

    found = [r for r in results if r["found"] is True]
    print(f"\n[+] Found on {len(found)}/{len(PLATFORMS)} platforms")
    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
        print(f"[+] Results → {args.output}")


def cmd_ip(args):
    print(f"[*] IP OSINT: {args.address}")
    result = ip_lookup(args.address)
    print(json.dumps(result, indent=2))


def cmd_whois(args):
    print(f"[*] WHOIS: {args.domain}")
    result = whois_lookup(args.domain)
    print(result)


def cmd_dns(args):
    domain = args.domain
    record_type = args.type.upper()
    print(f"[*] DNS OSINT: {domain}")

    if record_type == "ALL":
        for rt in DNS_RECORD_TYPES:
            records = dns_lookup(domain, rt)
            if records:
                print(f"\n  {rt}:")
                for r in records:
                    print(f"    {r}")
    elif record_type == "SUBDOMAINS":
        print(f"\n  Enumerating subdomains …")
        found = enumerate_subdomains(domain)
        print(f"\n  Found {len(found)} subdomains:")
        for s in found:
            print(f"    {s['subdomain']:<40} → {s['ip']}")
    else:
        records = dns_lookup(domain, record_type)
        print(f"\n  {record_type}: {records}")


def cmd_report(args):
    target = args.target
    print(f"[*] Generating OSINT report for: {target}")
    report = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "dns": {},
        "whois": None,
        "subdomains": [],
    }

    # DNS records
    for rt in DNS_RECORD_TYPES:
        records = dns_lookup(target, rt)
        if records:
            report["dns"][rt] = records

    # WHOIS
    report["whois"] = whois_lookup(target)

    # Subdomains
    print("  Enumerating subdomains …")
    report["subdomains"] = enumerate_subdomains(target)
    print(f"  Found {len(report['subdomains'])} subdomains")

    out = Path(args.out)
    out.write_text(json.dumps(report, indent=2))
    print(f"[+] Report → {out}")


def main():
    parser = argparse.ArgumentParser(description="OPSEC OSINT Intelligence Toolkit")
    sub = parser.add_subparsers(dest="cmd")

    em = sub.add_parser("email", help="Email OSINT (MX, Gravatar, breach links)")
    em.add_argument("--address", required=True)

    un = sub.add_parser("username", help="Username search across platforms")
    un.add_argument("--name", required=True)
    un.add_argument("--output", "-o")

    ip = sub.add_parser("ip", help="IP address OSINT (geo, ASN, Shodan)")
    ip.add_argument("--address", required=True)

    wh = sub.add_parser("whois", help="WHOIS domain lookup")
    wh.add_argument("--domain", required=True)

    dns = sub.add_parser("dns", help="DNS record enumeration")
    dns.add_argument("--domain", required=True)
    dns.add_argument("--type", default="ALL",
                     choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ALL", "SUBDOMAINS"])

    rep = sub.add_parser("report", help="Generate comprehensive OSINT report")
    rep.add_argument("--target", required=True)
    rep.add_argument("--out", default="osint_report.json")

    args = parser.parse_args()
    dispatch = {
        "email": cmd_email, "username": cmd_username, "ip": cmd_ip,
        "whois": cmd_whois, "dns": cmd_dns, "report": cmd_report,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
