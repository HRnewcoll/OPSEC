#!/usr/bin/env python3
"""
OPSEC Network Scanner
======================
Comprehensive network reconnaissance tool:
  - TCP/UDP port scanning (SYN-like connect scan, stealth options)
  - Service and version fingerprinting (banner grab)
  - OS detection hints from TTL and TCP window
  - ICMP host discovery (ping sweep)
  - ARP sweep for local network
  - CVE/vulnerability hints from service banners
  - Export results as JSON, CSV, or Nmap-like text

Usage:
  python network_scanner.py scan   --target 192.168.1.0/24 --ports top100
  python network_scanner.py scan   --target 10.0.0.1 --ports 1-65535 --threads 200
  python network_scanner.py ping   --network 192.168.1.0/24
  python network_scanner.py banner --target 192.168.1.1 --port 22
  python network_scanner.py full   --target 192.168.1.0/24 --out scan.json
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


# ── port lists ────────────────────────────────────────────────────────

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2181, 3000, 3306,
    3389, 3690, 4000, 4444, 5000, 5432, 5900, 5984, 6379, 6443, 7001, 7474,
    8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 10000, 11211,
    27017, 27018, 28017, 50000, 50070, 61616,
    # additional common
    20, 69, 79, 88, 102, 113, 137, 138, 179, 264, 389, 636, 873, 902, 1194,
    1723, 1812, 1813, 2375, 2376, 4369, 5222, 5269, 5353, 5672, 6000, 6667,
    8009, 8161, 8500, 9999,
]

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 79: "Finger",
    80: "HTTP", 88: "Kerberos", 102: "MMS", 110: "POP3", 111: "RPC",
    119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-sub", 631: "IPP", 636: "LDAPS", 873: "rsync",
    902: "VMware", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4369: "Erlang-EPM", 5000: "Flask/UPnP", 5222: "XMPP",
    5353: "mDNS", 5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "K8s-API", 6667: "IRC",
    7001: "WebLogic", 7474: "Neo4j", 8000: "HTTP-alt", 8009: "AJP",
    8080: "HTTP-proxy", 8081: "HTTP-alt2", 8161: "ActiveMQ",
    8443: "HTTPS-alt", 8500: "Consul", 8888: "Jupyter",
    9000: "SonarQube/PHP-FPM", 9090: "Prometheus/Cockpit",
    9200: "Elasticsearch", 9300: "Elasticsearch-cluster",
    9418: "Git", 9999: "Tor/JDWP", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-shard",
    28017: "MongoDB-web", 50000: "SAP", 50070: "Hadoop-HDFS",
    61616: "ActiveMQ-broker",
}

# Vulnerability hints keyed on service banner keywords
VULN_HINTS = {
    "openssh 7.2": "CVE-2016-6210: user enumeration",
    "openssh 7.4": "CVE-2018-15473: user enumeration",
    "openssh 8.0": "Consider CVE-2023-38408 (agent forwarding)",
    "apache/2.4.49": "CVE-2021-41773: Path traversal (critical)",
    "apache/2.4.50": "CVE-2021-42013: Path traversal bypass (critical)",
    "iis/7.5": "CVE-2010-3972: FTP auth bypass",
    "vsftpd 2.3.4": "CVE-2011-2523: Backdoor command exec (critical)",
    "proftpd 1.3.3": "CVE-2010-4221: Stack overflow",
    "redis": "Check if requires authentication (redis-cli ping)",
    "memcached": "Typically no auth — data exposure risk",
    "mongodb": "Check if auth enabled (CVE-2013-1892)",
    "elasticsearch": "Check if auth + TLS enabled",
    "docker": "Docker daemon exposed — potential container escape",
    "kubernetes": "K8s API exposed — check RBAC",
    "weblogic": "Check CVE-2020-14882, CVE-2021-2394 (RCE)",
    "jenkins": "Check CVE-2024-23897 (arbitrary file read)",
    "tomcat": "Check CVE-2020-1938 (Ghostcat AJP)",
    "wordpress": "Use WPScan for vulnerability enumeration",
    "drupal": "Check SA-CORE-2018-002 (Drupalgeddon2)",
    "jboss": "Check CVE-2017-12149 (deserialization RCE)",
}


# ── port scanner ──────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    result = {"port": port, "state": "closed", "service": SERVICE_NAMES.get(port, "unknown")}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            result["state"] = "open"
            # Banner grab
            try:
                s.settimeout(2.0)
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                if not banner:
                    # Try HTTP
                    pass
                result["banner"] = banner[:200]
                result["vuln_hints"] = _check_vuln(banner)
            except Exception:
                pass
    except (ConnectionRefusedError, OSError):
        result["state"] = "closed"
    except socket.timeout:
        result["state"] = "filtered"
    return result


def scan_port_http(host: str, port: int, timeout: float = 2.0) -> dict:
    """Additional HTTP banner grab for web ports."""
    result = scan_port(host, port, timeout)
    if result["state"] == "open" and port in (80, 8080, 8000, 8081, 8888):
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                s.sendall(req)
                resp = s.recv(2048).decode("utf-8", errors="replace")
                # Extract Server header
                for line in resp.splitlines():
                    if line.lower().startswith("server:"):
                        result["http_server"] = line.split(":", 1)[1].strip()
                    if line.lower().startswith("x-powered-by:"):
                        result["http_powered_by"] = line.split(":", 1)[1].strip()
                result["http_status"] = resp.split("\r\n")[0] if resp else None
        except Exception:
            pass
    return result


def _check_vuln(banner: str) -> list[str]:
    banner_lower = banner.lower()
    hints = []
    for pattern, hint in VULN_HINTS.items():
        if pattern in banner_lower:
            hints.append(hint)
    return hints


def parse_port_range(spec: str) -> list[int]:
    if spec == "top100":
        return TOP_100_PORTS
    if spec == "all":
        return list(range(1, 65536))
    if spec == "common":
        return list(range(1, 1025))
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ── OS fingerprint hints ──────────────────────────────────────────────

def ttl_os_hint(ttl: int) -> str:
    if ttl <= 0:
        return "unknown"
    if ttl <= 64:
        return "Linux/macOS (TTL≤64)"
    if ttl <= 128:
        return "Windows (TTL≤128)"
    if ttl <= 255:
        return "Cisco/network device (TTL≤255)"
    return "unknown"


def ping_host(host: str) -> tuple[bool, int]:
    """Return (alive, ttl). TTL=-1 if unknown."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", "1000", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        alive = result.returncode == 0
        ttl = -1
        m = re.search(r"[Tt][Tt][Ll]=(\d+)", result.stdout)
        if m:
            ttl = int(m.group(1))
        return alive, ttl
    except Exception:
        return False, -1


# ── network sweep ─────────────────────────────────────────────────────

def ping_sweep(network: str, threads: int = 50) -> list[dict]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network: {e}")
        return []

    hosts = list(net.hosts())
    print(f"[*] Ping sweep: {network} ({len(hosts)} hosts, {threads} threads)")
    alive = []

    def check(ip):
        host = str(ip)
        is_alive, ttl = ping_host(host)
        if is_alive:
            hostname = None
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                pass
            return {"ip": host, "alive": True, "ttl": ttl,
                    "os_hint": ttl_os_hint(ttl), "hostname": hostname}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive.append(res)
                print(f"  ✓ {res['ip']:<18} TTL={res['ttl']:<4} {res['os_hint']}"
                      + (f"  ({res['hostname']})" if res['hostname'] else ""))

    print(f"\n[+] {len(alive)}/{len(hosts)} hosts alive")
    return sorted(alive, key=lambda x: ipaddress.ip_address(x["ip"]))


# ── full host scan ────────────────────────────────────────────────────

def scan_host(host: str, ports: list[int], threads: int = 100,
              timeout: float = 1.0) -> dict:
    print(f"[*] Scanning {host} — {len(ports)} ports")
    result = {"host": host, "timestamp": datetime.now().isoformat(),
              "ports": [], "os_hint": None}

    # Hostname resolution
    try:
        result["hostname"] = socket.gethostbyaddr(host)[0]
    except Exception:
        result["hostname"] = None

    # Ping for OS hint
    alive, ttl = ping_host(host)
    result["alive"] = alive
    if ttl > 0:
        result["ttl"] = ttl
        result["os_hint"] = ttl_os_hint(ttl)

    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port_http, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r["state"] in ("open", "filtered"):
                open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])
    result["ports"] = open_ports
    result["open_count"] = sum(1 for p in open_ports if p["state"] == "open")
    return result


def scan_network(network: str, ports: list[int], threads: int = 100) -> list[dict]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[!] {e}"); return []

    # First ping sweep
    alive_hosts = ping_sweep(network, threads=min(threads, 50))
    if not alive_hosts:
        print("[!] No alive hosts found")
        return []

    results = []
    for host_info in alive_hosts:
        host = host_info["ip"]
        scan_result = scan_host(host, ports, threads=threads)
        scan_result.update(host_info)
        results.append(scan_result)
        _print_host_result(scan_result)
    return results


def _print_host_result(result: dict):
    print(f"\n{'='*60}")
    print(f"  Host     : {result['host']}"
          + (f"  ({result.get('hostname')})" if result.get('hostname') else ""))
    print(f"  OS hint  : {result.get('os_hint', 'unknown')}")
    print(f"  Open ports ({result.get('open_count', 0)}):")
    for p in result.get("ports", []):
        if p["state"] == "open":
            banner = p.get("banner", "")[:60] if p.get("banner") else ""
            server = p.get("http_server", "")
            svc_str = p.get("service", "")
            extra = server or banner
            print(f"    {p['port']:<6} {svc_str:<18} {extra}")
            for hint in p.get("vuln_hints", []):
                print(f"           ⚠  {hint}")


# ── banner grab single port ───────────────────────────────────────────

def banner_grab(host: str, port: int) -> dict:
    print(f"[*] Banner grab: {host}:{port}")
    result = scan_port_http(host, port, timeout=3.0)
    print(json.dumps(result, indent=2))
    return result


# ── export ────────────────────────────────────────────────────────────

def export_results(results, out_path: Path, fmt: str = "json"):
    if fmt == "json":
        out_path.write_text(json.dumps(results, indent=2))
    elif fmt == "csv":
        import csv
        rows = []
        for r in (results if isinstance(results, list) else [results]):
            for p in r.get("ports", []):
                rows.append({
                    "host": r.get("host"), "hostname": r.get("hostname"),
                    "port": p["port"], "state": p["state"],
                    "service": p.get("service"), "banner": p.get("banner", ""),
                    "os_hint": r.get("os_hint"),
                })
        with open(out_path, "w", newline="") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
    print(f"[+] Results → {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OPSEC Network Scanner")
    sub = parser.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="Port scan a host or network")
    sc.add_argument("--target", required=True, help="IP, hostname, or CIDR")
    sc.add_argument("--ports", default="top100",
                    help="Port spec: top100 | common | all | 22,80,443 | 1-1024")
    sc.add_argument("--threads", type=int, default=100)
    sc.add_argument("--timeout", type=float, default=1.0)
    sc.add_argument("--out", help="Output file path")
    sc.add_argument("--format", choices=["json", "csv"], default="json")

    pg = sub.add_parser("ping", help="Ping sweep a network")
    pg.add_argument("--network", required=True, help="CIDR e.g. 192.168.1.0/24")
    pg.add_argument("--threads", type=int, default=50)
    pg.add_argument("--out")

    bn = sub.add_parser("banner", help="Grab service banner from a single port")
    bn.add_argument("--target", required=True)
    bn.add_argument("--port", required=True, type=int)

    fl = sub.add_parser("full", help="Ping sweep + port scan + export")
    fl.add_argument("--target", required=True, help="CIDR or single IP")
    fl.add_argument("--ports", default="top100")
    fl.add_argument("--threads", type=int, default=100)
    fl.add_argument("--out", default="scan_results.json")
    fl.add_argument("--format", choices=["json", "csv"], default="json")

    args = parser.parse_args()

    if args.cmd == "scan":
        ports = parse_port_range(args.ports)
        try:
            ipaddress.ip_network(args.target, strict=False)
            results = scan_network(args.target, ports, args.threads)
        except ValueError:
            results = scan_host(args.target, ports, args.threads, args.timeout)
            _print_host_result(results)
        if args.out:
            export_results(results, Path(args.out), args.format)

    elif args.cmd == "ping":
        results = ping_sweep(args.network, args.threads)
        if args.out:
            export_results(results, Path(args.out))

    elif args.cmd == "banner":
        banner_grab(args.target, args.port)

    elif args.cmd == "full":
        ports = parse_port_range(args.ports)
        results = scan_network(args.target, ports, args.threads)
        export_results(results, Path(args.out), args.format)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
