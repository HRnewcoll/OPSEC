#!/usr/bin/env python3
"""
OPSEC Intel Terminal — SpiderFoot & Recon-ng Wrapper
=====================================================
Integration layer for popular OSINT frameworks:
  - SpiderFoot (REST API + local subprocess)
  - theHarvester (subprocess)
  - Recon-ng (subprocess)
  - amass / subfinder (subprocess)
  - masscan / RustScan port enumeration hints

All results are normalised into the ingest.py entity model and
stored in DuckDB automatically.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Optional

# ── SpiderFoot REST API ────────────────────────────────────────────────

SF_DEFAULT_URL = "http://localhost:5001"


def spiderfoot_running(base_url: str = SF_DEFAULT_URL) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url}/ping", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def spiderfoot_new_scan(
    target: str,
    scan_name: str = None,
    modules: str = "sfp_dnsresolve,sfp_whois,sfp_threatcrowd,sfp_shodan",
    base_url: str = SF_DEFAULT_URL,
) -> Optional[str]:
    """
    Start a new SpiderFoot scan. Returns scan ID or None.
    Requires SpiderFoot running: python sf.py -l 127.0.0.1:5001
    """
    name = scan_name or f"opsec_{target}_{int(__import__('time').time())}"
    params = urllib.parse.urlencode({
        "scanname": name, "scantarget": target,
        "modulelist": modules, "typelist": "",
        "usecase": "All",
    }).encode()

    try:
        import urllib.parse
        req = urllib.request.Request(
            f"{base_url}/startscan",
            data=params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            # SpiderFoot returns a redirect or scan page; extract scan ID
            import re
            m = re.search(r'scanid[=:\s]+([a-f0-9]{8,})', body, re.I)
            if m:
                return m.group(1)
    except Exception as e:
        print(f"[!] SpiderFoot API error: {e}")
    return None


def spiderfoot_get_results(
    scan_id: str,
    event_type: str = "",
    base_url: str = SF_DEFAULT_URL,
) -> list[dict]:
    """Fetch scan results for a given scan ID."""
    import urllib.parse
    url = f"{base_url}/scaneventresultsunique?id={scan_id}&eventType={event_type}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


def spiderfoot_list_scans(base_url: str = SF_DEFAULT_URL) -> list[dict]:
    try:
        with urllib.request.urlopen(f"{base_url}/scanlist", timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


def spiderfoot_ingest_results(
    scan_id: str,
    case_id: Optional[str] = None,
    base_url: str = SF_DEFAULT_URL,
) -> int:
    """
    Pull SpiderFoot results and upsert into DuckDB via ingest.py.
    Returns number of entities added.
    """
    try:
        import ingest
    except ImportError:
        print("[!] ingest.py not available"); return 0

    results = spiderfoot_get_results(scan_id, base_url=base_url)
    count   = 0
    sf_type_map = {
        "IP_ADDRESS":     "ip",
        "INTERNET_NAME":  "domain",
        "EMAILADDR":      "email",
        "USERNAME":       "username",
        "HASH":           "hash",
        "URL_FORM":       "url",
        "VULNERABILITY_GENERAL": "cve",
        "MALICIOUS_IPADDR": "ip",
        "MALICIOUS_INTERNET_NAME": "domain",
    }
    for row in results:
        sf_type = row.get("type") or row.get("Type", "")
        value   = row.get("data") or row.get("Data", "")
        if not value:
            continue
        etype = sf_type_map.get(sf_type, "unknown")
        if etype == "unknown":
            continue
        risk = 0.8 if "MALICIOUS" in sf_type else 0.3
        ingest.upsert_entity(etype, value,
                             {"source": "spiderfoot", "sf_type": sf_type},
                             case_id, risk_score=risk)
        ingest.add_ioc(etype, value, "spiderfoot", case_id)
        count += 1

    print(f"[+] SpiderFoot: ingested {count} entities from scan {scan_id}")
    return count


# ── theHarvester ───────────────────────────────────────────────────────

def run_theharvester(
    domain: str,
    sources: str = "google,bing,duckduckgo,crtsh",
    limit: int = 200,
    case_id: Optional[str] = None,
) -> dict:
    """
    Run theHarvester as a subprocess and parse output.
    Requires: pip install theHarvester
    """
    result: dict = {"domain": domain, "emails": [], "hosts": [], "ips": []}

    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    if not binary:
        result["error"] = (
            "theHarvester not found. Install: pip install theHarvester"
        )
        return result

    import tempfile, re
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    cmd = [
        binary, "-d", domain, "-b", sources,
        "-l", str(limit), "-f", out_file,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        # Parse JSON output
        out_path = Path(out_file + ".json")
        if out_path.exists():
            data = json.loads(out_path.read_text())
            result["emails"] = data.get("emails", [])
            result["hosts"]  = data.get("hosts",  [])
            result["ips"]    = data.get("ips",    [])
            out_path.unlink(missing_ok=True)
        else:
            # Fallback: parse text output
            text = proc.stdout
            result["emails"] = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)
            result["hosts"]  = re.findall(r"[\w.-]+\." + re.escape(domain), text)

    except subprocess.TimeoutExpired:
        result["error"] = "theHarvester timed out after 120s"
    except Exception as e:
        result["error"] = str(e)

    # Ingest results
    if case_id:
        try:
            import ingest
            for email in result.get("emails", []):
                ingest.upsert_entity("email", email,
                                     {"source": "theharvester"}, case_id)
                ingest.add_ioc("email", email, "theharvester", case_id)
            for host in result.get("hosts", []):
                ingest.upsert_entity("domain", host,
                                     {"source": "theharvester"}, case_id)
            for ip in result.get("ips", []):
                ingest.upsert_entity("ip", ip,
                                     {"source": "theharvester"}, case_id)
        except ImportError:
            pass

    return result


# ── Recon-ng wrapper ───────────────────────────────────────────────────

def run_recon_ng(
    domain: str,
    workspace: str = "opsec",
    modules: list[str] = None,
) -> dict:
    """
    Run Recon-ng commands via subprocess.
    Requires Recon-ng to be installed and on PATH.
    """
    reconng = shutil.which("recon-ng")
    if not reconng:
        return {
            "error": "Recon-ng not found. Install: pip install recon-ng",
            "install": "pip install recon-ng",
        }

    mods = modules or [
        "recon/domains-hosts/brute_hosts",
        "recon/hosts-hosts/resolve",
        "recon/domains-contacts/whois_pocs",
    ]

    commands = [
        f"workspaces create {workspace}",
        f"db insert domains << {domain}",
    ]
    for mod in mods:
        commands += [f"modules load {mod}", "run"]
    commands.append("exit")

    script = "\n".join(commands)
    try:
        proc = subprocess.run(
            [reconng, "--no-check"],
            input=script,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return {
            "stdout": proc.stdout[:5000],
            "stderr": proc.stderr[:1000],
            "workspace": workspace,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Recon-ng timed out"}
    except Exception as e:
        return {"error": str(e)}


# ── amass ─────────────────────────────────────────────────────────────

def run_amass(
    domain: str,
    passive: bool = True,
    timeout_min: int = 10,
    case_id: Optional[str] = None,
) -> list[str]:
    """
    Run OWASP Amass subdomain enumeration.
    Returns list of discovered subdomains.
    Install: go install -v github.com/owasp-amass/amass/v4/...@master
    """
    amass = shutil.which("amass")
    if not amass:
        print("[!] amass not found. Install from: https://github.com/owasp-amass/amass")
        return []

    cmd = [amass, "enum", "-d", domain, "-timeout", str(timeout_min)]
    if passive:
        cmd.append("-passive")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_min * 60 + 30)
        subdomains = [
            line.strip()
            for line in proc.stdout.splitlines()
            if line.strip() and domain in line
        ]
        if case_id and subdomains:
            try:
                import ingest
                for sub in subdomains:
                    ingest.upsert_entity("domain", sub,
                                         {"source": "amass", "parent": domain},
                                         case_id)
            except ImportError:
                pass
        return subdomains
    except Exception as e:
        print(f"[!] amass error: {e}")
        return []


# ── subfinder ─────────────────────────────────────────────────────────

def run_subfinder(
    domain: str,
    case_id: Optional[str] = None,
) -> list[str]:
    """
    Run ProjectDiscovery subfinder.
    Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    """
    binary = shutil.which("subfinder")
    if not binary:
        print("[!] subfinder not found.")
        return []
    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        subdomains = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        if case_id:
            try:
                import ingest
                for sub in subdomains:
                    ingest.upsert_entity("domain", sub,
                                         {"source": "subfinder"}, case_id)
            except ImportError:
                pass
        return subdomains
    except Exception as e:
        print(f"[!] subfinder error: {e}"); return []


# ── tool availability check ────────────────────────────────────────────

def check_tools() -> dict[str, bool]:
    return {
        "spiderfoot":    spiderfoot_running(),
        "theHarvester":  bool(shutil.which("theHarvester") or shutil.which("theharvester")),
        "recon-ng":      bool(shutil.which("recon-ng")),
        "amass":         bool(shutil.which("amass")),
        "subfinder":     bool(shutil.which("subfinder")),
        "masscan":       bool(shutil.which("masscan")),
        "rustscan":      bool(shutil.which("rustscan")),
        "nmap":          bool(shutil.which("nmap")),
    }
