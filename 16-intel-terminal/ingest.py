#!/usr/bin/env python3
"""
OPSEC Intel Terminal — DuckDB Ingestion Engine
================================================
DuckDB-backed OSINT data pipeline.  All queries store results persistently
and return pandas DataFrames ready for Streamlit.

Functions:
    init_db()                       — Create/open DB, ensure schema
    ingest_ip(ip, case_id)          — IP geo, ASN, Shodan → entities + events
    ingest_domain(domain, case_id)  — DNS, RDAP, crt.sh → entities + relationships
    ingest_email(email, case_id)    — MX, Gravatar, breach links
    ingest_username(username, case_id) — 19-platform username check
    add_ioc(type, value, source, case_id) — Add raw IOC
    get_entities(case_id)           — DataFrame of all entities
    get_relationships(case_id)      — DataFrame of all edges
    get_timeline(case_id, limit)    — DataFrame of events
    get_iocs(case_id)               — DataFrame of IOCs
    search(query)                   — Full-text search across entities + IOCs
    get_cases()                     — DataFrame of cases
    create_case(name, description)
    close_case(name)
    add_case_note(name, text)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import sys
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import duckdb
import pandas as pd

# ── paths ──────────────────────────────────────────────────────────────
INTEL_DIR = Path("~/.opsec/intel").expanduser()
DB_PATH   = INTEL_DIR / "intel.duckdb"

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

# ── schema ─────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          VARCHAR PRIMARY KEY,
    name        VARCHAR UNIQUE NOT NULL,
    description VARCHAR DEFAULT '',
    status      VARCHAR DEFAULT 'open',
    created     TIMESTAMP DEFAULT NOW(),
    modified    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS entities (
    id          VARCHAR PRIMARY KEY,
    type        VARCHAR NOT NULL,
    value       VARCHAR NOT NULL,
    metadata    JSON,
    case_id     VARCHAR,
    tags        VARCHAR[],
    risk_score  FLOAT   DEFAULT 0.0,
    first_seen  TIMESTAMP DEFAULT NOW(),
    last_seen   TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS relationships (
    id          VARCHAR PRIMARY KEY,
    from_id     VARCHAR NOT NULL,
    to_id       VARCHAR NOT NULL,
    rel_type    VARCHAR NOT NULL,
    case_id     VARCHAR,
    confidence  FLOAT   DEFAULT 1.0,
    created     TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          TIMESTAMP DEFAULT NOW(),
    event_type  VARCHAR NOT NULL,
    target      VARCHAR NOT NULL,
    case_id     VARCHAR,
    data        JSON
);

CREATE TABLE IF NOT EXISTS iocs (
    id          VARCHAR PRIMARY KEY,
    type        VARCHAR NOT NULL,
    value       VARCHAR NOT NULL,
    source      VARCHAR DEFAULT 'manual',
    tlp         VARCHAR DEFAULT 'WHITE',
    confidence  FLOAT   DEFAULT 0.5,
    case_id     VARCHAR,
    notes       VARCHAR DEFAULT '',
    added       TIMESTAMP DEFAULT NOW()
);

CREATE SEQUENCE IF NOT EXISTS event_seq START 1;
"""

# ── connection ─────────────────────────────────────────────────────────

_conn: Optional[duckdb.DuckDBPyConnection] = None


def get_conn() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is None:
        _conn = init_db()
    return _conn


def init_db() -> duckdb.DuckDBPyConnection:
    """Open (or create) the DuckDB database and ensure the schema exists."""
    global _conn
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(DB_PATH))
    conn.execute(_SCHEMA)
    _conn = conn
    return conn


# ── helpers ────────────────────────────────────────────────────────────

def _eid(entity_type: str, value: str) -> str:
    return hashlib.sha256(f"{entity_type.lower()}:{value.lower()}".encode()).hexdigest()[:16]


def _rid(from_id: str, to_id: str, rel_type: str) -> str:
    return hashlib.sha256(f"{from_id}:{to_id}:{rel_type}".encode()).hexdigest()[:16]


def http_get(url: str, timeout: int = 10) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def http_get_json(url: str, timeout: int = 10) -> Optional[dict]:
    raw = http_get(url, timeout)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return None


# ── entity CRUD ────────────────────────────────────────────────────────

def upsert_entity(
    entity_type: str,
    value: str,
    metadata: dict | None = None,
    case_id: str | None = None,
    tags: list[str] | None = None,
    risk_score: float = 0.0,
) -> str:
    conn = get_conn()
    eid  = _eid(entity_type, value)
    meta = json.dumps(metadata or {})
    now  = datetime.now(timezone.utc)

    existing = conn.execute("SELECT id FROM entities WHERE id = ?", [eid]).fetchone()
    if existing:
        conn.execute(
            "UPDATE entities SET last_seen=?, metadata=?, risk_score=GREATEST(risk_score,?) WHERE id=?",
            [now, meta, risk_score, eid]
        )
    else:
        conn.execute(
            "INSERT INTO entities(id,type,value,metadata,case_id,tags,risk_score,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            [eid, entity_type.lower(), value, meta, case_id, tags or [], risk_score, now, now]
        )
    return eid


def upsert_relationship(
    from_id: str,
    to_id: str,
    rel_type: str,
    case_id: str | None = None,
    confidence: float = 1.0,
) -> str:
    conn = get_conn()
    rid  = _rid(from_id, to_id, rel_type)
    existing = conn.execute("SELECT id FROM relationships WHERE id = ?", [rid]).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO relationships(id,from_id,to_id,rel_type,case_id,confidence)"
            " VALUES(?,?,?,?,?,?)",
            [rid, from_id, to_id, rel_type, case_id, confidence]
        )
    return rid


def log_event(event_type: str, target: str, data: dict, case_id: str | None = None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO events(id,ts,event_type,target,case_id,data)"
        " VALUES(nextval('event_seq'),NOW(),?,?,?,?)",
        [event_type, target, case_id, json.dumps(data)]
    )


def add_ioc(
    ioc_type: str,
    value: str,
    source: str = "manual",
    case_id: str | None = None,
    notes: str = "",
    confidence: float = 0.7,
    tlp: str = "WHITE",
) -> str:
    conn = get_conn()
    iid  = _eid(ioc_type, value)
    existing = conn.execute("SELECT id FROM iocs WHERE id = ?", [iid]).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO iocs(id,type,value,source,tlp,confidence,case_id,notes)"
            " VALUES(?,?,?,?,?,?,?,?)",
            [iid, ioc_type.lower(), value, source, tlp, confidence, case_id, notes]
        )
    return iid


# ── DataFrames for Streamlit ───────────────────────────────────────────

def get_entities(case_id: str | None = None) -> pd.DataFrame:
    conn = get_conn()
    if case_id:
        return conn.execute(
            "SELECT * FROM entities WHERE case_id=? ORDER BY last_seen DESC", [case_id]
        ).df()
    return conn.execute("SELECT * FROM entities ORDER BY last_seen DESC").df()


def get_relationships(case_id: str | None = None) -> pd.DataFrame:
    conn = get_conn()
    if case_id:
        return conn.execute(
            "SELECT * FROM relationships WHERE case_id=? ORDER BY created DESC", [case_id]
        ).df()
    return conn.execute("SELECT * FROM relationships ORDER BY created DESC").df()


def get_timeline(case_id: str | None = None, limit: int = 100) -> pd.DataFrame:
    conn = get_conn()
    if case_id:
        return conn.execute(
            "SELECT * FROM events WHERE case_id=? ORDER BY ts DESC LIMIT ?",
            [case_id, limit]
        ).df()
    return conn.execute(
        "SELECT * FROM events ORDER BY ts DESC LIMIT ?", [limit]
    ).df()


def get_iocs(case_id: str | None = None) -> pd.DataFrame:
    conn = get_conn()
    if case_id:
        return conn.execute(
            "SELECT * FROM iocs WHERE case_id=? ORDER BY added DESC", [case_id]
        ).df()
    return conn.execute("SELECT * FROM iocs ORDER BY added DESC").df()


def search(query: str) -> pd.DataFrame:
    conn = get_conn()
    like = f"%{query.lower()}%"
    ents = conn.execute(
        "SELECT id, type, value, case_id, risk_score, first_seen FROM entities"
        " WHERE LOWER(value) LIKE ? OR LOWER(type) LIKE ? ORDER BY risk_score DESC LIMIT 50",
        [like, like]
    ).df()
    iocs = conn.execute(
        "SELECT id, type, value, case_id, confidence AS risk_score, added AS first_seen"
        " FROM iocs WHERE LOWER(value) LIKE ? OR LOWER(type) LIKE ? LIMIT 50",
        [like, like]
    ).df()
    combined = pd.concat([ents, iocs], ignore_index=True).drop_duplicates("id")
    return combined


def get_stats(case_id: str | None = None) -> dict:
    conn = get_conn()
    q_suffix = "WHERE case_id=?" if case_id else ""
    params   = [case_id] if case_id else []
    return {
        "entities":      conn.execute(f"SELECT COUNT(*) FROM entities {q_suffix}", params).fetchone()[0],
        "relationships": conn.execute(f"SELECT COUNT(*) FROM relationships {q_suffix}", params).fetchone()[0],
        "events":        conn.execute(f"SELECT COUNT(*) FROM events {q_suffix}", params).fetchone()[0],
        "iocs":          conn.execute(f"SELECT COUNT(*) FROM iocs {q_suffix}", params).fetchone()[0],
    }


# ── case management ────────────────────────────────────────────────────

def get_cases() -> pd.DataFrame:
    return get_conn().execute("SELECT * FROM cases ORDER BY created DESC").df()


def create_case(name: str, description: str = "") -> str:
    conn = get_conn()
    cid  = _eid("case", name)
    try:
        conn.execute(
            "INSERT INTO cases(id,name,description) VALUES(?,?,?)",
            [cid, name, description]
        )
    except Exception:
        pass  # already exists
    return cid


def close_case(name: str):
    get_conn().execute(
        "UPDATE cases SET status='closed', modified=NOW() WHERE name=?", [name]
    )


# ── IP ingestion ───────────────────────────────────────────────────────

def ingest_ip(ip: str, case_id: str | None = None) -> dict:
    result: dict = {"ip": ip, "ts": datetime.now().isoformat()}

    # Validate
    try:
        addr = ipaddress.ip_address(ip)
        result["private"] = addr.is_private
        result["version"] = addr.version
    except ValueError:
        result["error"] = "Invalid IP"
        return result

    # Hostname
    try:
        result["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result["hostname"] = None

    # Geolocation — ip-api.com (free, no key)
    geo = http_get_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
        f"regionName,city,lat,lon,isp,org,as,query"
    )
    if geo and geo.get("status") == "success":
        result["geo"] = geo
        result["lat"] = geo.get("lat")
        result["lon"] = geo.get("lon")
        risk = 0.0
        if geo.get("countryCode") in ("RU", "CN", "KP", "IR"):
            risk += 0.3
        result["risk_score"] = risk

    # Shodan internetdb (free, no API key)
    shodan = http_get_json(f"https://internetdb.shodan.io/{ip}")
    if shodan:
        result["shodan"]  = shodan
        result["ports"]   = shodan.get("ports", [])
        result["hostnames"] = shodan.get("hostnames", [])
        vulns = shodan.get("vulns", [])
        result["vulns"]   = vulns
        if vulns:
            result["risk_score"] = result.get("risk_score", 0.0) + min(len(vulns) * 0.15, 0.7)

    # Add IOC
    add_ioc("ip", ip, "ingest", case_id)

    # Entity + relationships
    eid = upsert_entity("ip", ip, result, case_id,
                        risk_score=result.get("risk_score", 0.0))
    if result.get("hostname"):
        hid = upsert_entity("domain", result["hostname"], {}, case_id)
        upsert_relationship(eid, hid, "has_hostname", case_id)
    if geo and geo.get("org"):
        oid = upsert_entity("org", geo["org"], {}, case_id)
        upsert_relationship(eid, oid, "owned_by", case_id)
    for vuln in result.get("vulns", []):
        vid = upsert_entity("cve", vuln, {}, case_id, risk_score=0.8)
        upsert_relationship(eid, vid, "vulnerable_to", case_id, confidence=0.9)

    log_event("ip_lookup", ip, result, case_id)
    return result


# ── domain ingestion ───────────────────────────────────────────────────

def ingest_domain(domain: str, case_id: str | None = None) -> dict:
    result: dict = {"domain": domain, "ts": datetime.now().isoformat()}

    # A records
    try:
        ips = list({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)})
        result["a_records"] = ips
    except Exception:
        result["a_records"] = []

    # RDAP
    rdap = http_get_json(f"https://rdap.org/domain/{domain}")
    if rdap:
        for ev in rdap.get("events", []):
            if ev.get("eventAction") == "registration":
                result["registered"] = ev.get("eventDate", "")[:10]
        result["rdap_status"] = rdap.get("status", [])

    # Certificate Transparency (crt.sh) — discovers subdomains
    crt = http_get_json(f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json")
    subdomains: set[str] = set()
    if crt and isinstance(crt, list):
        for cert in crt[:200]:
            for sub in cert.get("name_value", "").split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
    result["subdomains"] = sorted(subdomains)[:30]

    # Risk hints
    risk = 0.0
    suspicious_tlds = (".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top")
    if any(domain.endswith(t) for t in suspicious_tlds):
        risk += 0.4
    if result.get("registered") and result["registered"] > (
        datetime.now().strftime("%Y") + "-01-01"
    ):
        risk += 0.1  # recently registered
    result["risk_score"] = min(risk, 1.0)

    # Entity + relationships
    add_ioc("domain", domain, "ingest", case_id)
    did = upsert_entity("domain", domain, result, case_id,
                        risk_score=result["risk_score"])
    for ip in result.get("a_records", []):
        iid = upsert_entity("ip", ip, {}, case_id)
        upsert_relationship(did, iid, "resolves_to", case_id)
    for sub in result.get("subdomains", []):
        sid = upsert_entity("domain", sub, {"parent": domain}, case_id)
        upsert_relationship(did, sid, "subdomain_of", case_id, confidence=0.95)
        if len(result.get("subdomains", [])) <= 10:
            # Only auto-ingest first 10 to avoid hammering
            pass

    log_event("domain_lookup", domain, result, case_id)
    return result


# ── email ingestion ────────────────────────────────────────────────────

def ingest_email(email: str, case_id: str | None = None) -> dict:
    result: dict = {"email": email, "ts": datetime.now().isoformat()}
    if not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        result["error"] = "Invalid email"
        return result

    local, domain = email.split("@", 1)
    result["local"]  = local
    result["domain"] = domain

    import hashlib
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    result["gravatar"]  = f"https://www.gravatar.com/avatar/{md5}"
    result["hibp_link"] = f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"

    add_ioc("email", email, "ingest", case_id)
    eid = upsert_entity("email", email, result, case_id)
    did = upsert_entity("domain", domain, {}, case_id)
    upsert_relationship(eid, did, "belongs_to", case_id)

    log_event("email_lookup", email, result, case_id)
    return result


# ── username ingestion ─────────────────────────────────────────────────

_PLATFORMS = [
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
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("Keybase",    "https://keybase.io/{}"),
    ("DockerHub",  "https://hub.docker.com/u/{}"),
    ("PyPI",       "https://pypi.org/user/{}"),
    ("NPM",        "https://www.npmjs.com/~{}"),
    ("Pastebin",   "https://pastebin.com/u/{}"),
    ("Dev.to",     "https://dev.to/{}"),
    ("Mastodon",   "https://mastodon.social/@{}"),
    ("Telegram",   "https://t.me/{}"),
]


def ingest_username(username: str, case_id: str | None = None) -> dict:
    result: dict = {"username": username, "ts": datetime.now().isoformat(),
                    "found": [], "not_found": []}

    def _check(platform: str, url_tpl: str) -> dict:
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

    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = {ex.submit(_check, p, u): p for p, u in _PLATFORMS}
        for fut in as_completed(futs):
            r = fut.result()
            if r["found"] is True:
                result["found"].append(r)
            elif r["found"] is False:
                result["not_found"].append(r["platform"])

    uid = upsert_entity("username", username, result, case_id,
                        risk_score=0.0)
    for entry in result["found"]:
        peid = upsert_entity("url", entry["url"],
                             {"platform": entry["platform"]}, case_id)
        upsert_relationship(uid, peid, "profile_on", case_id)

    log_event("username_lookup", username, result, case_id)
    return result


# ── aggregate stats for dashboard ─────────────────────────────────────

def entity_type_counts(case_id: str | None = None) -> pd.DataFrame:
    conn = get_conn()
    q = "SELECT type, COUNT(*) as count FROM entities"
    if case_id:
        q += " WHERE case_id=?"
        return conn.execute(q + " GROUP BY type ORDER BY count DESC", [case_id]).df()
    return conn.execute(q + " GROUP BY type ORDER BY count DESC").df()


def top_risk_entities(case_id: str | None = None, n: int = 10) -> pd.DataFrame:
    conn = get_conn()
    q = "SELECT id, type, value, risk_score, case_id FROM entities"
    if case_id:
        q += f" WHERE case_id=? ORDER BY risk_score DESC LIMIT {n}"
        return conn.execute(q, [case_id]).df()
    q += f" ORDER BY risk_score DESC LIMIT {n}"
    return conn.execute(q).df()


def geo_entities() -> pd.DataFrame:
    """Return entities with lat/lon extracted from metadata JSON."""
    conn = get_conn()
    return conn.execute("""
        SELECT id, type, value,
               TRY_CAST(json_extract_string(metadata, '$.lat') AS FLOAT) AS lat,
               TRY_CAST(json_extract_string(metadata, '$.lon') AS FLOAT) AS lon,
               json_extract_string(metadata, '$.geo.country') AS country,
               json_extract_string(metadata, '$.geo.city')    AS city,
               risk_score
        FROM entities
        WHERE json_extract_string(metadata, '$.lat') IS NOT NULL
    """).df()
