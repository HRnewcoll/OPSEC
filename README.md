# OPSEC

> **A modular, zero-cloud OPSEC & OSINT toolkit — and a guide to building your own private Palantir.**

---

## 📦 This Toolkit — 16 Modules

| # | Module | What it does |
|---|--------|-------------|
| 01 | [Proxy / VPN Tools](01-proxy-vpn/) | WireGuard config gen, SOCKS5/HTTP proxy chains, Tor routing |
| 02 | [Quantum-Resistant Encryption](02-quantum-encryption/) | AES-256-GCM + X25519 hybrid encryption, Argon2id KDF, Kyber simulation |
| 03 | [Secure Messaging](03-secure-messaging/) | Double-Ratchet E2E CLI messenger + browser chat |
| 04 | [Secure File Sharing](04-secure-file-sharing/) | Encrypted chunked transfer with BLAKE2b integrity & zlib compression |
| 05 | [MAC Spoofer](05-mac-spoofer/) | Randomise / rotate MAC addresses per interface |
| 06 | [Fingerprint Blocker](06-fingerprint-blocker/) | Canvas noise, WebGL spoof, WebRTC block, UA rotation |
| 07 | [Adblock & DNS Sinkhole](07-adblock/) | Aggregate blocklists → `/etc/hosts`, Pi-hole, dnsmasq, unbound |
| 08 | [Session Manager](08-session-manager/) | Isolated browser profiles per identity |
| 09 | [OSINT Tools](09-osint-tools/) | Email recon, username enum (25+ platforms), IP geo, DNS, WHOIS |
| 10 | [Hash Tools](10-hash-tools/) | Multi-algo hashing, HMAC, Argon2id, hash-id, dict cracking |
| 11 | [Firmware](11-firmware/) | Firmware analysis utilities |
| 12 | [Data Recovery](12-data-recovery/) | AES-256-GCM encrypted backup with incremental support & BLAKE2b |
| 13 | [Network Scanner](13-network-scanner/) | TCP port scan, banner grab, OS hint, ping sweep, CVE hints |
| 14 | [Password Manager](14-password-manager/) | AES-256-GCM vault, PBKDF2, TOTP, HIBP k-anon breach check |
| 15 | [Metadata Cleaner](15-metadata-cleaner/) | Strip EXIF/PDF/DOCX metadata before sharing |
| 16 | [Intel Terminal](16-intel-terminal/) | Palantir-inspired CLI: entity graph, threat intel, case management |

```bash
# Install deps for any module
pip install -r <module>/requirements.txt
```

---

## 🌍 Build Your Private Palantir

The sections below are a curated map of the open-source ecosystem you can wire together to build a **god's-eye geospatial intelligence dashboard** — fully local, zero cloud dependency.

---

### 🖥️ Tier 1 — "God's-Eye" Dashboards (Highest Visual Impact)

| Repo | What it is |
|------|-----------|
| 🔗 [WorldMonitor](https://github.com/koala73/worldmonitor) | **The 2026 breakout.** Real-time 36-layer global intelligence dashboard — ADS-B flights, AIS ships, active conflicts, nuclear sites, undersea cables, satellite fire detections, protests, sanctions, internet outages, prediction markets. AI classifies threats, generates briefs, computes per-country Instability Index. 3D globe option. Pure Palantir Gotham aesthetic. Browser-based (self-host or Vercel). MIT license. |
| 🔗 [Crucix](https://github.com/calesthio/Crucix) | **OPSEC-maxxed local watcher.** Pulls 27 open feeds every 15 min (NASA fires, ACLED conflicts, GDELT, planes/ships, radiation, quakes, sanctions, social sentiment). Self-contained Node.js + SSE dashboard, pings on changes, fully local/Docker, zero telemetry. Hook local LLMs (Ollama) for natural-language queries. Closest to a "Jarvis-style" terminal agent that watches the world privately. |
| 🔗 [RADAR](https://github.com/Syntax-Error-1337/radar) | **Geospatial intel aggregator.** Blends ADS-B flights, AIS ships, GPS jamming heatmaps (H3), geo-news, Cloudflare cyber metrics, threat alerts (rockets/UAVs). React + MapLibre + WebSockets + DuckDB. Planned satellite imagery + AI anomaly detection. Live: [radar.army](https://radar.army). |
| 🔗 [osint-worldview](https://github.com/amanimran786/osint-worldview) | **Full-stack compliance-first dashboard.** FastAPI + React + Celery + Postgres. 400+ feeds, AI summaries, multi-lang, market signals, geopolitical/infra layers. Native Tauri desktop app + PWA offline maps. Audit trails for investigators. Explicitly Palantir-style. |
| 🔗 [GeoSentinel](https://github.com/h9zdev/GeoSentinel) | Live flight/ship tracking, OLLAMA AI integration, TOR support, dark-web search. Built for local LLMs + privacy. |

---

### 🧠 Tier 2 — Entity Graph / Recursive Agent Layer

| Repo | What it is |
|------|-----------|
| 🔗 [OpenPlanter](https://github.com/ShinMegamiBoson/OpenPlanter) | **Community-edition Palantir for linking data.** Feed PDFs/CSVs/JSON (leaks, lobbying, contracts), auto-resolves entities, spawns recursive LLM agents, builds knowledge graphs, detects anomalies, generates reports. Terminal TUI or headless. Pair with any dashboard above for a full intel pipeline. |
| 🔗 [SpiderFoot + Neo4j](https://github.com/blacklanternsecurity/spiderfoot-neo4j) | Pipe SpiderFoot OSINT directly into a Neo4j graph — replicates Palantir's ontology linking. |
| 🔗 [NetworkX](https://github.com/networkx/networkx) | Lightweight Python graph library for prototyping entity relationships; CPU-only, no server. |
| 🔗 [Dashjoin](https://github.com/Dashjoin/dashjoin) | Low-code platform with linked-data ontology modeling — closest open-source analog to Palantir Foundry's ontology layer. |
| 🔗 [Neo4j Community](https://github.com/neo4j/neo4j) | Open-source graph database. Free edition handles large OSINT graphs; pair with SpiderFoot. |

---

### 🌐 Tier 3 — 3D Geospatial Rendering Engines

| Repo | What it is |
|------|-----------|
| 🔗 [CesiumJS](https://github.com/CesiumGS/cesium) | **The foundation.** WebGL 3D globe that streams massive geospatial datasets. Used in virtually every open-source globe project. Runs in-browser, minimal VRAM. |
| 🔗 [Satellite-Tracker](https://github.com/itsmedmd/satellite-tracker) | Ready-made CesiumJS viewer tracking 22,000+ satellites in real-time using TLE data. |
| 🔗 [GAIA](https://github.com/OSINT-TECHNOLOGIES/gaia) | Geospatial & Aerial Images Analyser — work with Sentinel and Google Earth Engine imagery in a web UI. |
| 🔗 [GeoAI](https://github.com/opengeos/geoai) | Python package for AI + geospatial analysis; add ML to your maps without heavy GPU load. |

---

### 📡 Tier 4 — Real-Time OSINT Feed Connectors

| Repo | What it is |
|------|-----------|
| 🔗 [ADSB-Flight-Map](https://github.com/ISmillex/adsb-flight-map) | Fetches live ADS-B aircraft data and renders it as 3D entities on a map. |
| 🔗 [Skies-ADSB](https://github.com/machineinteractive/skies-adsb) | Transforms your browser into a 3D air-traffic display; popular on Raspberry Pi setups. |
| 🔗 [SpiderFoot](https://github.com/smicallef/spiderfoot) | Automated OSINT across 200+ modules (domains, IPs, emails, social). Python-based, fully local. |
| 🔗 [theHarvester](https://github.com/laramies/theHarvester) | Email, subdomain, and name enumeration from public sources. Lightweight CLI. |
| 🔗 [Holehe](https://github.com/megadose/holehe) | Check if an email is attached to accounts on 120+ sites — core investigative layer. |
| 🔗 [Web-Check](https://github.com/lissy93/web-check) | One-click OSINT for any website: IP, DNS, SSL, headers, ports. Self-hostable. |
| 🔗 [Recon-ng](https://github.com/lanmaster53/recon-ng) | Modular reconnaissance framework with marketplace. Python-native, easy to extend. |

---

### 🤖 Tier 5 — Local AI & Agent Frameworks

| Repo | What it is |
|------|-----------|
| 🔗 [Ollama](https://github.com/ollama/ollama) | Run local LLMs (Llama 3, Qwen, Mistral) with AMD ROCm + CUDA support. Use `q4_k_m` quantised models to cut VRAM requirements. |
| 🔗 [LangChain](https://github.com/langchain-ai/langchain) | Framework for tool-augmented AI agents — build OSINT agents that call SpiderFoot, DuckDB, Cesium, etc. |
| 🔗 [Continue](https://github.com/continuedev/continue) | VS Code extension for local AI pair-programming with an Ollama backend. |

---

### 🗄️ Tier 6 — Storage & Query

| Repo | What it is |
|------|-----------|
| 🔗 [DuckDB](https://github.com/duckdb/duckdb) | Embedded analytical SQL — runs in-process, no server, extremely RAM-efficient. RADAR uses it natively. |
| 🔗 [Qdrant](https://github.com/qdrant/qdrant) | Vector search engine for semantic search over OSINT embeddings. Run in CPU mode. |
| 🔗 [Chroma](https://github.com/chroma-core/chroma) | Lightweight vector DB for prototyping AI-powered OSINT queries. |
| 🔗 [LanceDB](https://github.com/lancedb/lancedb) | Serverless vector DB with native DuckDB integration. |

---

### 🛡️ Tier 7 — OPSEC & Privacy Hardening

| Repo | What it is |
|------|-----------|
| 🔗 [Awesome-OSINT](https://github.com/jivoi/awesome-osint) | The OSINT bible — 500+ curated tools, scripts, and feeds. Bookmark this. |
| 🔗 [Awesome-Privacy](https://github.com/Lissy93/awesome-privacy) | 500+ privacy-respecting tools and self-hosted alternatives to everything. |
| 🔗 [cipher387/osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) | 1,000+ OSINT feeds and tools to pipe into the dashboards above. |
| 🔗 [Detection Labs for Palantir-Style Activity](https://github.com/VolkanSah/Detection-Labs-for-Palantir-Style-Activity) | Build defensive concepts and threat-hunting labs — learn what to detect. |
| 🔗 [OpenCTI](https://github.com/opencti-platform/opencti) | Full Cyber Threat Intelligence platform using STIX2 standards. Docker self-host. |
| 🔗 [MISP](https://github.com/MISP/MISP) | Mature, widely adopted threat intelligence sharing platform for indicators & threats. |
| 🔗 [IntelOwl](https://github.com/intelowlproject/IntelOwl) | Manage threat intelligence at scale with 100+ analyzers. API-first, Docker-ready. |

---

## 🚀 Starter Stack (Quick-Start)

```bash
# ── 1. Global intel dashboard (pick one) ─────────────────────
git clone https://github.com/koala73/worldmonitor
# or
git clone https://github.com/calesthio/Crucix && cd Crucix && docker compose up

# ── 2. OSINT data ingestion ───────────────────────────────────
git clone https://github.com/smicallef/spiderfoot
cd spiderfoot && pip install -r requirements.txt

# ── 3. Local AI runtime ───────────────────────────────────────
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b-instruct-q4_k_m   # ~2.1 GB VRAM

# ── 4. Storage layer ──────────────────────────────────────────
pip install duckdb lancedb                # in-process analytics + vectors

# ── 5. Entity / knowledge graph ───────────────────────────────
pip install networkx
# or full graph DB:
docker run -p 7474:7474 -p 7687:7687 neo4j:community

# ── 6. 3D globe rendering ─────────────────────────────────────
npm create vite@latest my-dashboard -- --template react
cd my-dashboard && npm install cesium @cesium/engine

# ── 7. Live flight layer (OpenSky Network — free, no key) ─────
# Fetch: https://opensky-network.org/api/states/all
# Feed into CesiumJS as point entities on the globe

# ── 8. Entity analysis pipeline ───────────────────────────────
git clone https://github.com/ShinMegamiBoson/OpenPlanter
# Feed PDF/CSV leaks → OpenPlanter → knowledge graph → WorldMonitor/RADAR
```

---

## 🔗 Recommended Pipeline

```
[SpiderFoot / Holehe / ADSB / AIS feeds]
          │
          ▼
     [DuckDB storage]
          │
          ├──► [OpenPlanter] → entity graph → [Neo4j / NetworkX]
          │
          ├──► [Ollama LLM agent] → AI briefs / anomaly detection
          │
          └──► [WorldMonitor / Crucix / RADAR] → 3D globe visualisation
```

---

## 🎯 AI "Vibe Prompt" (copy/paste into your local LLM)

```
You are an OSINT architect. I'm building a local, private intelligence dashboard.

Requirements:
- All data stays local; use only free/public OSINT feeds
- Target: track global threats (conflicts, flights, ships, cyber indicators)

Task: Generate a minimal working prototype that:
1. Ingests live ADS-B flight data from the OpenSky Network API
2. Stores results in DuckDB with schema: {icao24, callsign, lat, lon, alt, timestamp}
3. Renders aircraft as 3D entities on a CesiumJS globe (dark military theme)
4. Adds a Cmd+K command palette to filter/search entities
5. Pipes anomalies (unusual altitude drops, restricted airspace) to an Ollama LLM for
   a one-sentence threat brief

Output: requirements.txt, app.py or index.html, ingest.py, and a Dockerfile
```

---

## 📚 Master Reference Lists

- [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) — 500+ OSINT tools
- [Lissy93/awesome-privacy](https://github.com/Lissy93/awesome-privacy) — privacy hardening
- [cipher387/osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) — 1,000+ feeds & tools
- [BushidoUK/Open-source-tools-for-CTI](https://github.com/BushidoUK/Open-source-tools-for-CTI) — CTI tool list + OPSEC essentials
