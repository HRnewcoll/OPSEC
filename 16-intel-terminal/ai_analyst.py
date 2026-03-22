#!/usr/bin/env python3
"""
OPSEC Intel Terminal — AI Analyst (Ollama)
==========================================
Local LLM integration via Ollama for:
  - Automated entity risk assessment
  - IOC classification & pivot suggestions
  - Free-form threat intelligence queries (RAG over case entities)
  - Automated intelligence report drafting
  - CVE & malware context enrichment
  - Interactive analyst chat with case context injection

Ollama must be running locally:
  curl -fsSL https://ollama.com/install.sh | sh
  ollama serve
  ollama pull llama3.2:3b-instruct-q4_K_M   # lightweight, fast
  ollama pull qwen2.5:7b-instruct-q4_K_M    # better reasoning
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime
from typing import Iterator, Optional

# ── Ollama endpoint ────────────────────────────────────────────────────
OLLAMA_BASE = "http://localhost:11434"

# Default model; overridden by model_selector() in app.py
DEFAULT_MODEL = "llama3.2:3b-instruct"

# ── recommended models ─────────────────────────────────────────────────
RECOMMENDED_MODELS = [
    {
        "name":    "llama3.2:3b-instruct",
        "pull":    "ollama pull llama3.2:3b-instruct",
        "size_gb": 2.0,
        "note":    "Fast, low RAM — good for quick analysis",
    },
    {
        "name":    "llama3.2:3b-instruct-q4_K_M",
        "pull":    "ollama pull llama3.2:3b-instruct-q4_K_M",
        "size_gb": 2.1,
        "note":    "Quantised — best for constrained hardware",
    },
    {
        "name":    "qwen2.5:7b-instruct",
        "pull":    "ollama pull qwen2.5:7b-instruct",
        "size_gb": 4.7,
        "note":    "Better reasoning; good for report generation",
    },
    {
        "name":    "mistral:7b-instruct",
        "pull":    "ollama pull mistral:7b-instruct",
        "size_gb": 4.1,
        "note":    "Strong for structured output tasks",
    },
    {
        "name":    "gemma2:2b-instruct",
        "pull":    "ollama pull gemma2:2b-instruct",
        "size_gb": 1.6,
        "note":    "Smallest option; minimal RAM",
    },
]


# ── helpers ────────────────────────────────────────────────────────────

def _http_post(url: str, body: dict, timeout: int = 120) -> Optional[dict]:
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def is_ollama_running() -> bool:
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def list_models() -> list[str]:
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=5) as r:
            data = json.loads(r.read())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


# ── system prompts ─────────────────────────────────────────────────────

_ANALYST_SYSTEM = """You are a senior cyber threat intelligence analyst with expertise in OSINT,
network forensics, and adversary tracking. You are concise, precise, and structured.
Always respond in Markdown. Highlight IOCs (IPs, domains, hashes, CVEs) in backticks.
When uncertain, say so explicitly — never hallucinate threat intel."""

_IOC_EXTRACT_SYSTEM = """You are an IOC extraction engine. Extract all indicators of compromise
from the provided text and return ONLY a JSON array in this exact format:
[{"type": "ip|domain|hash|email|url|cve", "value": "...", "confidence": 0.0-1.0}]
Return [] if none found. No explanation, no markdown, only valid JSON."""

_RISK_SYSTEM = """You are a threat scoring engine. Given entity metadata, output ONLY a JSON object:
{"risk_score": 0.0-1.0, "risk_label": "Low|Medium|High|Critical",
 "reasons": ["reason1", "reason2"], "pivots": ["suggested next investigation step"]}
No explanation, only valid JSON."""

_REPORT_SYSTEM = """You are a senior intelligence analyst writing a formal threat intelligence report.
Be factual, cite specific IOCs, and structure your report professionally.
Use Markdown with clear sections: Executive Summary, Key Findings, Entities, Recommendations."""


# ── core completion ────────────────────────────────────────────────────

def complete(
    prompt: str,
    model: str = DEFAULT_MODEL,
    system: str = _ANALYST_SYSTEM,
    temperature: float = 0.3,
    max_tokens: int = 2048,
) -> str:
    """Single-shot completion. Returns response text or error message."""
    if not is_ollama_running():
        return "⚠️ Ollama is not running. Start it with: `ollama serve`"

    body = {
        "model":   model,
        "prompt":  prompt,
        "system":  system,
        "stream":  False,
        "options": {
            "temperature":   temperature,
            "num_predict":   max_tokens,
            "num_ctx":       4096,
            "repeat_penalty": 1.1,
        },
    }
    result = _http_post(f"{OLLAMA_BASE}/api/generate", body)
    if result and "error" not in result:
        return result.get("response", "")
    return f"⚠️ Ollama error: {result.get('error', 'unknown error')}"


def stream_complete(
    prompt: str,
    model: str = DEFAULT_MODEL,
    system: str = _ANALYST_SYSTEM,
    temperature: float = 0.3,
) -> Iterator[str]:
    """Streaming completion — yields tokens one by one."""
    if not is_ollama_running():
        yield "⚠️ Ollama is not running. Start it with: `ollama serve`"
        return

    import urllib.request
    body = json.dumps({
        "model":   model,
        "prompt":  prompt,
        "system":  system,
        "stream":  True,
        "options": {"temperature": temperature, "num_ctx": 4096},
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/generate", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            for line in resp:
                line = line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    if token:
                        yield token
                    if chunk.get("done"):
                        break
                except Exception:
                    continue
    except Exception as e:
        yield f"\n⚠️ Stream error: {e}"


# ── specialised tasks ──────────────────────────────────────────────────

def analyse_entity(
    entity_type: str,
    value: str,
    metadata: dict,
    model: str = DEFAULT_MODEL,
) -> str:
    """
    Produce a threat intelligence assessment for a single entity.
    Returns Markdown-formatted analysis.
    """
    meta_str = json.dumps(metadata, indent=2, default=str)[:1500]
    prompt = f"""Analyse this {entity_type.upper()} entity for threat intelligence value:

**Value:** `{value}`
**Metadata:**
```json
{meta_str}
```

Provide:
1. Brief summary (2-3 sentences)
2. Threat indicators (if any)
3. Recommended pivot points for further investigation
4. Risk level: Low / Medium / High / Critical
"""
    return complete(prompt, model, _ANALYST_SYSTEM)


def score_risk(
    entity_type: str,
    value: str,
    metadata: dict,
    model: str = DEFAULT_MODEL,
) -> dict:
    """Return AI-generated risk score as a dict."""
    meta_str = json.dumps(metadata, default=str)[:800]
    prompt = f"Entity type: {entity_type}\nValue: {value}\nMetadata: {meta_str}"
    raw = complete(prompt, model, _RISK_SYSTEM, temperature=0.1)
    # Extract JSON
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    return {"risk_score": 0.0, "risk_label": "Unknown",
            "reasons": [], "pivots": [], "raw": raw}


def extract_iocs(text: str, model: str = DEFAULT_MODEL) -> list[dict]:
    """
    Extract IOCs from arbitrary text using the LLM.
    Returns list of {type, value, confidence} dicts.
    """
    prompt = f"Extract all IOCs from this text:\n\n{text[:3000]}"
    raw = complete(prompt, model, _IOC_EXTRACT_SYSTEM, temperature=0.0, max_tokens=512)
    # Try to parse JSON array
    m = re.search(r"\[.*?\]", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    return []


def generate_report(
    case_name: str,
    entities_summary: str,
    events_summary: str,
    model: str = DEFAULT_MODEL,
) -> str:
    """Generate a formal threat intelligence report for a case."""
    prompt = f"""Generate a threat intelligence report for case: **{case_name}**

## Entities collected:
{entities_summary[:2000]}

## Key events (timeline):
{events_summary[:1000]}

Write a professional, structured report with:
- Executive Summary
- Key Findings & IOCs
- Threat Actor Hypothesis (if data supports it)
- Network / Infrastructure Analysis
- Recommendations

Use Markdown formatting. Be specific and technical."""
    return complete(prompt, model, _REPORT_SYSTEM, temperature=0.4, max_tokens=3000)


def ask_with_context(
    question: str,
    entity_context: str,
    model: str = DEFAULT_MODEL,
) -> str:
    """Answer an analyst's question with entity context injected."""
    prompt = f"""## Intelligence Context
{entity_context[:2000]}

## Analyst Question
{question}

Answer based on the provided context. If you need to speculate beyond the data, say so clearly."""
    return complete(prompt, model, _ANALYST_SYSTEM)


def enrich_cve(cve_id: str, model: str = DEFAULT_MODEL) -> str:
    """Get a plain-English explanation of a CVE from the LLM."""
    prompt = f"""Explain {cve_id} for a security analyst:
1. Affected software and versions
2. Attack vector and exploitability (CVSS)
3. Impact if exploited
4. Known exploitation in the wild
5. Recommended mitigations

Be concise (5-8 bullet points per section)."""
    return complete(prompt, model, _ANALYST_SYSTEM)


def suggest_pivots(
    entity_type: str,
    value: str,
    model: str = DEFAULT_MODEL,
) -> list[str]:
    """Suggest next OSINT pivot steps for an entity."""
    prompt = f"""I'm investigating a {entity_type}: `{value}`.

List 5-8 specific OSINT pivot steps to investigate further.
Return ONLY a JSON array of strings: ["step1", "step2", ...]
No explanation, only valid JSON."""
    raw = complete(prompt, model, _ANALYST_SYSTEM, temperature=0.2, max_tokens=256)
    m = re.search(r"\[.*?\]", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    # Fallback: split lines
    lines = [l.strip().lstrip("•-0123456789. ") for l in raw.splitlines()
             if l.strip() and len(l.strip()) > 10]
    return lines[:8]


# ── chat history helper ────────────────────────────────────────────────

class AnalystChat:
    """Simple multi-turn chat session with Ollama (context maintained in memory)."""

    def __init__(self, model: str = DEFAULT_MODEL, case_context: str = ""):
        self.model   = model
        self.history: list[dict] = []
        if case_context:
            self.history.append({
                "role": "user",
                "content": f"Intelligence context for this session:\n{case_context}"
            })
            self.history.append({
                "role": "assistant",
                "content": "Understood. I've reviewed the case context. Ready for your queries."
            })

    def chat(self, message: str) -> str:
        """Send a message and get a response (maintains history)."""
        if not is_ollama_running():
            return "⚠️ Ollama is not running."

        self.history.append({"role": "user", "content": message})

        body = {
            "model":    self.model,
            "messages": [{"role": "system", "content": _ANALYST_SYSTEM}]
                         + self.history,
            "stream":   False,
            "options":  {"temperature": 0.3, "num_ctx": 4096},
        }
        result = _http_post(f"{OLLAMA_BASE}/api/chat", body)
        if result and "error" not in result:
            reply = result.get("message", {}).get("content", "")
            self.history.append({"role": "assistant", "content": reply})
            return reply
        return f"⚠️ Error: {result.get('error', 'unknown') if result else 'no response'}"

    def clear(self):
        self.history.clear()
