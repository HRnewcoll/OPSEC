#!/usr/bin/env python3
"""
OPSEC Intel Terminal — Graph Engine
=====================================
NetworkX-backed entity relationship graph with:
  - pyvis interactive HTML visualisation (auto-layouts, physics)
  - Plotly Sankey / force-directed fallback (no pyvis required)
  - Community detection (Louvain/greedy modularity)
  - Centrality metrics (degree, betweenness, eigenvector, PageRank)
  - Shortest-path analysis between entities
  - Subgraph extraction by case, type, or depth
  - Export to GEXF, GraphML, and adjacency JSON
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Optional

import networkx as nx
import pandas as pd

# ── optional deps ──────────────────────────────────────────────────────
try:
    from pyvis.network import Network as PyvisNetwork
    HAS_PYVIS = True
except ImportError:
    HAS_PYVIS = False

try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


# ── type → visual style mapping ────────────────────────────────────────

NODE_STYLES: dict[str, dict] = {
    "ip":       {"color": "#00d4ff", "shape": "dot",      "size": 18, "icon": "🌐"},
    "domain":   {"color": "#4ec9b0", "shape": "diamond",  "size": 20, "icon": "🔗"},
    "email":    {"color": "#bc8cff", "shape": "triangle",  "size": 16, "icon": "✉️"},
    "username": {"color": "#e3b341", "shape": "star",      "size": 20, "icon": "👤"},
    "url":      {"color": "#58a6ff", "shape": "dot",       "size": 12, "icon": "🔗"},
    "org":      {"color": "#f0883e", "shape": "square",    "size": 22, "icon": "🏢"},
    "cve":      {"color": "#f85149", "shape": "hexagon",   "size": 24, "icon": "⚠️"},
    "malware":  {"color": "#ff0000", "shape": "hexagon",   "size": 26, "icon": "☣️"},
    "hash":     {"color": "#6e7681", "shape": "dot",       "size": 14, "icon": "#"},
    "person":   {"color": "#ffa657", "shape": "ellipse",   "size": 18, "icon": "🧑"},
    "phone":    {"color": "#7ee787", "shape": "dot",       "size": 14, "icon": "📞"},
}

EDGE_STYLES: dict[str, dict] = {
    "resolves_to":    {"color": "#4ec9b0", "width": 2, "dashes": False},
    "subdomain_of":   {"color": "#4ec9b0", "width": 1, "dashes": True},
    "owned_by":       {"color": "#f0883e", "width": 2, "dashes": False},
    "has_hostname":   {"color": "#00d4ff", "width": 1, "dashes": True},
    "belongs_to":     {"color": "#bc8cff", "width": 2, "dashes": False},
    "profile_on":     {"color": "#e3b341", "width": 1, "dashes": True},
    "vulnerable_to":  {"color": "#f85149", "width": 3, "dashes": False},
    "linked_to":      {"color": "#8b949e", "width": 1, "dashes": True},
}

_DEFAULT_NODE = {"color": "#8b949e", "shape": "dot", "size": 14, "icon": "●"}
_DEFAULT_EDGE = {"color": "#30363d", "width": 1,  "dashes": False}


# ── graph construction ─────────────────────────────────────────────────

def build_graph(
    entities_df: pd.DataFrame,
    relationships_df: pd.DataFrame,
) -> nx.DiGraph:
    """Build a NetworkX DiGraph from DuckDB DataFrames."""
    G = nx.DiGraph()

    for _, row in entities_df.iterrows():
        style = NODE_STYLES.get(str(row.get("type", "")).lower(), _DEFAULT_NODE)
        G.add_node(
            row["id"],
            label=str(row.get("value", row["id"]))[:40],
            type=str(row.get("type", "unknown")),
            value_full=str(row.get("value", "")),
            case_id=str(row.get("case_id", "") or ""),
            risk=float(row.get("risk_score", 0.0) or 0.0),
            first_seen=str(row.get("first_seen", "") or ""),
            **{k: v for k, v in style.items() if k != "icon"},
            icon=style.get("icon", "●"),
        )

    for _, row in relationships_df.iterrows():
        fid = row.get("from_id")
        tid = row.get("to_id")
        if fid in G.nodes and tid in G.nodes:
            style = EDGE_STYLES.get(str(row.get("rel_type", "")).lower(), _DEFAULT_EDGE)
            G.add_edge(
                fid, tid,
                rel_type=str(row.get("rel_type", "linked_to")),
                confidence=float(row.get("confidence", 1.0) or 1.0),
                case_id=str(row.get("case_id", "") or ""),
                **style,
            )

    return G


# ── subgraph helpers ───────────────────────────────────────────────────

def filter_by_type(G: nx.DiGraph, entity_types: list[str]) -> nx.DiGraph:
    types = {t.lower() for t in entity_types}
    nodes = [n for n, d in G.nodes(data=True) if d.get("type", "").lower() in types]
    return G.subgraph(nodes).copy()


def filter_by_case(G: nx.DiGraph, case_id: str) -> nx.DiGraph:
    nodes = [n for n, d in G.nodes(data=True) if d.get("case_id") == case_id]
    return G.subgraph(nodes).copy()


def ego_subgraph(G: nx.DiGraph, node_id: str, radius: int = 2) -> nx.DiGraph:
    """Return the neighbourhood of a node up to `radius` hops."""
    try:
        undirected = G.to_undirected()
        ego = nx.ego_graph(undirected, node_id, radius=radius)
        return G.subgraph(ego.nodes).copy()
    except Exception:
        return G.subgraph([node_id]).copy()


# ── metrics ────────────────────────────────────────────────────────────

def compute_metrics(G: nx.DiGraph) -> dict:
    if len(G.nodes) == 0:
        return {}

    ug = G.to_undirected()

    metrics: dict = {
        "nodes":        len(G.nodes),
        "edges":        len(G.edges),
        "density":      round(nx.density(G), 4),
        "components":   nx.number_weakly_connected_components(G),
    }

    if len(G.nodes) >= 2:
        try:
            deg_centrality = nx.degree_centrality(G)
            top_degree = sorted(deg_centrality.items(), key=lambda x: x[1], reverse=True)[:5]
            metrics["top_degree"] = [
                {"id": nid, "label": G.nodes[nid].get("label", nid), "score": round(s, 4)}
                for nid, s in top_degree
            ]
        except Exception:
            pass

        try:
            pr = nx.pagerank(G, max_iter=100)
            top_pr = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:5]
            metrics["top_pagerank"] = [
                {"id": nid, "label": G.nodes[nid].get("label", nid), "score": round(s, 4)}
                for nid, s in top_pr
            ]
        except Exception:
            pass

        try:
            between = nx.betweenness_centrality(G, k=min(len(G.nodes), 50))
            top_between = sorted(between.items(), key=lambda x: x[1], reverse=True)[:5]
            metrics["top_betweenness"] = [
                {"id": nid, "label": G.nodes[nid].get("label", nid), "score": round(s, 4)}
                for nid, s in top_between
            ]
        except Exception:
            pass

    # Community detection
    try:
        communities = list(nx.community.greedy_modularity_communities(ug))
        metrics["communities"] = len(communities)
        metrics["largest_community"] = max(len(c) for c in communities) if communities else 0
    except Exception:
        metrics["communities"] = None

    return metrics


def shortest_path(G: nx.DiGraph, src_id: str, dst_id: str) -> list[str]:
    """Return node IDs on shortest path, or [] if none."""
    try:
        return nx.shortest_path(G.to_undirected(), src_id, dst_id)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


# ── pyvis renderer ─────────────────────────────────────────────────────

def render_pyvis(
    G: nx.DiGraph,
    height: str = "600px",
    bgcolor: str = "#0a0e1a",
    physics: bool = True,
) -> Optional[str]:
    """
    Render the graph as a self-contained HTML string via pyvis.
    Returns None if pyvis is not installed.
    """
    if not HAS_PYVIS:
        return None

    net = PyvisNetwork(
        height=height,
        width="100%",
        bgcolor=bgcolor,
        font_color="#e6edf3",
        directed=True,
    )
    net.set_options(json.dumps({
        "physics": {
            "enabled": physics,
            "barnesHut": {
                "gravitationalConstant": -8000,
                "springLength": 180,
                "springConstant": 0.04,
                "damping": 0.09,
                "avoidOverlap": 0.2,
            },
            "stabilization": {"iterations": 150},
        },
        "edges": {
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.7}},
            "smooth": {"type": "curvedCW", "roundness": 0.2},
            "font": {"size": 10, "color": "#8b949e", "align": "middle"},
        },
        "nodes": {
            "font": {"size": 12, "color": "#e6edf3"},
            "borderWidth": 2,
            "borderWidthSelected": 4,
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 100,
            "navigationButtons": True,
            "keyboard": True,
        },
    }))

    for node_id, data in G.nodes(data=True):
        risk  = data.get("risk", 0.0)
        color = data.get("color", "#8b949e")
        # Overlay risk: tint towards red for high-risk nodes
        if risk >= 0.7:
            color = "#f85149"
        elif risk >= 0.4:
            color = "#e3b341"

        tooltip = (
            f"<b>{data.get('icon', '●')} {data.get('label', node_id)}</b><br>"
            f"Type: {data.get('type', '?')}<br>"
            f"Risk: {risk:.2f}<br>"
            f"Case: {data.get('case_id', '—')}<br>"
            f"First seen: {data.get('first_seen', '—')[:10]}"
        )
        net.add_node(
            node_id,
            label=data.get("label", node_id),
            title=tooltip,
            color={"background": color, "border": "#21262d",
                   "highlight": {"background": "#ffffff", "border": color}},
            size=data.get("size", 14),
            shape=data.get("shape", "dot"),
            mass=1 + risk * 2,
        )

    for src, dst, edata in G.edges(data=True):
        style = EDGE_STYLES.get(edata.get("rel_type", ""), _DEFAULT_EDGE)
        net.add_edge(
            src, dst,
            title=edata.get("rel_type", "linked_to"),
            color=style["color"],
            width=style["width"],
            dashes=style.get("dashes", False),
            arrows="to",
        )

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        net.save_graph(f.name)
        return Path(f.name).read_text()


# ── plotly fallback renderer ───────────────────────────────────────────

def render_plotly(G: nx.DiGraph):
    """
    Render graph with Plotly (works even without pyvis).
    Returns a plotly Figure.
    """
    if not HAS_PLOTLY:
        return None
    if len(G.nodes) == 0:
        import plotly.graph_objects as _go
        return _go.Figure()

    import plotly.graph_objects as _go

    pos = nx.spring_layout(G.to_undirected(), seed=42, k=2.5 / max(len(G.nodes) ** 0.5, 1))

    edge_x, edge_y = [], []
    for src, dst in G.edges():
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = _go.Scatter(
        x=edge_x, y=edge_y,
        line={"width": 1, "color": "#30363d"},
        hoverinfo="none",
        mode="lines",
    )

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    for nid, data in G.nodes(data=True):
        x, y = pos[nid]
        node_x.append(x)
        node_y.append(y)
        risk  = data.get("risk", 0.0)
        color = "#f85149" if risk >= 0.7 else "#e3b341" if risk >= 0.4 else data.get("color", "#00d4ff")
        node_color.append(color)
        node_size.append(max(10, data.get("size", 14)))
        node_text.append(
            f"<b>{data.get('icon', '')} {data.get('label', nid)}</b><br>"
            f"Type: {data.get('type', '?')}<br>"
            f"Risk: {risk:.2f}"
        )

    node_trace = _go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=[G.nodes[n].get("label", n)[:20] for n in G.nodes()],
        textposition="top center",
        textfont={"size": 10, "color": "#e6edf3"},
        hovertext=node_text,
        marker={
            "size": node_size,
            "color": node_color,
            "line": {"width": 1.5, "color": "#0a0e1a"},
        },
    )

    fig = _go.Figure(
        data=[edge_trace, node_trace],
        layout=_go.Layout(
            paper_bgcolor="#0a0e1a",
            plot_bgcolor="#0a0e1a",
            font={"color": "#e6edf3"},
            showlegend=False,
            hovermode="closest",
            xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
            margin={"l": 10, "r": 10, "t": 10, "b": 10},
        ),
    )
    return fig


# ── export ─────────────────────────────────────────────────────────────

def export_gexf(G: nx.DiGraph, path: Path):
    nx.write_gexf(G, str(path))


def export_graphml(G: nx.DiGraph, path: Path):
    nx.write_graphml(G, str(path))


def to_adjacency_json(G: nx.DiGraph) -> dict:
    return {
        "nodes": [
            {"id": n, **{k: v for k, v in d.items()
                         if not callable(v) and k not in ("color",)}}
            for n, d in G.nodes(data=True)
        ],
        "edges": [
            {"from": u, "to": v, "rel_type": d.get("rel_type")}
            for u, v, d in G.edges(data=True)
        ],
    }
