"""
ForensiX Investigation Relationship Graph Service.
Constructs multi-entity relationship graph using NetworkX:
- Entities (nodes): IP addresses, domains, usernames, and evidence files.
- Relationships (edges): LOGGED_IN_FROM, CONNECTS_TO, FOUND_IN, FLAGGED_IN.
- Graph analytics: node degrees, suspicious highlighting, cluster statistics.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
import networkx as nx

from app.db import query_db
from app.modules.iocs.service import defang


def build_case_graph(case_id: int, node_types: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Construct a NetworkX Graph from case evidence, events, findings, and IOCs.
    Returns serialized graph dict with nodes, edges, and topological metrics.
    """
    G = nx.DiGraph()

    allowed_types = set(node_types) if node_types else {"ip", "domain", "user", "evidence"}

    # 1. Gather all findings to know which IPs or evidence items are suspicious/compromised
    findings_rows = [
        dict(r) for r in query_db(
            "SELECT rule, severity, src_ip, evidence_id FROM findings WHERE case_id = ?",
            (case_id,),
        )
    ]
    suspicious_ips: Set[str] = set()
    for f in findings_rows:
        if f.get("src_ip"):
            suspicious_ips.add(f["src_ip"])

    # 2. Gather Evidence Nodes
    evidence_rows = [
        dict(r) for r in query_db(
            "SELECT id, display_name, sha256, integrity_status FROM evidence WHERE case_id = ? AND withdrawn = 0",
            (case_id,),
        )
    ]
    for ev in evidence_rows:
        node_id = f"ev_{ev['id']}"
        is_compromised = (ev["integrity_status"] == "COMPROMISED")
        if "evidence" in allowed_types:
            G.add_node(
                node_id,
                label=ev["display_name"],
                type="evidence",
                raw_value=ev["display_name"],
                evidence_id=ev["id"],
                sha256=ev["sha256"][:16] + "...",
                color="#ef4444" if is_compromised else "#f59e0b",
                size=22,
            )

    # 3. Gather IOC Nodes (IPs, Domains)
    ioc_rows = [
        dict(r) for r in query_db(
            "SELECT id, type, value, verdict, first_evidence_id FROM iocs WHERE case_id = ?",
            (case_id,),
        )
    ]
    for ioc in ioc_rows:
        ioc_type = ioc["type"]
        val = ioc["value"]
        verdict = ioc["verdict"]
        is_bad = verdict in ("Suspicious", "Known malicious") or val in suspicious_ips

        if ioc_type == "ipv4" and "ip" in allowed_types:
            node_id = f"ip_{val}"
            if not G.has_node(node_id):
                G.add_node(
                    node_id,
                    label=defang(val, "ipv4"),
                    type="ip",
                    raw_value=val,
                    verdict=verdict,
                    color="#ef4444" if is_bad else "#3b82f6",
                    size=18,
                )
            if ioc.get("first_evidence_id") and "evidence" in allowed_types:
                ev_node = f"ev_{ioc['first_evidence_id']}"
                if G.has_node(ev_node):
                    G.add_edge(node_id, ev_node, label="FOUND_IN", color="#94a3b8")

        elif ioc_type == "domain" and "domain" in allowed_types:
            node_id = f"dom_{val}"
            if not G.has_node(node_id):
                G.add_node(
                    node_id,
                    label=defang(val, "domain"),
                    type="domain",
                    raw_value=val,
                    verdict=verdict,
                    color="#ef4444" if is_bad else "#8b5cf6",
                    size=18,
                )
            if ioc.get("first_evidence_id") and "evidence" in allowed_types:
                ev_node = f"ev_{ioc['first_evidence_id']}"
                if G.has_node(ev_node):
                    G.add_edge(node_id, ev_node, label="FOUND_IN", color="#94a3b8")

    # 4. Gather Events Nodes (Users, src_ip -> dst_ip connections, logins)
    event_rows = [
        dict(r) for r in query_db(
            "SELECT src_ip, dst_ip, username, evidence_id, action FROM events WHERE case_id = ? LIMIT 500",
            (case_id,),
        )
    ]
    for ev in event_rows:
        user = ev.get("username")
        src_ip = ev.get("src_ip")
        dst_ip = ev.get("dst_ip")

        user_node = None
        if user and user not in ("-", "unknown", "root") and "user" in allowed_types:
            user_node = f"usr_{user}"
            if not G.has_node(user_node):
                G.add_node(
                    user_node,
                    label=user,
                    type="user",
                    raw_value=user,
                    color="#10b981",
                    size=20,
                )

        src_node = None
        if src_ip and src_ip not in ("127.0.0.1", "0.0.0.0") and "ip" in allowed_types:
            src_node = f"ip_{src_ip}"
            if not G.has_node(src_node):
                is_bad = src_ip in suspicious_ips
                G.add_node(
                    src_node,
                    label=defang(src_ip, "ipv4"),
                    type="ip",
                    raw_value=src_ip,
                    color="#ef4444" if is_bad else "#3b82f6",
                    size=18,
                )

        dst_node = None
        if dst_ip and dst_ip not in ("127.0.0.1", "0.0.0.0") and "ip" in allowed_types:
            dst_node = f"ip_{dst_ip}"
            if not G.has_node(dst_node):
                is_bad = dst_ip in suspicious_ips
                G.add_node(
                    dst_node,
                    label=defang(dst_ip, "ipv4"),
                    type="ip",
                    raw_value=dst_ip,
                    color="#ef4444" if is_bad else "#3b82f6",
                    size=18,
                )

        # Edges
        if user_node and src_node:
            if not G.has_edge(user_node, src_node):
                G.add_edge(user_node, src_node, label="LOGGED_IN_FROM", color="#64748b")

        if src_node and dst_node and src_node != dst_node:
            if not G.has_edge(src_node, dst_node):
                G.add_edge(src_node, dst_node, label="CONNECTS_TO", color="#cbd5e1")

    # Serialize NetworkX graph into node/edge lists for vis-network
    nodes_out = []
    suspicious_count = 0
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("color") == "#ef4444":
            suspicious_count += 1
        nodes_out.append({
            "id": node_id,
            "label": attrs.get("label", node_id),
            "type": attrs.get("type", "unknown"),
            "raw_value": attrs.get("raw_value", ""),
            "color": attrs.get("color", "#3b82f6"),
            "size": attrs.get("size", 18),
            "degree": G.degree(node_id),
        })

    edges_out = []
    for u, v, attrs in G.edges(data=True):
        edges_out.append({
            "from": u,
            "to": v,
            "label": attrs.get("label", ""),
            "color": attrs.get("color", "#94a3b8"),
        })

    # Network topological metrics
    density = round(nx.density(G), 3) if len(G) > 1 else 0.0

    return {
        "nodes": nodes_out,
        "edges": edges_out,
        "metrics": {
            "total_nodes": len(nodes_out),
            "total_edges": len(edges_out),
            "suspicious_nodes": suspicious_count,
            "density": density,
        },
    }
