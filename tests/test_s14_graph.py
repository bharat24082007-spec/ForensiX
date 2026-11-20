"""
Tests for Section S14: Investigation Relationship Graph Module.
Covers:
- NetworkX graph construction from evidence, IOCs, events, and findings
- Red entity node color highlighting for suspicious/malicious indicators
- Dynamic entity filtering by node type (IP, Domain, User, Evidence)
- Graph topological metrics computation (density, degrees, suspicious counts)
- Route access control: @case_member_required (404 for non-members)
- JSON data API structure for vis-network canvas rendering
"""

import io
from pathlib import Path
import pytest
from werkzeug.datastructures import FileStorage

from app import create_app
from app.db import init_db, query_db, execute_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case, assign_member
from app.modules.evidence.service import intake_evidence
from app.modules.graph.service import build_case_graph


@pytest.fixture
def graph_env(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    master_key = data_dir / "keys" / "master.key"
    work_dir = data_dir / "work"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(data_dir / "keys"),
        "LOGS_DIR": str(data_dir / "logs"),
        "WORK_DIR": str(work_dir),
        "DATABASE_PATH": str(db_path),
        "MASTER_KEY_PATH": str(master_key),
        "WTF_CSRF_ENABLED": False,
        "ALLOW_LAN": False,
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "test_secret_key_forensix_section14_graph",
    })

    with app.app_context():
        init_db(db_path)
        lead_id = create_user("Lead Investigator", "lead_graph", "Lead", "LeadPass123!@#")
        analyst_id = create_user("Analyst Investigator", "analyst_graph", "Analyst", "AnalystPass123!")
        outsider_id = create_user("Outsider User", "outsider_graph", "Analyst", "OutsiderPass123!")

        case_id = create_case("Graph Relationship Incident", "Investigating threat actor network", "High", lead_id)
        assign_member(case_id, analyst_id, lead_id)

    return {
        "app": app,
        "lead_id": lead_id,
        "analyst_id": analyst_id,
        "outsider_id": outsider_id,
        "case_id": case_id,
        "vault_dir": vault_dir,
        "work_dir": work_dir,
    }


def test_graph_construction_with_networkx(graph_env):
    """Verify that nodes and relationships are correctly modeled with NetworkX."""
    app = graph_env["app"]
    case_id = graph_env["case_id"]
    lead_id = graph_env["lead_id"]
    vault_dir = graph_env["vault_dir"]
    work_dir = graph_env["work_dir"]

    with app.app_context():
        # Ingest evidence
        storage = FileStorage(stream=io.BytesIO(b"evidence raw"), filename="pcap1.pcap")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "pcap")

        # Ingest IOCs
        execute_db(
            """INSERT INTO iocs (case_id, type, value, first_evidence_id, verdict, source)
               VALUES (?, 'domain', 'c2-beacon.xyz', ?, 'Known malicious', 'unit_test')""",
            (case_id, ev_id),
        )

        # Ingest Events (user -> ip login, and src_ip -> dst_ip connection)
        execute_db(
            """INSERT INTO events (case_id, evidence_id, line_no, timestamp_utc, source_type, src_ip, dst_ip, username, action, raw_line)
               VALUES (?, ?, 1, '2026-10-14T02:00:00Z', 'pcap', '198.51.100.22', '203.0.113.88', 'compromised_user', 'TCP_SYN', 'packet')""",
            (case_id, ev_id),
        )

        data = build_case_graph(case_id)
        nodes = data["nodes"]
        edges = data["edges"]
        types = {n["type"] for n in nodes}

        assert "evidence" in types
        assert "domain" in types
        assert "ip" in types
        assert "user" in types

        # Check edges
        edge_labels = {e["label"] for e in edges}
        assert "FOUND_IN" in edge_labels or "CONNECTS_TO" in edge_labels or "LOGGED_IN_FROM" in edge_labels


def test_suspicious_entities_highlighted_red(graph_env):
    """Verify that malicious indicators and finding IPs turn red (#ef4444)."""
    app = graph_env["app"]
    case_id = graph_env["case_id"]
    lead_id = graph_env["lead_id"]

    with app.app_context():
        # Insert a finding for 198.51.100.99
        execute_db(
            """INSERT INTO findings (case_id, evidence_id, rule, severity, src_ip, count, evidence_lines, status)
               VALUES (?, NULL, 'BRUTE_FORCE', 'High', '198.51.100.99', 10, '1', 'Open')""",
            (case_id,),
        )
        # Insert normal IP and suspicious IP in IOCs
        execute_db(
            """INSERT INTO iocs (case_id, type, value, verdict, source)
               VALUES (?, 'ipv4', '198.51.100.99', 'Known malicious', 'unit_test')""",
            (case_id,),
        )
        execute_db(
            """INSERT INTO iocs (case_id, type, value, verdict, source)
               VALUES (?, 'ipv4', '203.0.113.10', 'Known good', 'unit_test')""",
            (case_id,),
        )

        data = build_case_graph(case_id)
        node_map = {n["raw_value"]: n for n in data["nodes"]}

        assert node_map["198.51.100.99"]["color"] == "#ef4444"  # Red
        assert node_map["203.0.113.10"]["color"] == "#3b82f6"  # Blue


def test_graph_node_type_filtering(graph_env):
    """Verify filtering by node type (e.g. only IPs and Users) omits other entity classes."""
    app = graph_env["app"]
    case_id = graph_env["case_id"]
    lead_id = graph_env["lead_id"]
    vault_dir = graph_env["vault_dir"]
    work_dir = graph_env["work_dir"]

    with app.app_context():
        storage = FileStorage(stream=io.BytesIO(b"evidence"), filename="doc.pdf")
        ev_id = intake_evidence(case_id, storage, lead_id, vault_dir, work_dir, "doc.pdf")
        execute_db(
            """INSERT INTO iocs (case_id, type, value, verdict, source)
               VALUES (?, 'domain', 'malicious.biz', 'Suspicious', 'test')""",
            (case_id,),
        )
        execute_db(
            """INSERT INTO events (case_id, evidence_id, timestamp_utc, source_type, src_ip, username, action)
               VALUES (?, ?, '2026-10-14T01:00:00Z', 'auth.log', '198.51.100.5', 'admin_user', 'LOGIN')""",
            (case_id, ev_id),
        )

        # Filter only 'ip' and 'user'
        filtered_data = build_case_graph(case_id, node_types=["ip", "user"])
        node_types = {n["type"] for n in filtered_data["nodes"]}

        assert "ip" in node_types or "user" in node_types
        assert "domain" not in node_types
        assert "evidence" not in node_types


def test_graph_routes_and_access_control(graph_env):
    """Verify access controls: non-member gets 404, assigned member gets 200, JSON API works."""
    app = graph_env["app"]
    case_id = graph_env["case_id"]
    analyst_id = graph_env["analyst_id"]
    outsider_id = graph_env["outsider_id"]

    client = app.test_client()

    # 1. Outsider gets 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(outsider_id)
        sess["_fresh"] = True
    resp_out = client.get(f"/cases/{case_id}/graph")
    assert resp_out.status_code == 404

    # 2. Member gets 200 HTML view
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True
    resp_mem = client.get(f"/cases/{case_id}/graph")
    assert resp_mem.status_code == 200
    assert b"Relationship Graph" in resp_mem.data

    # 3. JSON data endpoint
    resp_json = client.get(f"/cases/{case_id}/graph/data?types=ip,domain")
    assert resp_json.status_code == 200
    json_data = resp_json.get_json()
    assert "nodes" in json_data
    assert "edges" in json_data
    assert "metrics" in json_data
    assert "density" in json_data["metrics"]
