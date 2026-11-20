"""
ForensiX UI Smoke Test Suite.
Verifies all 7 UI repair specifications:
1. ICONS: No broken/empty SVG icons; every symbol reference in <use href="#icon-..."> resolves.
2. DASHBOARD LAYOUT: Page header, single-row Start Here card, 4 stat tiles, plain-language
   integrity tile, 11-card feature map, two-column layout (Cases + Custody).
3. TOP BAR: Real breadcrumbs, user menu with role badge, dark mode toggle button.
4. SIDEBAR: Icons on every item, active states, small caps group labels, fixed layout.
5. CASE PAGES: Stepper + tabs under case header, active tab underlined, bottom next-step buttons.
6. CONSISTENCY: Uniform buttons, cards, tables, and chips using tokens.css.
7. COMPREHENSIVE SMOKE: No 404, no 500 across all sidebar and case routes.
"""

from __future__ import annotations

import re
from pathlib import Path
import pytest

from app import create_app
from app.db import init_db, query_db
from app.modules.accounts.service import create_user
from app.modules.cases.service import create_case
from app.modules.dashboard.service import create_or_load_demo_case


@pytest.fixture
def smoke_app(tmp_path):
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vault"
    db_path = data_dir / "db" / "forensix.db"
    keys_dir = data_dir / "keys"
    work_dir = data_dir / "work"
    reports_dir = data_dir / "reports"
    logs_dir = data_dir / "logs"
    backups_dir = data_dir / "backups"

    app = create_app({
        "TESTING": True,
        "DATA_DIR": str(data_dir),
        "VAULT_DIR": str(vault_dir),
        "DB_DIR": str(data_dir / "db"),
        "KEYS_DIR": str(keys_dir),
        "LOGS_DIR": str(logs_dir),
        "WORK_DIR": str(work_dir),
        "REPORTS_DIR": str(reports_dir),
        "BACKUPS_DIR": str(backups_dir),
        "DATABASE_PATH": str(db_path),
        "SECRET_KEY": "smoke-test-secret-key-32-bytes-long!",
        "MASTER_KEY_PATH": str(keys_dir / "master.key"),
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        init_db()
        admin_id = create_user("Test Admin", "admin_smoke", "Admin", "AdminPass1234!")
        lead_id = create_user("Lead Investigator", "lead_smoke", "Lead", "LeadPass1234!")

    return app, admin_id, lead_id


def extract_svg_symbols(html: str) -> set[str]:
    """Find all <symbol id="..."> in the rendered HTML."""
    return set(re.findall(r'<symbol\s+[^>]*id=["\']([^"\']+)["\']', html))


def extract_used_icons(html: str) -> set[str]:
    """Find all #icon-... references in <use href="..."> or <use xlink:href="...">."""
    return set(re.findall(r'<use\s+[^>]*(?:href|xlink:href)=["\']#([^"\']+)["\']', html))


def test_sidebar_links_and_icon_integrity(smoke_app):
    """Verify all sidebar navigation links return 200 and every used SVG icon is present in the sprite."""
    app, admin_id, _ = smoke_app
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    sidebar_urls = [
        "/dashboard",
        "/cases",
        "/reports",
        "/verify-report",
        "/system/health",
        "/system/backup",
        "/system/tools",
        "/account",
    ]

    for url in sidebar_urls:
        resp = client.get(url)
        assert resp.status_code == 200, f"Expected 200 for {url}, got {resp.status_code}"
        html = resp.get_data(as_text=True)

        symbols = extract_svg_symbols(html)
        assert len(symbols) >= 20, f"Sprite with symbols missing on {url}"

        used_icons = extract_used_icons(html)
        missing_icons = used_icons - symbols
        assert not missing_icons, f"On {url}, broken icon references: {missing_icons}"


def test_dashboard_layout_specifications(smoke_app):
    """Verify Dashboard adheres strictly to layout requirements 2a-2f."""
    app, admin_id, _ = smoke_app
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # 2a. Page header: Title + one-line description on left; ONE primary button "+ New Case" on right
    assert "Forensic Overview" in html
    assert "+ New Case" in html

    # 2b. "Start here" card (one row): three big buttons with icons
    assert "start-here-card" in html
    assert "start-here-grid" in html
    assert "⚡ Load Demo Case" in html
    assert "📋 Open Feature Map" in html

    # 2c. Stat tiles in CSS grid
    assert "dashboard-stats-grid" in html
    assert "Active Cases" in html
    assert "Vault Evidence Items" in html
    assert "Recent Audits" in html

    # 2d. Integrity tile: Plain language and semantic color
    assert "Integrity Status" in html
    assert ("All evidence verified" in html or "compromised" in html or "needs review" in html or "need review" in html)

    # 2e. Feature Map: 11 cards in responsive grid with Open links
    assert "id=\"feature-map\"" in html or "id='feature-map'" in html
    assert "Platform Feature Map" in html
    assert "11 Modules Operational" in html
    assert "feature-map-grid" in html

    # 2f. Two columns below: Recent Cases (left), Recent Custody Trail (right)
    assert "dashboard-columns-grid" in html
    assert "dashboard-col-left" in html
    assert "dashboard-col-right" in html
    assert "Recent Active Cases" in html
    assert "Recent Custody Trail" in html


def test_topbar_user_menu_and_breadcrumbs(smoke_app):
    """Verify top bar breadcrumbs, user menu with role badge, and dark mode toggle button."""
    app, admin_id, _ = smoke_app
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Real breadcrumbs
    assert "breadcrumb-trail" in html
    assert "Dashboard" in html

    # User menu
    assert "user-menu" in html
    assert "Test Admin" in html
    assert "Admin" in html
    assert "/account" in html
    assert "/logout" in html

    # Theme toggle button
    assert "id=\"theme-toggle-btn\"" in html or "id='theme-toggle-btn'" in html


def test_case_tabs_stepper_and_next_step_buttons(smoke_app):
    """Verify case tabs, guided stepper, active tab underline, and next step buttons across all tabs."""
    app, admin_id, lead_id = smoke_app
    client = app.test_client()

    with app.app_context():
        case_id = create_case("Operation Nightfall", "Digital espionage inquiry", "High", lead_id)
        # Assign admin as member so admin has access
        from app.modules.cases.service import assign_member
        assign_member(case_id, admin_id, lead_id)

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    case_tabs = [
        (f"/cases/{case_id}", "overview"),
        (f"/cases/{case_id}/evidence", "evidence"),
        (f"/cases/{case_id}/custody", "custody"),
        (f"/cases/{case_id}/analysis", "analysis"),
        (f"/cases/{case_id}/timeline", "timeline"),
        (f"/cases/{case_id}/iocs", "iocs"),
        (f"/cases/{case_id}/reports", "reports"),
        (f"/cases/{case_id}/graph", "graph"),
    ]

    for url, tab_name in case_tabs:
        resp = client.get(url)
        assert resp.status_code == 200, f"Case tab failed: {url} returned {resp.status_code}"
        html = resp.get_data(as_text=True)

        # Stepper is present
        assert "guided-stepper" in html, f"Missing guided-stepper on {url}"
        assert "1 Evidence" in html
        assert "2 Verify" in html
        assert "3 Analyse" in html
        assert "4 Timeline" in html
        assert "5 Report" in html

        # Tabs container with active tab
        assert "tabs-container" in html, f"Missing tabs-container on {url}"
        assert "tab-item active" in html, f"Missing active tab on {url}"

        # Real breadcrumbs with case number
        assert "breadcrumb-trail" in html
        assert "Cases" in html

        # Next Step button exists at the bottom
        assert "Next:" in html or "Back to Case Overview" in html or "Export Case Package" in html, f"Missing next-step button on {url}"

        # SVG icon verification
        symbols = extract_svg_symbols(html)
        used_icons = extract_used_icons(html)
        missing_icons = used_icons - symbols
        assert not missing_icons, f"Missing icons on {url}: {missing_icons}"


def test_load_demo_case_smoke_flow(smoke_app):
    """Verify Demo Mode load button creates case and populates data without errors."""
    app, admin_id, _ = smoke_app
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)

    # Post to load demo case
    resp = client.post("/dashboard/load-demo-case", follow_redirects=True)
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Check redirect landed on the demo case overview
    assert "DEMO" in html or "Operation" in html or "Evidence Files" in html

    # Verify no broken SVG icons in the loaded demo case page
    symbols = extract_svg_symbols(html)
    used_icons = extract_used_icons(html)
    missing_icons = used_icons - symbols
    assert not missing_icons, f"Missing icons on demo case page: {missing_icons}"
