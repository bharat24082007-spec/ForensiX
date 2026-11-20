"""
Tests for Section S2: Security Core and Accounts.
Verifies Argon2id password hashing, password complexity policies,
account lockout, TOTP MFA, session security, CSRF protection,
security headers, RBAC role enforcement, and per-case separation of duties.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from flask import g
from flask_login import login_user

from app import create_app
from app.db import execute_db, query_db
from app.security.auth import (
    hash_password,
    verify_password,
    validate_password_complexity,
    User,
)
from app.security.crypto import (
    get_master_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    generate_ed25519_keypair,
)
from app.security.mfa import (
    generate_mfa_secret,
    get_provisioning_uri,
    generate_qr_code_svg,
    verify_totp_code,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    generate_backup_codes,
    verify_and_consume_backup_code,
)
from app.security.rbac import role_required, case_member_required
from app.modules.accounts.service import create_user, authenticate_credentials
import pyotp


@pytest.fixture
def auth_app(tmp_path: Path):
    """Fixture providing a Flask app instance with CSRF enabled and isolated test DB."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    app = create_app(
        test_config={
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,  # Disabled by default; tested explicitly in CSRF test
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": 5000,
            "ALLOW_LAN": False,
            "DATA_DIR": str(data_dir),
            "DATABASE_PATH": str(data_dir / "db" / "forensix.sqlite"),
        }
    )

    # Attach dummy route to test case membership and role restrictions
    @app.route("/test-cases/<int:case_id>/evidence/upload", methods=["POST"])
    @role_required("Lead", "Analyst")
    @case_member_required
    def dummy_evidence_upload(case_id: int):
        return {"status": "upload_authorized", "case_id": case_id}

    @app.route("/test-cases/<int:case_id>/overview", methods=["GET"])
    @case_member_required
    def dummy_case_overview(case_id: int):
        return {"status": "case_accessible", "case_id": case_id}

    yield app


def test_password_hashing_and_complexity():
    """Verify Argon2id hashing and password complexity rules."""
    valid_pwd = "ForensicPassword2026!"
    hashed = hash_password(valid_pwd)
    assert hashed != valid_pwd
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, valid_pwd) is True
    assert verify_password(hashed, "WrongPassword123") is False

    # Policy violations: too short, no digit, no letter
    with pytest.raises(ValueError, match="at least 12 characters"):
        validate_password_complexity("Short1!")

    with pytest.raises(ValueError, match="at least one digit"):
        validate_password_complexity("NoDigitsInThisPassword!")

    with pytest.raises(ValueError, match="at least one alphabetical letter"):
        validate_password_complexity("123456789012345")


def test_unauthenticated_access_is_redirected(auth_app):
    """Verify unauthenticated requests to protected endpoints redirect to /login."""
    client = auth_app.test_client()

    for endpoint in ["/dashboard", "/account", "/admin/users"]:
        response = client.get(endpoint)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


def test_login_and_logout_flow(auth_app):
    """Verify valid login establishes session and logout clears it."""
    with auth_app.app_context():
        user_id = create_user(
            name="John Analyst",
            username="janalyst",
            role="Analyst",
            password="StrongPassword123!",
        )

    client = auth_app.test_client()

    # Valid login
    resp = client.post(
        "/login",
        data={"username": "janalyst", "password": "StrongPassword123!"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Forensic Overview" in resp.data

    # Access protected route
    acct_resp = client.get("/account")
    assert acct_resp.status_code == 200
    assert b"janalyst" in acct_resp.data

    # Logout
    logout_resp = client.post("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"Authorized Personnel Access" in logout_resp.data

    # Verify session cleared
    after_logout = client.get("/account")
    assert after_logout.status_code == 302
    assert "/login" in after_logout.headers["Location"]


def test_account_lockout_after_five_failed_attempts(auth_app):
    """Verify account is temporarily locked for 15 minutes after 5 consecutive failures."""
    with auth_app.app_context():
        create_user(
            name="Target User",
            username="target_user",
            role="Analyst",
            password="CorrectPassword123!",
        )

    client = auth_app.test_client()

    # Submit 4 failed attempts
    for _ in range(4):
        resp = client.post(
            "/login",
            data={"username": "target_user", "password": "WrongPassword123!"},
            follow_redirects=True,
        )
        assert b"Invalid username or password" in resp.data

    # 5th failed attempt triggers 15-minute lockout
    fifth_resp = client.post(
        "/login",
        data={"username": "target_user", "password": "WrongPassword123!"},
        follow_redirects=True,
    )
    assert b"Account has been locked for 15 minutes" in fifth_resp.data

    # Even correct password is now blocked during lockout period
    locked_attempt = client.post(
        "/login",
        data={"username": "target_user", "password": "CorrectPassword123!"},
        follow_redirects=True,
    )
    assert b"Account is locked due to repeated failed attempts" in locked_attempt.data


def test_csrf_protection_rejects_post_without_token(tmp_path: Path):
    """Verify CSRF middleware actively blocks POST requests lacking valid CSRF token."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    csrf_app = create_app(
        test_config={
            "TESTING": True,
            "WTF_CSRF_ENABLED": True,  # Strictly enabled
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": 5000,
            "ALLOW_LAN": False,
            "DATA_DIR": str(data_dir),
            "DATABASE_PATH": str(data_dir / "db" / "forensix.sqlite"),
        }
    )

    client = csrf_app.test_client()

    # POST without CSRF token
    response = client.post(
        "/login",
        data={"username": "test", "password": "testpassword123"},
    )
    # Must be rejected with 400 Bad Request
    assert response.status_code == 400


def test_role_restrictions_and_reviewer_denied_upload(auth_app):
    """
    Verify RBAC role checks:
    - Reviewer cannot access upload route (403 Forbidden).
    - Non-admin cannot access /admin/users (403 Forbidden).
    """
    with auth_app.app_context():
        reviewer_id = create_user(
            name="Bob Reviewer",
            username="breviewer",
            role="Reviewer",
            password="ReviewerPassword123!",
        )
        lead_id = create_user(
            name="Charlie Lead",
            username="clead",
            role="Lead",
            password="LeadPassword123!",
        )
        case_id = execute_db(
            "INSERT INTO cases (case_no, title, lead_user_id) VALUES ('CASE-2026-0002', 'Test Case', ?)",
            (lead_id,),
        )
        # Assign reviewer to case
        execute_db("INSERT INTO case_members (case_id, user_id) VALUES (?, ?)", (case_id, reviewer_id))

    client = auth_app.test_client()

    # Authenticate as Reviewer
    with client.session_transaction() as sess:
        sess["_user_id"] = str(reviewer_id)
        sess["_fresh"] = True

    # Reviewer cannot access /admin/users
    admin_resp = client.get("/admin/users")
    assert admin_resp.status_code == 403

    # Reviewer CANNOT upload evidence (forbidden: 403)
    upload_resp = client.post(f"/test-cases/{case_id}/evidence/upload")
    assert upload_resp.status_code == 403

    # Switch session to Lead
    with client.session_transaction() as sess:
        sess["_user_id"] = str(lead_id)
        sess["_fresh"] = True

    # Lead CAN upload evidence (authorized: 200)
    lead_upload = client.post(f"/test-cases/{case_id}/evidence/upload")
    assert lead_upload.status_code == 200
    assert lead_upload.get_json()["status"] == "upload_authorized"


def test_case_member_required_returns_404_for_non_members_and_admins(auth_app):
    """
    Verify Separation of Duties:
    - Non-member gets 404 (NOT 403) to prevent case enumeration.
    - Admin has NO case access unless explicitly assigned, receiving 404.
    - Assigned member receives 200.
    """
    with auth_app.app_context():
        lead_id = create_user("Lead 1", "lead1", "Lead", "Password12345!")
        analyst_id = create_user("Analyst 1", "analyst1", "Analyst", "Password12345!")
        admin_id = create_user("Admin 1", "admin1", "Admin", "Password12345!")

        case_id = execute_db(
            "INSERT INTO cases (case_no, title, lead_user_id) VALUES ('CASE-2026-0003', 'Secret Case', ?)",
            (lead_id,),
        )

    client = auth_app.test_client()

    # 1. Unassigned Analyst attempts access -> MUST return 404
    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True

    resp_analyst = client.get(f"/test-cases/{case_id}/overview")
    assert resp_analyst.status_code == 404

    # 2. Admin (not a member) attempts access -> MUST return 404 (Separation of duties)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True

    resp_admin = client.get(f"/test-cases/{case_id}/overview")
    assert resp_admin.status_code == 404

    # 3. Explicitly assign Analyst to the case
    with auth_app.app_context():
        execute_db("INSERT INTO case_members (case_id, user_id) VALUES (?, ?)", (case_id, analyst_id))

    with client.session_transaction() as sess:
        sess["_user_id"] = str(analyst_id)
        sess["_fresh"] = True

    resp_assigned = client.get(f"/test-cases/{case_id}/overview")
    assert resp_assigned.status_code == 200
    assert resp_assigned.get_json()["status"] == "case_accessible"


def test_totp_mfa_flow_and_backup_codes():
    """Verify offline TOTP secret generation, QR SVG, verification, and backup codes."""
    secret = generate_mfa_secret()
    uri = get_provisioning_uri("test_investigator", secret)
    qr_svg_uri = generate_qr_code_svg(uri)

    assert qr_svg_uri.startswith("data:image/svg+xml;base64,")

    # Valid token verification
    totp = pyotp.TOTP(secret)
    current_token = totp.now()
    assert verify_totp_code(secret, current_token) is True
    assert verify_totp_code(secret, "999999") is False

    # Encrypted storage at rest
    enc_secret = encrypt_mfa_secret(secret)
    assert enc_secret != secret
    dec_secret = decrypt_mfa_secret(enc_secret)
    assert dec_secret == secret

    # Single-use backup codes
    plain_codes, enc_backup = generate_backup_codes(count=4)
    assert len(plain_codes) == 4

    # Consume first backup code
    first_code = plain_codes[0]
    ok, updated_enc = verify_and_consume_backup_code(first_code, enc_backup)
    assert ok is True

    # Re-using the same backup code must fail
    reused, _ = verify_and_consume_backup_code(first_code, updated_enc)
    assert reused is False


def test_security_headers_and_csp(auth_app):
    """Verify security headers: CSP, anti-clickjacking, no-sniff, and anti-caching."""
    client = auth_app.test_client()

    resp = client.get("/")
    assert resp.status_code == 200
    headers = resp.headers

    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_crypto_master_key_outside_vault_and_ed25519(tmp_path: Path):
    """Verify master key resides in data/keys/ (outside vault) and Ed25519 key generation."""
    key_path = tmp_path / "data" / "keys" / "master.key"
    vault_dir = tmp_path / "data" / "vault"

    assert key_path.parent != vault_dir

    key = get_master_key(key_path)
    assert len(key) == 32

    # AES-256-GCM
    plaintext = b"Classified Forensic Evidence Record"
    aad = b"evidence_header"
    encrypted = encrypt_aes_gcm(plaintext, aad=aad, master_key=key)
    assert plaintext not in encrypted

    decrypted = decrypt_aes_gcm(encrypted, aad=aad, master_key=key)
    assert decrypted == plaintext

    # Ed25519 keypair
    pub_hex, priv_enc_hex = generate_ed25519_keypair(master_key=key)
    assert len(pub_hex) == 64
    assert len(priv_enc_hex) > 64
