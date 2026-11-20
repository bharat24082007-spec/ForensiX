"""
ForensiX Authentication Core.
Argon2id password hashing, 12+ character complexity policy,
account lockout enforcement (5 failures / 15 minutes), and Flask-Login integration.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from flask_login import LoginManager, UserMixin

from app.db import query_db, execute_db

# Argon2id password hasher with high security parameters
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
login_manager = LoginManager()
login_manager.login_view = "accounts.login"
login_manager.login_message = "Please sign in to access the investigation platform."
login_manager.login_message_category = "error"


class User(UserMixin):
    """ForensiX authenticated user session model."""

    def __init__(
        self,
        id: int,
        name: str,
        username: str,
        role: str,
        mfa_enabled: bool,
        is_active: bool,
        failed_attempts: int = 0,
        locked_until: Optional[str] = None,
        sign_pub_key: Optional[str] = None,
        sign_priv_key_enc: Optional[str] = None,
    ) -> None:
        self.id = id
        self.name = name
        self.username = username
        self.role = role
        self.mfa_enabled = bool(mfa_enabled)
        self._is_active = bool(is_active)
        self.failed_attempts = failed_attempts
        self.locked_until = locked_until
        self.sign_pub_key = sign_pub_key
        self.sign_priv_key_enc = sign_priv_key_enc

    @property
    def is_active(self) -> bool:
        return self._is_active

    def get_id(self) -> str:
        return str(self.id)


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Retrieve user instance from SQLite database by ID."""
    row = query_db(
        """
        SELECT id, name, username, role, mfa_enabled, is_active,
               failed_attempts, locked_until, sign_pub_key, sign_priv_key_enc
        FROM users WHERE id = ?
        """,
        (user_id,),
        one=True,
    )
    if not row:
        return None
    return User(
        id=row["id"],
        name=row["name"],
        username=row["username"],
        role=row["role"],
        mfa_enabled=bool(row["mfa_enabled"]),
        is_active=bool(row["is_active"]),
        failed_attempts=row["failed_attempts"],
        locked_until=row["locked_until"],
        sign_pub_key=row["sign_pub_key"],
        sign_priv_key_enc=row["sign_priv_key_enc"],
    )


def validate_password_complexity(password: str) -> None:
    """
    Enforce strict forensic password policy:
    Minimum 12 characters, including at least one number and one symbol/letter.
    """
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit (0-9).")
    if not re.search(r"[A-Za-z]", password):
        raise ValueError("Password must contain at least one alphabetical letter.")


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    validate_password_complexity(password)
    return hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        return hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def is_account_locked(locked_until_str: Optional[str]) -> bool:
    """Check if an account is currently under temporary lockout."""
    if not locked_until_str:
        return False
    try:
        # Expected format: ISO 8601 or SQLite datetime string
        locked_dt = datetime.fromisoformat(locked_until_str)
        if locked_dt.tzinfo is None:
            locked_dt = locked_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < locked_dt
    except (ValueError, TypeError):
        return False


def record_failed_login(user_id: int, current_attempts: int) -> Optional[datetime]:
    """
    Record an unsuccessful login attempt.
    If attempts reach 5, locks account for 15 minutes.
    """
    new_attempts = current_attempts + 1
    locked_until: Optional[str] = None
    lock_dt: Optional[datetime] = None

    if new_attempts >= 5:
        lock_dt = datetime.now(timezone.utc) + timedelta(minutes=15)
        locked_until = lock_dt.isoformat()

    execute_db(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (new_attempts, locked_until, user_id),
    )
    return lock_dt


def reset_failed_logins(user_id: int) -> None:
    """Reset failed attempts and unlock timestamp upon successful authentication."""
    execute_db(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
