"""
ForensiX Platform Configuration Module.
Enforces single-host constraints, secure secrets, and directory structures.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict


BANNED_SECRET_KEYS = {
    "",
    "change-me",
    "insecure-default-key",
    "default",
    "secret",
    "forensix_default_key",
    "change-me-in-production",
}


def load_dotenv(dotenv_path: Path | None = None) -> Dict[str, str]:
    """Parse a .env file and set environment variables if not already set."""
    if dotenv_path is None:
        dotenv_path = Path.cwd() / ".env"

    env_vars: Dict[str, str] = {}
    if not dotenv_path.is_file():
        return env_vars

    with open(dotenv_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            # Strip matching surrounding quotes if present
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            env_vars[key] = val
            if key not in os.environ:
                os.environ[key] = val
    return env_vars


class Config:
    """Application configuration with strict validation for single-host forensic operation."""

    def __init__(self, env: Dict[str, str] | None = None) -> None:
        if env is None:
            # Read directly from os.environ after populating from .env
            load_dotenv()
            env = dict(os.environ)

        self.SECRET_KEY: str = env.get("SECRET_KEY", "").strip()
        self.HOST: str = env.get("HOST", "127.0.0.1").strip()
        self.PORT: int = int(env.get("PORT", "5000").strip())
        self.ALLOW_LAN: bool = env.get("ALLOW_LAN", "false").strip().lower() in ("true", "1", "yes")

        base_data_dir = env.get("DATA_DIR", "data").strip()
        self.DATA_DIR: Path = Path(base_data_dir).resolve()

        # Vault, DB, work, reports, backups, keys, logs
        self.DB_DIR: Path = self.DATA_DIR / "db"
        self.VAULT_DIR: Path = self.DATA_DIR / "vault"
        self.WORK_DIR: Path = self.DATA_DIR / "work"
        self.REPORTS_DIR: Path = self.DATA_DIR / "reports"
        self.BACKUPS_DIR: Path = self.DATA_DIR / "backups"
        self.KEYS_DIR: Path = self.DATA_DIR / "keys"
        self.LOGS_DIR: Path = self.DATA_DIR / "logs"

        # Database file path
        self.DATABASE_PATH: Path = self.DB_DIR / "forensix.sqlite"

        # Master encryption key file (must reside outside data/vault/)
        self.MASTER_KEY_PATH: Path = self.KEYS_DIR / "master.key"

        # Upload constraints
        self.MAX_UPLOAD_MB: int = int(env.get("MAX_UPLOAD_MB", "200").strip())
        self.MAX_CONTENT_LENGTH: int = self.MAX_UPLOAD_MB * 1024 * 1024

        # Subprocess external tools
        self.TSHARK_PATH: str = env.get("TSHARK_PATH", "tshark").strip()
        self.CAPINFOS_PATH: str = env.get("CAPINFOS_PATH", "capinfos").strip()
        self.EXIFTOOL_PATH: str = env.get("EXIFTOOL_PATH", "exiftool").strip()
        self.FLS_PATH: str = env.get("FLS_PATH", "fls").strip()

        # Offline & verify flags
        self.EXTERNAL_LOOKUPS: bool = env.get("EXTERNAL_LOOKUPS", "false").strip().lower() in ("true", "1", "yes")
        self.PUBLIC_VERIFY: bool = env.get("PUBLIC_VERIFY", "false").strip().lower() in ("true", "1", "yes")
        self.WATCHDOG_INTERVAL_MIN: int = int(env.get("WATCHDOG_INTERVAL_MIN", "60").strip())

        # Validate security and single-host rules
        self.validate()

    def is_loopback(self, host: str) -> bool:
        """Check if the configured host is strictly a loopback address."""
        host_lower = host.lower()
        if host_lower in ("127.0.0.1", "localhost", "::1"):
            return True
        if host_lower.startswith("127."):
            return True
        return False

    def validate(self) -> None:
        """Enforce strict CIA rules at startup."""
        # 1. Refuse insecure or placeholder secret keys
        if not self.SECRET_KEY or self.SECRET_KEY in BANNED_SECRET_KEYS:
            raise ValueError(
                "CRITICAL SECURITY ERROR: SECRET_KEY is missing or set to an insecure default placeholder. "
                "You must set a unique, cryptographically strong SECRET_KEY (at least 32 characters) in .env."
            )
        if len(self.SECRET_KEY) < 16:
            raise ValueError(
                "CRITICAL SECURITY ERROR: SECRET_KEY is too short (minimum 16 characters required, 32+ recommended)."
            )

        # 2. Refuse non-loopback host unless ALLOW_LAN is explicitly True
        if not self.is_loopback(self.HOST) and not self.ALLOW_LAN:
            raise ValueError(
                f"CRITICAL NETWORK ERROR: Binding to non-loopback host '{self.HOST}' is rejected. "
                "ForensiX enforces a strict single-host constraint (127.0.0.1 only). "
                "Set ALLOW_LAN=true in .env only if external LAN access is explicitly permitted."
            )

    def ensure_directories(self) -> None:
        """Create storage directories with restricted permissions where supported."""
        target_dirs = [
            self.DATA_DIR,
            self.DB_DIR,
            self.VAULT_DIR,
            self.WORK_DIR,
            self.REPORTS_DIR,
            self.BACKUPS_DIR,
            self.KEYS_DIR,
            self.LOGS_DIR,
        ]
        for d in target_dirs:
            d.mkdir(parents=True, exist_ok=True)
            # Apply 0700 permission on Unix/POSIX systems where chmod is supported
            try:
                os.chmod(d, 0o700)
            except (OSError, NotImplementedError):
                pass
