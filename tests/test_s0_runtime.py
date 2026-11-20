"""
Tests for Section S0: Foundation and Single-Host Runtime.
Verifies single-host constraints, loopback checks, secret key rejection,
data directory provisioning, and secure structured logging.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from app import create_app
from app.config import Config, BANNED_SECRET_KEYS
from app.logger import setup_logger, sanitize_value


def test_refuse_banned_or_empty_secret_keys():
    """Verify that empty, placeholder, or banned secret keys fail startup validation."""
    for banned in BANNED_SECRET_KEYS:
        with pytest.raises(ValueError, match="SECRET_KEY is missing or set to an insecure default"):
            Config(
                env={
                    "SECRET_KEY": banned,
                    "HOST": "127.0.0.1",
                    "PORT": "5000",
                    "DATA_DIR": "data",
                }
            )


def test_refuse_short_secret_key():
    """Verify that secret keys shorter than 16 characters are rejected."""
    with pytest.raises(ValueError, match="SECRET_KEY is too short"):
        Config(
            env={
                "SECRET_KEY": "short_secret",
                "HOST": "127.0.0.1",
                "PORT": "5000",
                "DATA_DIR": "data",
            }
        )


def test_refuse_non_loopback_host_without_allow_lan():
    """Verify single-host constraint: binding to 0.0.0.0 or LAN IP is refused by default."""
    forbidden_hosts = ["0.0.0.0", "192.168.1.50", "10.0.0.1", "example.com"]
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"

    for host in forbidden_hosts:
        with pytest.raises(ValueError, match="Binding to non-loopback host"):
            Config(
                env={
                    "SECRET_KEY": valid_key,
                    "HOST": host,
                    "PORT": "5000",
                    "ALLOW_LAN": "false",
                    "DATA_DIR": "data",
                }
            )


def test_allow_non_loopback_when_allow_lan_is_true():
    """Verify non-loopback host is permitted only if ALLOW_LAN is explicitly true."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    config = Config(
        env={
            "SECRET_KEY": valid_key,
            "HOST": "0.0.0.0",
            "PORT": "5000",
            "ALLOW_LAN": "true",
            "DATA_DIR": "data",
        }
    )
    assert config.HOST == "0.0.0.0"
    assert config.ALLOW_LAN is True


def test_loopback_hosts_accepted():
    """Verify standard loopback addresses (127.0.0.1, localhost, ::1, 127.0.1.1) are accepted."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    for host in ["127.0.0.1", "localhost", "::1", "127.0.0.2"]:
        config = Config(
            env={
                "SECRET_KEY": valid_key,
                "HOST": host,
                "PORT": "5000",
                "ALLOW_LAN": "false",
                "DATA_DIR": "data",
            }
        )
        assert config.HOST == host


def test_directory_provisioning(tmp_path: Path):
    """Verify that all required data subdirectories are provisioned."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    config = Config(
        env={
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": "5000",
            "DATA_DIR": str(data_dir),
        }
    )
    config.ensure_directories()

    assert config.DB_DIR.is_dir()
    assert config.VAULT_DIR.is_dir()
    assert config.WORK_DIR.is_dir()
    assert config.REPORTS_DIR.is_dir()
    assert config.BACKUPS_DIR.is_dir()
    assert config.KEYS_DIR.is_dir()
    assert config.LOGS_DIR.is_dir()
    # Confirm master key path is outside vault
    assert config.MASTER_KEY_PATH.parent != config.VAULT_DIR


def test_app_serves_platform_running(tmp_path: Path):
    """Verify app factory creates test client and serves the S0 root verification endpoint."""
    valid_key = "a_very_strong_random_secret_key_for_testing_12345"
    data_dir = tmp_path / "data"

    app = create_app(
        test_config={
            "TESTING": True,
            "SECRET_KEY": valid_key,
            "HOST": "127.0.0.1",
            "PORT": 5000,
            "ALLOW_LAN": False,
            "DATA_DIR": str(data_dir),
        }
    )

    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"ForensiX Platform running" in response.data

    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    health_data = health_resp.get_json()
    assert health_data["status"] == "operational"
    assert health_data["host_mode"] == "loopback"


def test_structured_logger_and_scrubbing(tmp_path: Path):
    """Verify logger produces JSON lines and strictly scrubs sensitive keys."""
    logs_dir = tmp_path / "logs"
    logger = setup_logger(logs_dir)

    # Log with extra details containing sensitive credentials and safe data
    logger.info(
        "User action occurred",
        extra={
            "details": {
                "action": "LOGIN",
                "username": "investigator1",
                "password": "SuperSecretPassword123",
                "master_key": "raw_hex_key_data",
                "case_id": "CASE-2026-0001",
            }
        },
    )

    log_file = logs_dir / "forensix.log"
    assert log_file.is_file()

    with open(log_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) >= 1
    last_log = json.loads(lines[-1])
    assert last_log["message"] == "User action occurred"
    assert last_log["details"]["username"] == "investigator1"
    assert last_log["details"]["case_id"] == "CASE-2026-0001"
    # Verify sensitive data was redacted
    assert last_log["details"]["password"] == "[REDACTED]"
    assert last_log["details"]["master_key"] == "[REDACTED]"
    assert "SuperSecretPassword123" not in lines[-1]
