"""
ForensiX Structured Logging Module.
Enforces JSON lines rotating logs and strict redaction of sensitive credentials,
evidence payloads, and cryptographic keys.
"""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict


SENSITIVE_FIELD_NAMES = {
    "password",
    "password_hash",
    "mfa_secret",
    "secret_key",
    "private_key",
    "sign_priv_key",
    "sign_priv_key_enc",
    "master_key",
    "evidence_content",
    "raw_bytes",
    "token",
    "authorization",
}


def sanitize_value(val: Any) -> Any:
    """Recursively scrub sensitive keys and replace their values with REDACTED."""
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if str(k).lower() in SENSITIVE_FIELD_NAMES:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_value(v)
        return sanitized
    if isinstance(val, list):
        return [sanitize_value(item) for item in val]
    return val


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }

        # Include structured extra payload if provided and sanitize it
        if hasattr(record, "details") and isinstance(record.details, dict):
            log_entry["details"] = sanitize_value(record.details)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class SensitiveScrubberFilter(logging.Filter):
    """Filter that inspects log messages and parameters for sensitive leakage."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg_lower = record.msg.lower()
            for sensitive_kw in ("password=", "password:", "secret=", "secret_key=", "master_key="):
                if sensitive_kw in msg_lower:
                    record.msg = "[FILTERED: Log statement contained sensitive parameter keyword]"
                    record.args = ()
                    break
        return True


def setup_logger(logs_dir: Path, log_level: int = logging.INFO, reset_handlers: bool = False) -> logging.Logger:
    """Configure the root 'forensix' logger with rotating JSON file logging."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = (logs_dir / "forensix.log").resolve()

    logger = logging.getLogger("forensix")
    logger.setLevel(log_level)

    if reset_handlers:
        for h in list(logger.handlers):
            h.close()
            logger.removeHandler(h)

    # Check if a file handler is already pointing to this specific file
    has_target_file_handler = any(
        isinstance(h, RotatingFileHandler) and Path(h.baseFilename).resolve() == log_file
        for h in logger.handlers
    )

    if not has_target_file_handler:
        # Rotating file handler: 10 MB per file, keep 5 backups
        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(JsonFormatter())
        file_handler.addFilter(SensitiveScrubberFilter())
        logger.addHandler(file_handler)

    has_console = any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in logger.handlers)
    if not has_console:
        # Console handler for local terminal visibility
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(SensitiveScrubberFilter())
        logger.addHandler(console_handler)

    return logger
