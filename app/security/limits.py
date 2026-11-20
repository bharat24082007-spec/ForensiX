"""
ForensiX Rate Limiting Configuration.
Uses in-memory storage suitable for single-host forensic operation.
"""

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],  # Explicit limits on sensitive endpoints
    storage_uri="memory://",
)
