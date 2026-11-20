"""
ForensiX Security Headers & Session Policy.
Enforces strict Content Security Policy (CSP), anti-clickjacking,
MIME-sniffing prevention, and anti-caching for authenticated responses.
"""

from __future__ import annotations

from flask import Flask, Response, request
from flask_login import current_user


def init_security_headers(app: Flask) -> None:
    """Attach security headers after each HTTP request."""

    @app.after_request
    def set_headers(response: Response) -> Response:
        # Strict Content Security Policy (Zero external scripts or CDNs)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )

        # Anti-clickjacking & MIME sniffing protection
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Prevent browser caching of sensitive authenticated case data
        if current_user and current_user.is_authenticated:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response
