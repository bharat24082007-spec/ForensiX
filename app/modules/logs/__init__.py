"""
ForensiX Log Analyser Module.
Parses auth.log and web server access logs to generate timeline events,
extract attacker IOCs, and detect automated threat findings.
"""

from app.modules.logs.routes import logs_bp

__all__ = ["logs_bp"]
