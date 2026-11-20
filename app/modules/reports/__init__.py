"""
ForensiX Forensic Report Generator Module.
Generates signed PDF reports with chain-of-custody trail, evidence inventory,
timeline, findings, IOCs, and legal certification sections.
"""

from app.modules.reports.routes import reports_bp

__all__ = ["reports_bp"]
