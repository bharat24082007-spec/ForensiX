"""
ForensiX IOC Extractor & Reputation Module.
Extracts, stores, and displays Indicators of Compromise from evidence.
"""

from app.modules.iocs.routes import iocs_bp

__all__ = ["iocs_bp"]
