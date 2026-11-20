"""
ForensiX Network Packet Analysis Module.
Dissects PCAP/PCAPNG evidence into structured events, IOCs, and findings.
"""

from app.modules.network.routes import network_bp

__all__ = ["network_bp"]
