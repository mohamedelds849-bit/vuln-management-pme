"""vmp — a small risk-based vulnerability management pipeline for an SME.

Flow: Trivy JSON scans -> normalized findings -> enrichment (EPSS, CISA KEV)
      -> SSVC-inspired decision (P1..P4 + SLA) -> ledger (first seen, due date, fixed)
      -> reports (HTML for the business owner, JSON, CSV tickets, OpenVEX) -> CI gate.
"""
__version__ = "1.0.0"
