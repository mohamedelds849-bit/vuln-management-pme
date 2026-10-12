"""SSVC-inspired decision tree: exploitation x exposure x impact x asset criticality -> P1..P4.

Inspired by CISA's Stakeholder-Specific Vulnerability Categorization (SSVC) "deployer" tree,
simplified to the data an SME really has:
  exploitation : active   = CVE is in CISA KEV (exploitation observed in the wild)
                 likely   = EPSS >= epss_likely threshold (default 10 % in the next 30 days)
                 unlikely = everything else
  exposure     : from the asset (internet / internal / isolated)
  impact       : total  = CVSS v3 >= cvss_total (default 9.0) or scanner says CRITICAL
                 high   = CVSS v3 >= cvss_high (default 7.0) or scanner says HIGH
                 partial= the rest
  criticality  : from the asset (what the business loses if it falls)
Decision -> priority -> SLA:  Act=P1, Attend=P2, Track+=P3, Track=P4.
"""
from __future__ import annotations

from datetime import date

from .model import DECISIONS, Finding
from .policy import Policy


def exploitation(f: Finding, thresholds: dict) -> str:
    if f.kev:
        return "active"
    if f.epss is not None and f.epss >= float(thresholds["epss_likely"]):
        return "likely"
    return "unlikely"


def impact(f: Finding, thresholds: dict) -> str:
    if (f.cvss is not None and f.cvss >= float(thresholds["cvss_total"])) or f.scanner_severity == "CRITICAL":
        return "total"
    if (f.cvss is not None and f.cvss >= float(thresholds["cvss_high"])) or f.scanner_severity == "HIGH":
        return "high"
    return "partial"


def priority(expl: str, exposure: str, imp: str, criticality: str) -> tuple[str, str]:
    """Return (priority, reason). Rules are evaluated top-down; the first match wins."""
    internet = exposure == "internet"
    crit_high = criticality == "high"
    if expl == "active" and (internet or crit_high):
        return "P1", "exploitee dans la nature (KEV) sur un actif expose ou critique"
    if expl == "likely" and internet and imp == "total":
        return "P1", "exploitation probable (EPSS) sur un actif Internet, impact total"
    if expl == "active":
        return "P2", "exploitee dans la nature (KEV), actif interne non critique"
    if expl == "likely" and (imp == "total" or (internet and imp == "high")):
        return "P2", "exploitation probable (EPSS) et impact eleve ou total"
    if expl == "unlikely" and internet and imp == "total" and crit_high:
        return "P2", "impact total sur un actif Internet critique, meme sans exploitation connue"
    if expl == "likely":
        return "P3", "exploitation probable (EPSS) mais impact limite"
    if imp == "total" or (imp == "high" and internet):
        return "P3", "impact total, ou impact eleve sur un actif Internet"
    if exposure == "isolated":
        return "P4", "actif isole, pas d'exploitation connue"
    return "P4", "pas d'exploitation connue, impact limite"


def decide(findings: list[Finding], policy: Policy, today: date) -> None:
    """Fill exploitation / exposure / impact / priority / decision / sla / action / reasons (in place)."""
    for f in findings:
        asset = policy.asset(f.asset_id)
        f.exploitation = exploitation(f, policy.thresholds)
        f.exposure = asset.exposure
        f.impact = impact(f, policy.thresholds)
        f.priority, why = priority(f.exploitation, f.exposure, f.impact, asset.criticality)
        f.decision = DECISIONS[f.priority]
        f.sla_days = int(policy.sla[f.priority])
        f.reasons = [why]
        if f.kev:
            f.reasons.append(f"CISA KEV depuis le {f.kev_date_added}"
                             + (", utilisee par des rancongiciels" if f.kev_ransomware else ""))
        if f.epss is not None:
            pct = f" (percentile {f.epss_percentile:.0%})" if f.epss_percentile is not None else ""
            f.reasons.append(f"EPSS {f.epss:.1%}{pct}")
        if f.cvss is not None:
            f.reasons.append(f"CVSS {f.cvss:.1f}")
        if f.status in ("will_not_fix", "fix_deferred", "end_of_life"):
            f.reasons.append(f"statut distribution : {f.status}")
        exc = policy.find_exception(f, today)
        if exc:
            f.exception = {k: str(exc[k]) for k in ("status", "justification", "owner", "expires")}
            f.action = exc["status"]
            f.reasons.append(f"exception {exc['status']} jusqu'au {exc['expires']}")
        elif f.fix_available:
            f.action = "patch"
        else:
            f.action = "mitigate"
            f.reasons.append("pas de correctif disponible : mesure compensatoire et surveillance")
