"""Data model: one Finding = one CVE on one package of one asset."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

PRIORITIES = ("P1", "P2", "P3", "P4")
DECISIONS = {"P1": "Act", "P2": "Attend", "P3": "Track+", "P4": "Track"}


@dataclass
class Asset:
    id: str
    name: str
    exposure: str          # internet | internal | isolated
    criticality: str       # high | medium | low
    ref: str = ""          # image reference or path
    scan: str = ""         # path to the Trivy JSON scan
    owner: str = ""

    def __post_init__(self) -> None:
        if self.exposure not in ("internet", "internal", "isolated"):
            raise ValueError(f"asset {self.id}: exposure must be internet|internal|isolated, got {self.exposure!r}")
        if self.criticality not in ("high", "medium", "low"):
            raise ValueError(f"asset {self.id}: criticality must be high|medium|low, got {self.criticality!r}")


@dataclass
class Finding:
    asset_id: str
    cve: str
    pkg: str
    installed: str
    fixed: Optional[str]            # fixed version, None when no fix is available
    scanner_severity: str           # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN (as reported by Trivy)
    cvss: Optional[float] = None    # CVSS v3 base score (NVD first, then any other source)
    cvss_vector: Optional[str] = None
    title: str = ""
    target: str = ""                # Trivy "Target" (OS layer, requirements.txt, ...)
    pkg_type: str = ""              # debian, pip, npm, ...
    status: str = ""                # Trivy status: fixed, affected, will_not_fix, end_of_life, ...
    published: Optional[str] = None
    # enrichment
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due: Optional[str] = None
    kev_ransomware: bool = False
    # decision
    exploitation: str = ""          # active | likely | unlikely
    exposure: str = ""              # copied from the asset
    impact: str = ""                # total | high | partial
    priority: str = ""              # P1..P4
    decision: str = ""              # Act / Attend / Track+ / Track
    sla_days: int = 0
    action: str = ""                # patch | mitigate (no fix available) | accepted | not_affected | false_positive
    reasons: list = field(default_factory=list)
    exception: Optional[dict] = None

    @property
    def key(self) -> str:
        return f"{self.asset_id}|{self.cve}|{self.pkg}"

    @property
    def fix_available(self) -> bool:
        return bool(self.fixed)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["key"] = self.key
        d["fix_available"] = self.fix_available
        return d
