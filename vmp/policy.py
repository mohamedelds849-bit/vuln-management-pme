"""policy.yml: assets, SLA per priority, thresholds, exceptions, CI gate rules."""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Optional

import yaml

from .model import Asset, PRIORITIES

DEFAULT_SLA = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
DEFAULT_THRESHOLDS = {"epss_likely": 0.10, "cvss_total": 9.0, "cvss_high": 7.0}
DEFAULT_GATE = {"fail_on": ["overdue_P1", "new_P1_internet"], "warn_on": ["overdue_P2"]}
EXCEPTION_STATUSES = ("accepted", "not_affected", "false_positive")
GATE_RULES = ("overdue_P1", "overdue_P2", "new_P1_internet", "new_P1", "any_P1_open", "stale_feeds")


class Policy:
    def __init__(self, doc: dict, base_dir: Path):
        self.base_dir = base_dir
        self.organisation = str(doc.get("organisation", ""))
        self.assets: list[Asset] = []
        for a in doc.get("assets") or []:
            fields = {k: a[k] for k in a if k in Asset.__dataclass_fields__}
            self.assets.append(Asset(**fields))
        ids = [a.id for a in self.assets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate asset id in policy")
        self.sla = {**DEFAULT_SLA, **(doc.get("sla_days") or {})}
        for p in PRIORITIES:
            if int(self.sla[p]) <= 0:
                raise ValueError(f"sla_days.{p} must be > 0")
        self.thresholds = {**DEFAULT_THRESHOLDS, **(doc.get("thresholds") or {})}
        self.gate = {**DEFAULT_GATE, **(doc.get("gate") or {})}
        for rule in list(self.gate.get("fail_on", [])) + list(self.gate.get("warn_on", [])):
            if rule not in GATE_RULES:
                raise ValueError(f"unknown gate rule {rule!r}; known: {GATE_RULES}")
        self.exceptions: list[dict] = []
        for e in doc.get("exceptions") or []:
            self._check_exception(e)
            self.exceptions.append(e)

    @staticmethod
    def _check_exception(e: dict) -> None:
        for k in ("cve", "status", "justification", "owner", "expires"):
            if not e.get(k):
                raise ValueError(f"exception {e.get('cve', '?')}: field {k!r} is required")
        if e["cve"] == "*" and not e.get("package"):
            raise ValueError("exception with cve '*' must name a package")
        if e["status"] not in EXCEPTION_STATUSES:
            raise ValueError(f"exception {e['cve']}: status must be one of {EXCEPTION_STATUSES}")
        if len(str(e["justification"]).split()) < 5:
            raise ValueError(f"exception {e['cve']}: justification too short (5 words minimum)")
        Policy.to_date(e["expires"])

    @staticmethod
    def to_date(v) -> date:
        if isinstance(v, datetime):
            return v.date()
        if isinstance(v, date):
            return v
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").date()

    def asset(self, asset_id: str) -> Asset:
        for a in self.assets:
            if a.id == asset_id:
                return a
        raise KeyError(asset_id)

    def find_exception(self, finding, today: date) -> Optional[dict]:
        """Return the matching, non-expired exception.

        `cve: "*"` with a `package` covers every CVE of that package (component-level VEX,
        e.g. kernel headers in a container); asset and package filters are optional otherwise."""
        for e in self.exceptions:
            if e["cve"] not in ("*", finding.cve):
                continue
            if e.get("asset") and e["asset"] != finding.asset_id:
                continue
            if e.get("package") and e["package"] != finding.pkg:
                continue
            if self.to_date(e["expires"]) < today:
                continue  # expired: the finding comes back as open
            return e
        return None

    def expired_exceptions(self, today: date) -> list[dict]:
        return [e for e in self.exceptions if self.to_date(e["expires"]) < today]


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    with open(p, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return Policy(doc, p.parent)
