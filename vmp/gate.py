"""CI gate: turn the run summary into a pass / fail decision.

Rules (chosen in policy.yml `gate:`):
  overdue_P1       a P1 finding is past its due date
  overdue_P2       a P2 finding is past its due date
  new_P1_internet  a P1 appeared today on an internet-facing asset
  new_P1           a P1 appeared today on any asset
  any_P1_open      at least one P1 is open (strictest)
  stale_feeds      KEV or EPSS feed older than 7 days (the decision would be made on old data)
"""
from __future__ import annotations

from .model import Finding


def evaluate(findings: list[Finding], summary: dict, stale_feeds: list[str], gate_cfg: dict) -> dict:
    facts = {
        "overdue_P1": sum(1 for f in findings if f.priority == "P1" and getattr(f, "ledger_status", "") == "overdue"),
        "overdue_P2": sum(1 for f in findings if f.priority == "P2" and getattr(f, "ledger_status", "") == "overdue"),
        "new_P1_internet": sum(1 for f in findings if f.priority == "P1" and f.exposure == "internet"
                               and getattr(f, "first_seen", "") == summary["date"] and not f.exception),
        "new_P1": sum(1 for f in findings if f.priority == "P1"
                      and getattr(f, "first_seen", "") == summary["date"] and not f.exception),
        "any_P1_open": sum(1 for f in findings if f.priority == "P1"
                           and getattr(f, "ledger_status", "") in ("open", "overdue")),
        "stale_feeds": len(stale_feeds),
    }
    failures = [f"{r}={facts[r]}" for r in gate_cfg.get("fail_on", []) if facts.get(r, 0) > 0]
    warnings = [f"{r}={facts[r]}" for r in gate_cfg.get("warn_on", []) if facts.get(r, 0) > 0]
    return {"passed": not failures, "failures": failures, "warnings": warnings, "facts": facts}
