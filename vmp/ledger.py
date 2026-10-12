"""The ledger: what was seen when, what is due when, what got fixed.

A scanner tells you what is vulnerable *today*. Vulnerability management needs memory:
first seen, due date (first seen + SLA), fixed on, time to remediate. The ledger is a JSON
file committed with the project (or kept as a CI artifact), updated at every run.
"""
from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

from .model import Finding, PRIORITIES

OPEN_STATES = ("open", "overdue", "accepted", "not_affected", "false_positive", "mitigate")


def empty_ledger() -> dict:
    return {"version": 1, "findings": {}, "runs": []}


def load_ledger(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return empty_ledger()
    with open(p, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("version") != 1:
        raise ValueError(f"unsupported ledger version {doc.get('version')!r}")
    return doc


def save_ledger(doc: dict, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1, sort_keys=True)


def _iso(d: date) -> str:
    return d.isoformat()


def _state_for(f: Finding, due: date, today: date) -> str:
    if f.exception:
        return f.exception["status"]          # accepted / not_affected / false_positive
    if f.action == "mitigate" and due < today:
        return "overdue"
    return "overdue" if due < today else "open"


def update(ledger: dict, findings: list[Finding], scanned_assets: list[str], today: date) -> dict:
    """Merge today's findings into the ledger. Returns the run summary (new / fixed / ...).

    - new finding            -> first_seen = today, due = today + SLA
    - seen again             -> last_seen = today; if the priority got worse (e.g. newly in KEV),
                                due = min(old due, today + new SLA) and the finding is 'escalated'
    - missing from a scanned asset -> fixed_on = today, time_to_fix = fixed_on - first_seen
    - assets not scanned today are left untouched (a missing scan is not a fix)
    """
    entries: dict = ledger["findings"]
    seen_keys = set()
    summary = {"date": _iso(today), "new": 0, "escalated": 0, "fixed": 0, "reopened": 0,
               "open": 0, "overdue": 0, "excepted": 0, "by_priority": {p: 0 for p in PRIORITIES}}
    for f in findings:
        seen_keys.add(f.key)
        e = entries.get(f.key)
        sla_due = today + timedelta(days=f.sla_days)
        if e is None or e.get("status") == "fixed":
            if e is not None and e.get("status") == "fixed":
                summary["reopened"] += 1
            e = {"asset": f.asset_id, "cve": f.cve, "pkg": f.pkg, "first_seen": _iso(today),
                 "due": _iso(sla_due), "fixed_on": None, "time_to_fix_days": None, "history": []}
            summary["new"] += 1
        else:
            old_due = date.fromisoformat(e["due"])
            if PRIORITIES.index(f.priority) < PRIORITIES.index(e.get("priority", "P4")):
                e["due"] = _iso(min(old_due, sla_due))
                e["history"].append(f"{_iso(today)}: escalated {e.get('priority')} -> {f.priority}")
                summary["escalated"] += 1
        e.update({"last_seen": _iso(today), "priority": f.priority, "decision": f.decision,
                  "action": f.action, "installed": f.installed, "fixed_version": f.fixed,
                  "kev": f.kev, "epss": f.epss, "cvss": f.cvss})
        e["status"] = _state_for(f, date.fromisoformat(e["due"]), today)
        f.first_seen = e["first_seen"]  # type: ignore[attr-defined]
        f.due = e["due"]                # type: ignore[attr-defined]
        f.ledger_status = e["status"]   # type: ignore[attr-defined]
        entries[f.key] = e
        if not f.exception:
            summary["by_priority"][f.priority] += 1
        if e["status"] == "overdue":
            summary["overdue"] += 1
            summary["open"] += 1
        elif e["status"] == "open":
            summary["open"] += 1
        else:
            summary["excepted"] += 1
    # Findings that disappeared from an asset scanned today are fixed.
    for key, e in entries.items():
        if key in seen_keys or e.get("status") == "fixed" or e["asset"] not in scanned_assets:
            continue
        e["status"] = "fixed"
        e["fixed_on"] = _iso(today)
        e["time_to_fix_days"] = (today - date.fromisoformat(e["first_seen"])).days
        summary["fixed"] += 1
    ledger["runs"].append(summary)
    return summary


def metrics(ledger: dict, today: date) -> dict:
    """Mean time to remediate per priority (fixed findings only) and the oldest open finding."""
    ttf: dict[str, list[int]] = {p: [] for p in PRIORITIES}
    oldest_open: Optional[tuple[int, str]] = None
    for key, e in ledger["findings"].items():
        if e.get("status") == "fixed" and e.get("time_to_fix_days") is not None:
            ttf.setdefault(e.get("priority", "P4"), []).append(int(e["time_to_fix_days"]))
        elif e.get("status") in ("open", "overdue"):
            age = (today - date.fromisoformat(e["first_seen"])).days
            if oldest_open is None or age > oldest_open[0]:
                oldest_open = (age, key)
    mttr = {p: (round(sum(v) / len(v), 1) if v else None) for p, v in ttf.items()}
    return {"mttr_days": mttr, "fixed_total": sum(len(v) for v in ttf.values()),
            "oldest_open_days": oldest_open[0] if oldest_open else 0,
            "oldest_open_key": oldest_open[1] if oldest_open else None}
