"""Outputs: HTML report (French, for the business owner + technical annex), summary.json,
tickets.csv (one row per package upgrade) and openvex.json (exceptions as VEX statements)."""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .model import Finding, PRIORITIES

TEMPLATES = Path(__file__).parent / "templates"
PRIORITY_LABEL = {"P1": "Agir maintenant", "P2": "Traiter ce mois-ci", "P3": "Planifier", "P4": "Suivre"}
VEX_STATUS = {"not_affected": "not_affected", "false_positive": "not_affected", "accepted": "affected"}


def fix_plan(findings: list[Finding]) -> list[dict]:
    """Group open findings by (asset, package, fixed version): one upgrade closes N CVEs.

    Sorted by the best priority in the group, then by the number of CVEs closed."""
    groups: dict[tuple, dict] = {}
    for f in findings:
        if f.action != "patch":
            continue
        k = (f.asset_id, f.pkg, f.fixed or "")
        g = groups.setdefault(k, {"asset": f.asset_id, "pkg": f.pkg, "installed": f.installed,
                                  "fixed": f.fixed, "cves": [], "priority": "P4", "due": None, "kev": 0})
        g["cves"].append(f.cve)
        if PRIORITIES.index(f.priority) < PRIORITIES.index(g["priority"]):
            g["priority"] = f.priority
        due = getattr(f, "due", None)
        if due and (g["due"] is None or due < g["due"]):
            g["due"] = due
        g["kev"] += int(f.kev)
    out = sorted(groups.values(), key=lambda g: (PRIORITIES.index(g["priority"]), -len(g["cves"]), g["asset"], g["pkg"]))
    for g in out:
        g["n"] = len(g["cves"])
        g["cves"] = sorted(g["cves"])
    return out


def build_summary(findings: list[Finding], run: dict, metrics: dict, feeds_info: dict, policy, assets_meta: dict,
                  gate: dict, today: date) -> dict:
    by_asset: dict[str, dict] = {}
    for a in policy.assets:
        fs = [f for f in findings if f.asset_id == a.id]
        by_asset[a.id] = {
            "name": a.name, "ref": a.ref, "exposure": a.exposure, "criticality": a.criticality, "owner": a.owner,
            "total": len(fs),
            "by_priority": {p: sum(1 for f in fs if f.priority == p and f.action in ("patch", "mitigate")) for p in PRIORITIES},
            "kev": sum(1 for f in fs if f.kev), "no_fix": sum(1 for f in fs if f.action == "mitigate"),
            "excepted": sum(1 for f in fs if f.exception), "meta": assets_meta.get(a.id, {}),
        }
    actionable = [f for f in findings if f.action in ("patch", "mitigate")]
    plan = fix_plan(findings)
    return {
        "organisation": policy.organisation, "date": today.isoformat(),
        "feeds": feeds_info, "sla_days": policy.sla, "thresholds": policy.thresholds,
        "totals": {
            "findings": len(findings), "distinct_cves": len({f.cve for f in findings}),
            "actionable": len(actionable), "actionable_distinct_cves": len({f.cve for f in actionable}),
            "by_priority": {p: sum(1 for f in actionable if f.priority == p) for p in PRIORITIES},
            "kev": sum(1 for f in findings if f.kev), "kev_actionable": sum(1 for f in actionable if f.kev),
            "epss_likely": sum(1 for f in actionable if f.exploitation == "likely"),
            "no_fix": sum(1 for f in actionable if f.action == "mitigate"),
            "excepted": sum(1 for f in findings if f.exception),
            "scanner_severity": {s: sum(1 for f in findings if f.scanner_severity == s)
                                 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")},
        },
        "run": run, "metrics": metrics, "assets": by_asset,
        "plan_top": plan[:10], "plan_total": len(plan), "gate": gate,
        "expired_exceptions": [e["cve"] for e in policy.expired_exceptions(today)],
    }


def write_outputs(out_dir: str | Path, findings: list[Finding], summary: dict, policy) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}
    # 1. summary.json
    p = out / "summary.json"
    p.write_text(json.dumps(summary, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8", newline="\n")
    paths["summary"] = str(p)
    # 2. findings.json (everything, for other tools)
    p = out / "findings.json"
    rows = []
    for f in findings:
        d = f.to_dict()
        d["first_seen"] = getattr(f, "first_seen", None)
        d["due"] = getattr(f, "due", None)
        d["ledger_status"] = getattr(f, "ledger_status", None)
        rows.append(d)
    p.write_text(json.dumps(rows, ensure_ascii=False, indent=0, sort_keys=True), encoding="utf-8", newline="\n")
    paths["findings"] = str(p)
    # 3. tickets.csv : one line per package upgrade (what a sysadmin or a hosting provider gets)
    p = out / "tickets.csv"
    with open(p, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["priority", "due", "asset", "package", "installed", "fixed_version", "cves_closed", "kev", "cve_list"])
        for g in fix_plan(findings):
            w.writerow([g["priority"], g["due"] or "", g["asset"], g["pkg"], g["installed"], g["fixed"],
                        g["n"], g["kev"], " ".join(g["cves"])])
    paths["tickets"] = str(p)
    # 4. openvex.json : exceptions become machine-readable VEX statements
    p = out / "openvex.json"
    p.write_text(json.dumps(openvex(findings, summary["date"]), ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    paths["openvex"] = str(p)
    # 5. report.html
    # autoescape=True unconditionally: select_autoescape() keys on the file extension and would
    # leave a ".j2" template unescaped (caught by test_html_escapes_untrusted_scanner_text).
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True)
    env.filters["pct"] = lambda v: ("" if v is None else f"{v:.1%}")
    env.filters["num"] = lambda v: ("" if v is None else f"{v:,}".replace(",", " "))
    tpl = env.get_template("report.html.j2")
    actionable = sorted([f for f in findings if f.action in ("patch", "mitigate")],
                        key=lambda f: (PRIORITIES.index(f.priority), -(f.epss or 0), -(f.cvss or 0), f.asset_id, f.cve))
    html = tpl.render(s=summary, labels=PRIORITY_LABEL, priorities=PRIORITIES,
                      top=actionable[:60], excepted=exception_groups(findings), plan=fix_plan(findings)[:25],
                      n_actionable=len(actionable))
    p = out / "report.html"
    p.write_text(html, encoding="utf-8", newline="\n")
    paths["report"] = str(p)
    return paths


def exception_groups(findings: list[Finding]) -> list[dict]:
    """One row per exception rule (asset, package, status, owner, expiry): a component-level
    rule can cover thousands of CVEs; listing them one by one would hide the real decisions."""
    groups: dict[tuple, dict] = {}
    for f in findings:
        if not f.exception:
            continue
        k = (f.asset_id, f.pkg, f.exception["status"], f.exception["owner"], f.exception["expires"])
        g = groups.setdefault(k, {"asset": f.asset_id, "pkg": f.pkg, "status": f.exception["status"],
                                  "owner": f.exception["owner"], "expires": f.exception["expires"],
                                  "justification": f.exception["justification"], "cves": [], "kev": 0})
        g["cves"].append(f.cve)
        g["kev"] += int(f.kev)
    out = sorted(groups.values(), key=lambda g: (-len(g["cves"]), g["asset"], g["pkg"]))
    for g in out:
        g["n"] = len(g["cves"])
        g["cves"] = sorted(g["cves"])
    return out


def openvex(findings: list[Finding], today: str) -> dict:
    """Minimal OpenVEX document (https://github.com/openvex/spec) from the active exceptions."""
    statements = []
    for f in findings:
        if not f.exception:
            continue
        status = VEX_STATUS[f.exception["status"]]
        st = {
            "vulnerability": {"name": f.cve},
            "products": [{"@id": f"pkg:{f.pkg_type or 'generic'}/{f.pkg}@{f.installed}", "asset": f.asset_id}],
            "status": status,
            "timestamp": today,
            "action_statement" if status == "affected" else "justification":
                ("vulnerable_code_not_in_execute_path" if status == "not_affected" else f.exception["justification"]),
        }
        if status == "not_affected":
            st["impact_statement"] = f.exception["justification"]
        statements.append(st)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://agrisouss.example/vex/{today}",
            "author": "AgriSouss SARL (fictitious) - vulnerability management", "timestamp": today,
            "version": 1, "statements": statements}
