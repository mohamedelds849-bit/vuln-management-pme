import csv
import json
from datetime import date

from conftest import TODAY, finding
from vmp.decide import decide
from vmp.gate import evaluate
from vmp.ledger import empty_ledger, metrics, update
from vmp.report import build_summary, fix_plan, openvex, write_outputs

FEEDS_INFO = {"kev_version": "2026.10.08", "kev_count": 1739, "epss_date": "2026-10-11", "epss_model": "v1",
              "age_days": {"kev": 4, "epss": 1}, "stale": []}


def run_pipeline(policy, findings, today=TODAY, scanned=("web", "db", "lab", "hr"), ledger=None):
    decide(findings, policy, today)
    L = ledger if ledger is not None else empty_ledger()
    s = update(L, findings, list(scanned), today)
    gate = evaluate(findings, s, [], policy.gate)
    summary = build_summary(findings, s, metrics(L, today), FEEDS_INFO, policy, {}, gate, today)
    return L, s, gate, summary


def test_fix_plan_groups_one_upgrade_per_package(policy):
    fs = [finding(asset_id="web", cve="CVE-1", pkg="openssl", fixed="2"), finding(asset_id="web", cve="CVE-2", pkg="openssl", fixed="2", kev=True),
          finding(asset_id="web", cve="CVE-3", pkg="curl", fixed="9", cvss=5.0, scanner_severity="MEDIUM"),
          finding(asset_id="web", cve="CVE-4", pkg="zlib", fixed=None)]
    decide(fs, policy, TODAY)
    plan = fix_plan(fs)
    assert [g["pkg"] for g in plan] == ["openssl", "curl"]        # no-fix finding is not a ticket
    assert plan[0]["n"] == 2 and plan[0]["kev"] == 1 and plan[0]["priority"] == "P1" and plan[0]["cves"] == ["CVE-1", "CVE-2"]


def test_gate_new_p1_internet_fails(policy):
    L, s, gate, _ = run_pipeline(policy, [finding(asset_id="web", kev=True)])
    assert not gate["passed"] and gate["failures"] == ["new_P1_internet=1"]


def test_gate_new_p1_internal_passes_with_default_rules(policy):
    L, s, gate, _ = run_pipeline(policy, [finding(asset_id="db", kev=True)])
    assert gate["passed"] and gate["facts"]["new_P1"] == 1 and gate["facts"]["new_P1_internet"] == 0


def test_gate_excepted_p1_does_not_fail(policy):
    policy.exceptions.append({"cve": "CVE-2025-0001", "status": "not_affected", "justification": "a b c d e f",
                              "owner": "x", "expires": "2027-01-01"})
    L, s, gate, _ = run_pipeline(policy, [finding(asset_id="web", kev=True)])
    assert gate["passed"]


def test_gate_overdue_p1_fails_later(policy):
    f = finding(asset_id="db", kev=True)   # internal: new P1 does not fail, overdue does
    L, s, gate, _ = run_pipeline(policy, [f])
    assert gate["passed"]
    f2 = finding(asset_id="db", kev=True)
    L, s, gate, _ = run_pipeline(policy, [f2], today=date(2026, 10, 20), ledger=L)
    assert not gate["passed"] and gate["failures"] == ["overdue_P1=1"]


def test_gate_warnings_and_stale(policy):
    f = finding(asset_id="web", cvss=8.0)   # P3 on internet/high... check: unlikely, internet, high -> P3
    decide([f], policy, TODAY)
    s = update(empty_ledger(), [f], ["web"], TODAY)
    g = evaluate([f], s, ["kev"], {"fail_on": [], "warn_on": ["stale_feeds"]})
    assert g["passed"] and g["warnings"] == ["stale_feeds=1"]
    g = evaluate([f], s, ["kev"], {"fail_on": ["stale_feeds"], "warn_on": []})
    assert not g["passed"]


def test_summary_counts(policy):
    fs = [finding(asset_id="web", kev=True), finding(asset_id="web", cve="CVE-2", epss=0.5, cvss=9.8),
          finding(asset_id="db", cve="CVE-3", fixed=None, cvss=5.0, scanner_severity="MEDIUM")]
    _, _, _, summ = run_pipeline(policy, fs)
    t = summ["totals"]
    assert t["findings"] == 3 and t["distinct_cves"] == 3 and t["kev"] == 1 and t["epss_likely"] == 1 and t["no_fix"] == 1
    assert t["by_priority"]["P1"] == 2 and summ["assets"]["web"]["by_priority"]["P1"] == 2
    assert summ["assets"]["lab"]["total"] == 0 and summ["plan_total"] == 1   # CVE-1 and CVE-2 share one libfoo upgrade


def test_write_outputs_files(tmp_path, policy):
    policy.exceptions.append({"cve": "CVE-9", "status": "not_affected", "justification": "a b c d e f",
                              "owner": "x", "expires": "2027-01-01"})
    fs = [finding(asset_id="web", kev=True), finding(asset_id="web", cve="CVE-9", pkg="hdr", fixed=None),
          finding(asset_id="db", cve="CVE-3", pkg="p", cvss=5.0, scanner_severity="MEDIUM")]
    _, _, _, summ = run_pipeline(policy, fs)
    paths = write_outputs(tmp_path / "out", fs, summ, policy)
    html = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert "TestCo" in html and "CVE-2025-0001" in html and "P1" in html and "CVE-9" in html and "hdr" in html
    assert "<script" not in html
    rows = list(csv.DictReader(open(paths["tickets"], encoding="utf-8")))
    assert {r["package"] for r in rows} == {"libfoo", "p"} and rows[0]["priority"] == "P1"
    vex = json.loads((tmp_path / "out" / "openvex.json").read_text(encoding="utf-8"))
    assert vex["statements"][0]["vulnerability"]["name"] == "CVE-9" and vex["statements"][0]["status"] == "not_affected"
    fj = json.loads((tmp_path / "out" / "findings.json").read_text(encoding="utf-8"))
    assert len(fj) == 3 and fj[0]["first_seen"] == "2026-10-12"
    assert json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))["gate"]["passed"] is False


def test_html_escapes_untrusted_scanner_text(tmp_path, policy):
    """A package name or title coming from a scan must never become HTML."""
    fs = [finding(asset_id="web", pkg="<script>alert(1)</script>", title="<b>x</b>")]
    _, _, _, summ = run_pipeline(policy, fs)
    write_outputs(tmp_path / "out", fs, summ, policy)
    html = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_openvex_statuses():
    a = finding(exception={"status": "accepted", "justification": "j", "owner": "o", "expires": "2027-01-01"})
    b = finding(cve="CVE-2", exception={"status": "false_positive", "justification": "j", "owner": "o", "expires": "2027-01-01"})
    c = finding(cve="CVE-3")
    doc = openvex([a, b, c], "2026-10-12")
    assert [s["status"] for s in doc["statements"]] == ["affected", "not_affected"]
    assert doc["statements"][0]["action_statement"] == "j" and doc["statements"][1]["justification"] == "vulnerable_code_not_in_execute_path"
