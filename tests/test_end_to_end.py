"""End to end on the REAL committed scans (nginx, WordPress, MariaDB images scanned by Trivy on
2026-10-12) with the dated KEV / EPSS snapshot. These numbers are the ones quoted in the README."""
import json
import subprocess
import sys

import yaml

from conftest import ROOT


def run(tmp, *extra):
    cmd = [sys.executable, "-m", "vmp", "run", "--policy", "policy.yml", "--feeds", "data/feeds",
           "--ledger", "data/ledger.json", "--out", "reports", "--today", "2026-10-12", *extra]
    return subprocess.run(cmd, cwd=tmp, capture_output=True, text=True, env={"PYTHONPATH": str(ROOT), "PYTHONUTF8": "1"})


def test_real_scans_first_run(project_tmp):
    r = run(project_tmp)
    assert r.returncode == 1, r.stderr          # first run: 5 new P1 on internet-facing assets -> gate red
    s = json.loads((project_tmp / "reports" / "summary.json").read_text(encoding="utf-8"))
    t = s["totals"]
    assert t["findings"] == 9540 and t["distinct_cves"] == 7251
    assert t["kev"] == 3 and t["kev_actionable"] == 0          # the 3 KEV hits are kernel CVEs on linux-libc-dev
    assert t["excepted"] == 6259 and t["actionable"] == 3281
    assert t["by_priority"] == {"P1": 5, "P2": 96, "P3": 993, "P4": 2187}
    assert s["gate"]["failures"] == ["new_P1_internet=5"]
    # the 5 P1 are one CVE (CVE-2025-15467, OpenSSL, EPSS 52 %) on 5 binary packages of 2 images
    fj = json.loads((project_tmp / "reports" / "findings.json").read_text(encoding="utf-8"))
    p1 = [f for f in fj if f["priority"] == "P1" and f["action"] == "patch"]
    assert {f["cve"] for f in p1} == {"CVE-2025-15467"} and {f["asset_id"] for f in p1} == {"web-proxy", "web-app"}
    assert s["plan_top"][0]["priority"] == "P1" and s["plan_total"] == 257
    assert (project_tmp / "data" / "ledger.json").exists()
    assert "[gate] FAIL" in r.stdout


def test_real_scans_second_run_fixed_and_overdue(project_tmp):
    run(project_tmp)
    # 20 days later: nginx got its OpenSSL and curl updates, nothing else changed
    scan = project_tmp / "data" / "scans" / "nginx_1.27.json"
    d = json.loads(scan.read_text(encoding="utf-8"))
    for res in d["Results"]:
        res["Vulnerabilities"] = [v for v in res["Vulnerabilities"]
                                  if not (v["PkgName"] in ("openssl", "libssl3", "curl", "libcurl4") and v.get("FixedVersion"))]
    scan.write_text(json.dumps(d), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "vmp", "run", "--today", "2026-11-01"], cwd=project_tmp,
                       capture_output=True, text=True, env={"PYTHONPATH": str(ROOT), "PYTHONUTF8": "1"})
    assert r.returncode == 1
    s = json.loads((project_tmp / "reports" / "summary.json").read_text(encoding="utf-8"))
    assert s["run"]["fixed"] == 76 and s["run"]["new"] == 0
    assert s["gate"]["failures"] == ["overdue_P1=3"]          # WordPress OpenSSL still not patched after 20 days
    assert "stale_feeds=2" in s["gate"]["warnings"]           # feeds dated 2026-10-11 are 21 days old
    assert s["metrics"]["mttr_days"]["P1"] == 20.0


def test_gate_command(project_tmp):
    run(project_tmp)
    r = subprocess.run([sys.executable, "-m", "vmp", "gate", "--summary", "reports/summary.json"], cwd=project_tmp,
                       capture_output=True, text=True, env={"PYTHONPATH": str(ROOT), "PYTHONUTF8": "1"})
    assert r.returncode == 1 and r.stdout.startswith("FAIL")


def test_missing_scan_is_skipped_not_fixed(project_tmp):
    run(project_tmp)
    (project_tmp / "data" / "scans" / "mariadb_11.4.json").unlink()
    r = run(project_tmp)
    assert "[warn] asset db: no scan file" in r.stdout
    s = json.loads((project_tmp / "reports" / "summary.json").read_text(encoding="utf-8"))
    assert s["run"]["fixed"] == 0


def test_mutation_policy_tamper_is_visible(project_tmp):
    """Change the SLA or the EPSS threshold in policy.yml and the outputs must change: the
    decisions really come from the policy, not from constants hidden in the code."""
    doc = yaml.safe_load((project_tmp / "policy.yml").read_text(encoding="utf-8"))
    doc["thresholds"]["epss_likely"] = 0.90
    doc["sla_days"]["P1"] = 2
    (project_tmp / "policy.yml").write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    run(project_tmp)
    s = json.loads((project_tmp / "reports" / "summary.json").read_text(encoding="utf-8"))
    assert s["totals"]["by_priority"]["P1"] == 0           # OpenSSL EPSS 52 % < 90 % -> no longer P1
    assert s["sla_days"]["P1"] == 2
