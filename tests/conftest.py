import json
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vmp.feeds import load_feeds  # noqa: E402
from vmp.model import Finding  # noqa: E402
from vmp.policy import Policy  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
TODAY = date(2026, 10, 12)


def trivy_doc(vulns, target="img (debian 12.11)", artifact="img:1", os_name="12.11"):
    """Build a minimal Trivy JSON v2 document from a list of vulnerability dicts."""
    return {"SchemaVersion": 2, "CreatedAt": "2026-10-12T02:00:00Z", "ArtifactName": artifact,
            "ArtifactType": "container_image",
            "Metadata": {"OS": {"Family": "debian", "Name": os_name}, "RepoDigests": [f"{artifact}@sha256:abc"]},
            "Results": [{"Target": target, "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": vulns}]}


def vuln(cve="CVE-2025-0001", pkg="libfoo", installed="1.0-1", fixed="1.0-2", severity="HIGH", score=7.5,
         status="fixed", **extra):
    v = {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": installed, "Severity": severity,
         "Status": status, "Title": f"{pkg}: something", "PublishedDate": "2025-01-01T00:00:00Z"}
    if fixed:
        v["FixedVersion"] = fixed
    if score is not None:
        v["CVSS"] = {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": score}}
    v.update(extra)
    return v


def finding(**kw) -> Finding:
    base = dict(asset_id="web", cve="CVE-2025-0001", pkg="libfoo", installed="1.0-1", fixed="1.0-2",
                scanner_severity="HIGH", cvss=7.5)
    base.update(kw)
    return Finding(**base)


POLICY_DOC = {
    "organisation": "TestCo",
    "assets": [
        {"id": "web", "name": "Web", "ref": "img:1", "scan": "", "exposure": "internet", "criticality": "high"},
        {"id": "db", "name": "DB", "ref": "db:1", "scan": "", "exposure": "internal", "criticality": "high"},
        {"id": "lab", "name": "Lab", "ref": "lab:1", "scan": "", "exposure": "isolated", "criticality": "low"},
        {"id": "hr", "name": "HR tool", "ref": "hr:1", "scan": "", "exposure": "internal", "criticality": "low"},
    ],
    "sla_days": {"P1": 7, "P2": 30, "P3": 90, "P4": 180},
    "thresholds": {"epss_likely": 0.10, "cvss_total": 9.0, "cvss_high": 7.0},
    "gate": {"fail_on": ["overdue_P1", "new_P1_internet"], "warn_on": ["overdue_P2", "stale_feeds"]},
    "exceptions": [],
}


@pytest.fixture
def policy(tmp_path) -> Policy:
    return Policy(json.loads(json.dumps(POLICY_DOC)), tmp_path)


@pytest.fixture
def feeds():
    return load_feeds(FIX / "feeds")


@pytest.fixture
def project_tmp(tmp_path):
    """A copy of the real project layout (policy + committed scans + feed snapshot) in tmp."""
    (tmp_path / "data" / "scans").mkdir(parents=True)
    (tmp_path / "data" / "feeds").mkdir(parents=True)
    for p in (ROOT / "data" / "scans").glob("*.json"):
        (tmp_path / "data" / "scans" / p.name).write_bytes(p.read_bytes())
    for p in (FIX / "feeds").iterdir():
        (tmp_path / "data" / "feeds" / p.name).write_bytes(p.read_bytes())
    (tmp_path / "policy.yml").write_text((ROOT / "policy.yml").read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def write_policy(path: Path, doc: dict) -> Path:
    path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path
