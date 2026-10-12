import json

import pytest

from conftest import FIX, trivy_doc, vuln
from vmp.ingest import count_by, load_trivy, parse_trivy, scan_metadata


def test_parse_basic_fields():
    fs = parse_trivy(trivy_doc([vuln()]), "web")
    assert len(fs) == 1
    f = fs[0]
    assert (f.asset_id, f.cve, f.pkg, f.installed, f.fixed) == ("web", "CVE-2025-0001", "libfoo", "1.0-1", "1.0-2")
    assert f.scanner_severity == "HIGH" and f.cvss == 7.5 and f.cvss_vector.startswith("CVSS:3.1")
    assert f.target.startswith("img") and f.pkg_type == "debian" and f.status == "fixed"
    assert f.published == "2025-01-01" and f.fix_available and f.key == "web|CVE-2025-0001|libfoo"


def test_no_fixed_version_means_none():
    f = parse_trivy(trivy_doc([vuln(fixed="", status="affected")]), "web")[0]
    assert f.fixed is None and not f.fix_available


def test_cvss_source_order_nvd_first_then_others():
    v = vuln(score=None)
    v["CVSS"] = {"redhat": {"V3Score": 5.5}, "nvd": {"V3Score": 9.1, "V3Vector": "CVSS:3.1/x"}}
    assert parse_trivy(trivy_doc([v]), "web")[0].cvss == 9.1
    v["CVSS"] = {"redhat": {"V3Score": 5.5}, "ghsa": {"V3Score": 6.0}}
    assert parse_trivy(trivy_doc([v]), "web")[0].cvss == 6.0
    v["CVSS"] = {"redhat": {"V3Score": 5.5}}
    assert parse_trivy(trivy_doc([v]), "web")[0].cvss == 5.5
    v["CVSS"] = {"nvd": {"V2Score": 7.5}}   # v2 only: ignored on purpose
    assert parse_trivy(trivy_doc([v]), "web")[0].cvss is None


def test_same_cve_same_package_twice_is_kept_once():
    fs = parse_trivy(trivy_doc([vuln(), vuln()]), "web")
    assert len(fs) == 1


def test_same_cve_two_packages_are_two_findings():
    fs = parse_trivy(trivy_doc([vuln(pkg="libssl3"), vuln(pkg="openssl")]), "web")
    assert {f.pkg for f in fs} == {"libssl3", "openssl"}


def test_missing_ids_are_skipped():
    v = vuln()
    del v["VulnerabilityID"]
    assert parse_trivy(trivy_doc([v]), "web") == []


def test_unknown_severity_and_schema():
    f = parse_trivy(trivy_doc([vuln(severity=None)]), "web")[0]
    assert f.scanner_severity == "UNKNOWN"
    with pytest.raises(ValueError):
        parse_trivy({"SchemaVersion": 1, "Results": []}, "web")


def test_results_without_vulnerabilities_key():
    doc = trivy_doc([])
    del doc["Results"][0]["Vulnerabilities"]
    assert parse_trivy(doc, "web") == []


def test_real_mariadb_excerpt():
    fs = load_trivy(FIX / "scans" / "mariadb_11.4.json", "db")
    assert len(fs) == 76
    assert count_by(fs, "pkg_type") == {"gobinary": 60, "ubuntu": 16}
    meta = scan_metadata(FIX / "scans" / "mariadb_11.4.json")
    assert meta["artifact"] == "mariadb:11.4" and meta["os"] == "ubuntu 24.04"
    assert meta["repo_digests"][0].startswith("mariadb@sha256:")


def test_load_from_file(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(trivy_doc([vuln()])), encoding="utf-8")
    assert len(load_trivy(p, "web")) == 1
