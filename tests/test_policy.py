import copy
from datetime import date

import pytest

from conftest import POLICY_DOC, ROOT, TODAY, finding, write_policy
from vmp.policy import Policy, load_policy


def doc(**changes):
    d = copy.deepcopy(POLICY_DOC)
    d.update(changes)
    return d


def test_real_policy_loads():
    p = load_policy(ROOT / "policy.yml")
    assert [a.id for a in p.assets] == ["web-proxy", "web-app", "db", "portal-deps"]
    assert p.sla == {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
    assert p.asset("db").exposure == "internal" and p.asset("web-app").criticality == "high"
    assert len(p.exceptions) == 2 and p.exceptions[0]["cve"] == "*"


def test_defaults_when_sections_missing(tmp_path):
    p = Policy({"assets": []}, tmp_path)
    assert p.sla["P1"] == 7 and p.thresholds["epss_likely"] == 0.10 and "overdue_P1" in p.gate["fail_on"]


@pytest.mark.parametrize("bad", [
    {"id": "x", "name": "x", "exposure": "cloud", "criticality": "high"},
    {"id": "x", "name": "x", "exposure": "internet", "criticality": "urgent"},
])
def test_asset_validation(tmp_path, bad):
    with pytest.raises(ValueError):
        Policy(doc(assets=[bad]), tmp_path)


def test_duplicate_asset_id(tmp_path):
    a = POLICY_DOC["assets"][0]
    with pytest.raises(ValueError, match="duplicate"):
        Policy(doc(assets=[a, a]), tmp_path)


def test_sla_must_be_positive(tmp_path):
    with pytest.raises(ValueError):
        Policy(doc(sla_days={"P1": 0}), tmp_path)


def test_unknown_gate_rule(tmp_path):
    with pytest.raises(ValueError, match="unknown gate rule"):
        Policy(doc(gate={"fail_on": ["panic"]}), tmp_path)


def good_exc(**kw):
    e = {"cve": "CVE-2025-0001", "status": "accepted", "justification": "words words words words words",
         "owner": "someone", "expires": "2027-01-01"}
    e.update(kw)
    return e


@pytest.mark.parametrize("bad", [
    good_exc(owner=""), good_exc(justification="too short"), good_exc(status="ignored"),
    good_exc(expires="soon"), good_exc(cve="*", package=None),
])
def test_exception_validation(tmp_path, bad):
    with pytest.raises(ValueError):
        Policy(doc(exceptions=[bad]), tmp_path)


def test_exception_matching(tmp_path):
    p = Policy(doc(exceptions=[good_exc(asset="web", package="libfoo")]), tmp_path)
    assert p.find_exception(finding(asset_id="web", pkg="libfoo"), TODAY)
    assert p.find_exception(finding(asset_id="db", pkg="libfoo"), TODAY) is None
    assert p.find_exception(finding(asset_id="web", pkg="other"), TODAY) is None
    assert p.find_exception(finding(asset_id="web", pkg="libfoo", cve="CVE-2025-0002"), TODAY) is None


def test_wildcard_component_exception(tmp_path):
    p = Policy(doc(exceptions=[good_exc(cve="*", package="linux-libc-dev", status="not_affected")]), tmp_path)
    assert p.find_exception(finding(cve="CVE-2004-0230", pkg="linux-libc-dev"), TODAY)
    assert p.find_exception(finding(cve="CVE-2004-0230", pkg="linux-image"), TODAY) is None


def test_expiry(tmp_path):
    p = Policy(doc(exceptions=[good_exc(expires=date(2026, 10, 11))]), tmp_path)
    assert p.find_exception(finding(), TODAY) is None
    assert p.expired_exceptions(TODAY) and not p.expired_exceptions(date(2026, 10, 1))


def test_load_from_yaml_file(tmp_path):
    path = write_policy(tmp_path / "policy.yml", doc())
    p = load_policy(path)
    assert p.organisation == "TestCo" and p.base_dir == tmp_path
