"""The decision tree, case by case. Each row: exploitation, exposure, impact, criticality -> priority."""
from datetime import date

import pytest

from conftest import TODAY, finding
from vmp.decide import decide, exploitation, impact, priority

T = {"epss_likely": 0.10, "cvss_total": 9.0, "cvss_high": 7.0}


@pytest.mark.parametrize("kev,epss,expected", [
    (True, None, "active"), (True, 0.0, "active"), (False, 0.10, "likely"), (False, 0.5, "likely"),
    (False, 0.099, "unlikely"), (False, None, "unlikely"),
])
def test_exploitation(kev, epss, expected):
    assert exploitation(finding(kev=kev, epss=epss), T) == expected


@pytest.mark.parametrize("cvss,sev,expected", [
    (9.8, "HIGH", "total"), (9.0, "LOW", "total"), (None, "CRITICAL", "total"),
    (8.9, "MEDIUM", "high"), (7.0, "LOW", "high"), (None, "HIGH", "high"),
    (6.9, "MEDIUM", "partial"), (None, "LOW", "partial"), (None, "UNKNOWN", "partial"),
])
def test_impact(cvss, sev, expected):
    assert impact(finding(cvss=cvss, scanner_severity=sev), T) == expected


@pytest.mark.parametrize("expl,exposure,imp,crit,expected", [
    # KEV: internet or critical asset -> P1, otherwise P2
    ("active", "internet", "partial", "low", "P1"),
    ("active", "internal", "partial", "high", "P1"),
    ("active", "isolated", "total", "high", "P1"),
    ("active", "internal", "total", "low", "P2"),
    ("active", "isolated", "partial", "medium", "P2"),
    # EPSS likely
    ("likely", "internet", "total", "low", "P1"),
    ("likely", "internet", "high", "low", "P2"),
    ("likely", "internal", "total", "low", "P2"),
    ("likely", "internet", "partial", "high", "P3"),   # old CVE with high EPSS but low impact: plan, not panic
    ("likely", "internal", "high", "high", "P3"),
    ("likely", "isolated", "partial", "low", "P3"),
    # no known exploitation
    ("unlikely", "internet", "total", "high", "P2"),
    ("unlikely", "internet", "total", "low", "P3"),
    ("unlikely", "internal", "total", "high", "P3"),
    ("unlikely", "internet", "high", "low", "P3"),
    ("unlikely", "internal", "high", "high", "P4"),
    ("unlikely", "internet", "partial", "high", "P4"),
    ("unlikely", "isolated", "total", "low", "P3"),
    ("unlikely", "isolated", "partial", "high", "P4"),
])
def test_priority_table(expl, exposure, imp, crit, expected):
    p, reason = priority(expl, exposure, imp, crit)
    assert p == expected and reason


def test_priority_never_worse_when_exploitation_increases():
    """Monotonicity: for every exposure/impact/criticality, active <= likely <= unlikely (P1 best)."""
    order = ["active", "likely", "unlikely"]
    for exposure in ("internet", "internal", "isolated"):
        for imp in ("total", "high", "partial"):
            for crit in ("high", "medium", "low"):
                ps = [priority(e, exposure, imp, crit)[0] for e in order]
                assert ps == sorted(ps), (exposure, imp, crit, ps)


def test_decide_fills_everything(policy):
    f = finding(asset_id="web", kev=True, kev_date_added="2026-01-01", kev_ransomware=True, epss=0.9, epss_percentile=0.99, cvss=9.8)
    decide([f], policy, TODAY)
    assert (f.exploitation, f.exposure, f.impact, f.priority, f.decision, f.sla_days, f.action) == \
        ("active", "internet", "total", "P1", "Act", 7, "patch")
    assert any("KEV" in r for r in f.reasons) and any("ran" in r for r in f.reasons) and any("EPSS 90.0%" in r for r in f.reasons)


def test_decide_no_fix_is_mitigate(policy):
    f = finding(asset_id="db", fixed=None, status="will_not_fix")
    decide([f], policy, TODAY)
    assert f.action == "mitigate" and any("will_not_fix" in r for r in f.reasons)


def test_decide_exception_wins_over_patch(policy):
    policy.exceptions.append({"cve": "CVE-2025-0001", "status": "accepted", "justification": "one two three four five",
                              "owner": "me", "expires": "2027-01-01"})
    f = finding(asset_id="web")
    decide([f], policy, TODAY)
    assert f.action == "accepted" and f.exception["owner"] == "me"


def test_decide_expired_exception_is_ignored(policy):
    policy.exceptions.append({"cve": "CVE-2025-0001", "status": "accepted", "justification": "one two three four five",
                              "owner": "me", "expires": "2026-10-11"})
    f = finding(asset_id="web")
    decide([f], policy, TODAY)
    assert f.action == "patch" and f.exception is None


def test_thresholds_come_from_policy(policy):
    policy.thresholds["epss_likely"] = 0.5
    f = finding(asset_id="web", epss=0.3, cvss=9.8)
    decide([f], policy, TODAY)
    assert f.exploitation == "unlikely" and f.priority == "P2"


def test_unknown_asset_raises(policy):
    with pytest.raises(KeyError):
        decide([finding(asset_id="nope")], policy, TODAY)
