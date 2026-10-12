from datetime import date

import pytest

from conftest import TODAY, finding
from vmp.decide import decide
from vmp.ledger import empty_ledger, load_ledger, metrics, save_ledger, update


def decided(policy, **kw):
    f = finding(**kw)
    decide([f], policy, TODAY)
    return f


def test_new_finding_gets_first_seen_and_due(policy):
    f = decided(policy, asset_id="web", kev=True)  # P1, SLA 7
    L = empty_ledger()
    s = update(L, [f], ["web"], TODAY)
    e = L["findings"][f.key]
    assert e["first_seen"] == "2026-10-12" and e["due"] == "2026-10-19" and e["status"] == "open"
    assert s["new"] == 1 and s["open"] == 1 and s["by_priority"]["P1"] == 1
    assert f.first_seen == "2026-10-12" and f.ledger_status == "open"


def test_seen_again_keeps_first_seen_and_due(policy):
    f = decided(policy, asset_id="web", kev=True)
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    s = update(L, [f], ["web"], date(2026, 10, 15))
    e = L["findings"][f.key]
    assert e["first_seen"] == "2026-10-12" and e["due"] == "2026-10-19" and e["last_seen"] == "2026-10-15"
    assert s["new"] == 0 and s["overdue"] == 0


def test_overdue_after_sla(policy):
    f = decided(policy, asset_id="web", kev=True)
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    s = update(L, [f], ["web"], date(2026, 10, 20))
    assert L["findings"][f.key]["status"] == "overdue" and s["overdue"] == 1 and f.ledger_status == "overdue"


def test_fixed_when_missing_from_scanned_asset(policy):
    f = decided(policy, asset_id="web")
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    s = update(L, [], ["web"], date(2026, 10, 22))
    e = L["findings"][f.key]
    assert e["status"] == "fixed" and e["fixed_on"] == "2026-10-22" and e["time_to_fix_days"] == 10 and s["fixed"] == 1


def test_not_fixed_when_asset_not_scanned(policy):
    f = decided(policy, asset_id="web")
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    s = update(L, [], ["db"], date(2026, 10, 22))   # web was not scanned today
    assert L["findings"][f.key]["status"] == "open" and s["fixed"] == 0


def test_reopened_after_fix(policy):
    f = decided(policy, asset_id="web")
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    update(L, [], ["web"], date(2026, 10, 22))
    s = update(L, [f], ["web"], date(2026, 11, 1))
    e = L["findings"][f.key]
    assert s["reopened"] == 1 and s["new"] == 1 and e["status"] == "open" and e["first_seen"] == "2026-11-01"


def test_escalation_shortens_due_date(policy):
    f = decided(policy, asset_id="db", cvss=5.0, scanner_severity="MEDIUM")   # P4, SLA 180
    L = empty_ledger()
    update(L, [f], ["db"], TODAY)
    assert L["findings"][f.key]["due"] == "2027-04-10"
    f2 = finding(asset_id="db", kev=True)   # same key, now in KEV -> P1
    decide([f2], policy, date(2026, 10, 20))
    s = update(L, [f2], ["db"], date(2026, 10, 20))
    e = L["findings"][f2.key]
    assert s["escalated"] == 1 and e["priority"] == "P1" and e["due"] == "2026-10-27" and e["history"]


def test_de_escalation_never_extends_due(policy):
    f = decided(policy, asset_id="web", kev=True)   # P1, due +7
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    f2 = finding(asset_id="web", cvss=5.0, scanner_severity="MEDIUM")  # P4 now (KEV entry removed, say)
    decide([f2], policy, date(2026, 10, 13))
    update(L, [f2], ["web"], date(2026, 10, 13))
    assert L["findings"][f2.key]["due"] == "2026-10-19"


def test_exception_status_in_ledger(policy):
    policy.exceptions.append({"cve": "CVE-2025-0001", "status": "not_affected", "justification": "a b c d e f",
                              "owner": "x", "expires": "2027-01-01"})
    f = decided(policy, asset_id="web", kev=True)
    L = empty_ledger()
    s = update(L, [f], ["web"], TODAY)
    assert L["findings"][f.key]["status"] == "not_affected" and s["excepted"] == 1 and s["open"] == 0
    assert s["by_priority"]["P1"] == 0   # excepted findings are not counted as work


def test_metrics_mttr_and_oldest(policy):
    a = decided(policy, asset_id="web", kev=True)                    # P1
    b = decided(policy, asset_id="web", cve="CVE-2025-0002")        # P2/P3
    L = empty_ledger()
    update(L, [a, b], ["web"], TODAY)
    update(L, [b], ["web"], date(2026, 10, 17))                     # a fixed after 5 days
    m = metrics(L, date(2026, 10, 30))
    assert m["mttr_days"]["P1"] == 5.0 and m["fixed_total"] == 1
    assert m["oldest_open_days"] == 18 and m["oldest_open_key"] == b.key


def test_save_and_load_roundtrip(tmp_path, policy):
    f = decided(policy, asset_id="web")
    L = empty_ledger()
    update(L, [f], ["web"], TODAY)
    p = tmp_path / "ledger.json"
    save_ledger(L, p)
    L2 = load_ledger(p)
    assert L2["findings"][f.key]["first_seen"] == "2026-10-12" and len(L2["runs"]) == 1


def test_missing_ledger_is_empty(tmp_path):
    assert load_ledger(tmp_path / "none.json") == empty_ledger()


def test_bad_version(tmp_path):
    p = tmp_path / "l.json"
    p.write_text('{"version": 9}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_ledger(p)
