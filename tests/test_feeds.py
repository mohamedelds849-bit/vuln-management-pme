from datetime import date

import pytest

from conftest import FIX, TODAY, finding
from vmp.feeds import Feeds, enrich, load_feeds, parse_epss, parse_kev


def test_parse_kev_fields():
    doc = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-0001", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": ""},
    ]}
    kev = parse_kev(doc)
    assert set(kev) == {"CVE-2021-44228", "CVE-2024-0001"}
    assert kev["CVE-2021-44228"].ransomware is True and kev["CVE-2021-44228"].due_date == "2021-12-24"
    assert kev["CVE-2024-0001"].ransomware is False


def test_parse_epss_header_and_rows():
    text = "#model_version:v2026.06.15,score_date:2026-10-11T12:00:25Z\ncve,epss,percentile\nCVE-1,0.5,0.9\nCVE-2,bad,x\n"
    epss, score_date, model = parse_epss(text)
    assert epss == {"CVE-1": (0.5, 0.9)} and score_date == "2026-10-11" and model == "v2026.06.15"


def test_parse_epss_without_header():
    epss, score_date, model = parse_epss("cve,epss,percentile\nCVE-1,0.1,0.2\n")
    assert epss == {"CVE-1": (0.1, 0.2)} and score_date == "" and model == ""


def test_snapshot_feeds_load():
    f = load_feeds(FIX / "feeds")
    assert f.kev_version == "2026.10.08" and f.kev_count == 1739
    assert "CVE-2021-44228" in f.kev and f.epss["CVE-2021-44228"][0] > 0.9
    assert f.epss_date == "2026-10-11"


def test_missing_feeds_raise(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_feeds(tmp_path)


def test_enrich_sets_kev_and_epss():
    f = load_feeds(FIX / "feeds")
    a, b = finding(cve="CVE-2021-44228"), finding(cve="CVE-1999-9999")
    enrich([a, b], f)
    assert a.kev and a.kev_date_added == "2021-12-10" and a.epss > 0.9 and a.epss_percentile > 0.99
    assert not b.kev and b.epss is None


def test_feed_age_and_staleness():
    f = Feeds(kev={}, epss={}, kev_version="2026.10.08", kev_count=0, epss_date="2026-10-11", epss_model="")
    assert f.age_days(TODAY) == {"kev": 4, "epss": 1}
    assert f.stale(TODAY) == []
    assert f.stale(date(2026, 10, 20)) == ["kev", "epss"]
    bad = Feeds(kev={}, epss={}, kev_version="", kev_count=0, epss_date="", epss_model="")
    assert bad.stale(TODAY) == ["kev", "epss"]
