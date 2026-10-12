"""Threat-context feeds: CISA KEV (known exploited) and FIRST EPSS (exploit probability).

Both are public, free and need no API key. They are downloaded into a folder and read
offline, so the pipeline (and the tests) never depend on the network at run time.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Optional

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_FILE = "known_exploited_vulnerabilities.json"
EPSS_FILE = "epss_scores-current.csv.gz"
MAX_FEED_AGE_DAYS = 7


@dataclass
class KevEntry:
    cve: str
    date_added: str
    due_date: str
    ransomware: bool
    vendor: str
    product: str
    name: str


@dataclass
class Feeds:
    kev: dict[str, KevEntry]
    epss: dict[str, tuple[float, float]]  # cve -> (epss, percentile)
    kev_version: str
    kev_count: int
    epss_date: str
    epss_model: str

    def age_days(self, today: date) -> dict[str, Optional[int]]:
        def _age(s: str, fmt: str) -> Optional[int]:
            try:
                return (today - datetime.strptime(s[:10], fmt).date()).days
            except ValueError:
                return None

        return {"kev": _age(self.kev_version, "%Y.%m.%d"), "epss": _age(self.epss_date, "%Y-%m-%d")}

    def stale(self, today: date, max_age: int = MAX_FEED_AGE_DAYS) -> list[str]:
        return [name for name, age in self.age_days(today).items() if age is None or age > max_age]


def parse_kev(doc: dict) -> dict[str, KevEntry]:
    out = {}
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID", "").strip()
        if not cve:
            continue
        out[cve] = KevEntry(
            cve=cve,
            date_added=v.get("dateAdded", ""),
            due_date=v.get("dueDate", ""),
            ransomware=str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            vendor=v.get("vendorProject", ""),
            product=v.get("product", ""),
            name=v.get("vulnerabilityName", ""),
        )
    return out


def parse_epss(text: str) -> tuple[dict[str, tuple[float, float]], str, str]:
    """EPSS CSV: a comment line '#model_version:...,score_date:...' then cve,epss,percentile."""
    lines = text.splitlines()
    model, score_date = "", ""
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            k, _, val = part.partition(":")
            if k.strip() == "model_version":
                model = val.strip()
            elif k.strip() == "score_date":
                score_date = val.strip()[:10]
        lines = lines[1:]
    out: dict[str, tuple[float, float]] = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        try:
            out[row["cve"].strip()] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, ValueError, TypeError):
            continue
    return out, score_date, model


def load_feeds(feeds_dir: str | Path) -> Feeds:
    d = Path(feeds_dir)
    kev_path, epss_path = d / KEV_FILE, d / EPSS_FILE
    if not kev_path.exists() or not epss_path.exists():
        raise FileNotFoundError(
            f"feeds missing in {d}: run `python -m vmp fetch-feeds --dir {d}` (needs network)")
    with open(kev_path, encoding="utf-8") as fh:
        kev_doc = json.load(fh)
    kev = parse_kev(kev_doc)
    if epss_path.suffix == ".gz":
        with gzip.open(epss_path, "rt", encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = epss_path.read_text(encoding="utf-8")
    epss, score_date, model = parse_epss(text)
    return Feeds(kev=kev, epss=epss, kev_version=str(kev_doc.get("catalogVersion", "")),
                 kev_count=int(kev_doc.get("count", len(kev))), epss_date=score_date, epss_model=model)


def fetch_feeds(feeds_dir: str | Path, timeout: int = 120) -> dict[str, int]:
    """Download both feeds (plain HTTPS GET, no key). Returns bytes written per file."""
    d = Path(feeds_dir)
    d.mkdir(parents=True, exist_ok=True)
    written = {}
    for url, name in ((KEV_URL, KEV_FILE), (EPSS_URL, EPSS_FILE)):
        req = urllib.request.Request(url, headers={"User-Agent": "vmp/1.0 (student project)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed https URLs
            data = resp.read()
        (d / name).write_bytes(data)
        written[name] = len(data)
    return written


def enrich(findings, feeds: Feeds) -> None:
    """Attach KEV and EPSS data to each finding (in place)."""
    for f in findings:
        k = feeds.kev.get(f.cve)
        if k:
            f.kev, f.kev_date_added, f.kev_due, f.kev_ransomware = True, k.date_added, k.due_date, k.ransomware
        e = feeds.epss.get(f.cve)
        if e:
            f.epss, f.epss_percentile = e
