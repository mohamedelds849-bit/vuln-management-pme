"""Command line.

    python -m vmp run         [--policy policy.yml] [--feeds data/feeds] [--ledger data/ledger.json]
                              [--out reports] [--today YYYY-MM-DD] [--no-save-ledger]
    python -m vmp fetch-feeds [--dir data/feeds]
    python -m vmp gate        [--summary reports/summary.json]      exit 1 when the gate failed
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .decide import decide
from .feeds import enrich, fetch_feeds, load_feeds
from .gate import evaluate
from .ingest import load_trivy, scan_metadata
from .ledger import load_ledger, metrics, save_ledger, update
from .policy import load_policy
from .report import build_summary, write_outputs


def run(args) -> int:
    today = date.fromisoformat(args.today) if args.today else date.today()
    policy = load_policy(args.policy)
    feeds = load_feeds(args.feeds)
    stale = feeds.stale(today)
    findings, scanned, assets_meta = [], [], {}
    for a in policy.assets:
        scan_path = policy.base_dir / a.scan if a.scan else None
        if not scan_path or not scan_path.exists():
            print(f"[warn] asset {a.id}: no scan file ({a.scan}); skipped (not counted as fixed)")
            continue
        fs = load_trivy(scan_path, a.id)
        assets_meta[a.id] = scan_metadata(scan_path)
        findings.extend(fs)
        scanned.append(a.id)
        print(f"[scan] {a.id:<12} {len(fs):>6} findings  ({assets_meta[a.id]['artifact']}, {assets_meta[a.id]['os']})")
    enrich(findings, feeds)
    decide(findings, policy, today)
    ledger = load_ledger(args.ledger)
    run_summary = update(ledger, findings, scanned, today)
    m = metrics(ledger, today)
    gate = evaluate(findings, run_summary, stale, policy.gate)
    feeds_info = {"kev_version": feeds.kev_version, "kev_count": feeds.kev_count, "epss_date": feeds.epss_date,
                  "epss_model": feeds.epss_model, "age_days": feeds.age_days(today), "stale": stale}
    summary = build_summary(findings, run_summary, m, feeds_info, policy, assets_meta, gate, today)
    paths = write_outputs(args.out, findings, summary, policy)
    if not args.no_save_ledger:
        save_ledger(ledger, args.ledger)
    t = summary["totals"]
    print(f"[kev ] {t['kev']} finding(s) in CISA KEV, {t['kev_actionable']} actionable; EPSS-likely: {t['epss_likely']}")
    print(f"[prio] " + "  ".join(f"{p}={t['by_priority'][p]}" for p in ("P1", "P2", "P3", "P4"))
          + f"  (actionable {t['actionable']} / found {t['findings']}; no fix: {t['no_fix']}; excepted: {t['excepted']})")
    print(f"[run ] new={run_summary['new']} escalated={run_summary['escalated']} fixed={run_summary['fixed']} "
          f"overdue={run_summary['overdue']}")
    print(f"[out ] {paths['report']}")
    print(f"[gate] {'PASS' if gate['passed'] else 'FAIL'} {gate['failures']} warnings={gate['warnings']}")
    if stale:
        print(f"[warn] stale feeds: {stale} (older than 7 days)")
    return 0 if gate["passed"] else 1


def gate_cmd(args) -> int:
    doc = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    g = doc["gate"]
    print(("PASS" if g["passed"] else "FAIL"), g["failures"], "warnings:", g["warnings"])
    return 0 if g["passed"] else 1


def fetch_cmd(args) -> int:
    written = fetch_feeds(args.dir)
    for name, n in written.items():
        print(f"{name}: {n // 1024} KB")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vmp", description=f"risk-based vulnerability management pipeline v{__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="scans + feeds -> decisions, ledger, reports, gate")
    r.add_argument("--policy", default="policy.yml")
    r.add_argument("--feeds", default="data/feeds")
    r.add_argument("--ledger", default="data/ledger.json")
    r.add_argument("--out", default="reports")
    r.add_argument("--today", default=None, help="YYYY-MM-DD (default: today); makes runs reproducible")
    r.add_argument("--no-save-ledger", action="store_true", help="do not write the ledger back (dry run)")
    r.set_defaults(func=run)
    f = sub.add_parser("fetch-feeds", help="download CISA KEV and EPSS (network)")
    f.add_argument("--dir", default="data/feeds")
    f.set_defaults(func=fetch_cmd)
    g = sub.add_parser("gate", help="exit 1 when reports/summary.json says the gate failed")
    g.add_argument("--summary", default="reports/summary.json")
    g.set_defaults(func=gate_cmd)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
