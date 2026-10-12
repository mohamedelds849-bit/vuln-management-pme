"""Print a Markdown summary of reports/summary.json (used by the weekly workflow)."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "reports/summary.json"
s = json.load(open(path, encoding="utf-8"))
t, g, p = s["totals"], s["gate"], s["totals"]["by_priority"]
print(f"## Gate: {'PASS' if g['passed'] else 'FAIL'} {' '.join(g['failures'])}  (warnings: {' '.join(g['warnings']) or 'none'})")
print("| findings | actionable | P1 | P2 | P3 | P4 | KEV (to act) | no fix | excepted |")
print("|---|---|---|---|---|---|---|---|---|")
print(f"| {t['findings']} | {t['actionable']} | {p['P1']} | {p['P2']} | {p['P3']} | {p['P4']} | "
      f"{t['kev']} ({t['kev_actionable']}) | {t['no_fix']} | {t['excepted']} |")
print(f"\nFeeds: KEV {s['feeds']['kev_version']} ({s['feeds']['kev_count']}), EPSS {s['feeds']['epss_date']}. "
      f"Run: new={s['run']['new']} fixed={s['run']['fixed']} overdue={s['run']['overdue']}.")
