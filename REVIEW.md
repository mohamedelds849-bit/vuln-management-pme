# Self-review — vuln-management-pme (2026-10-12)

## What was checked by running it

| Check | Command | Result |
|---|---|---|
| Real scans | `trivy image` (0.75.0, Windows, registry pull, no Docker) on `nginx:1.27`, `wordpress:6.8-php8.2-apache`, `mariadb:11.4`; `trivy fs` on the requirements.txt copy | 707 + 8 757 + 76 + 0 findings; digests in each scan's `Metadata.RepoDigests` |
| Real feeds | `python -m vmp fetch-feeds` | KEV 2026.10.08 (1 739 CVE, 1.7 MB), EPSS scored 2026-10-11 (2.7 MB gz) |
| Pipeline | `python -m vmp run --today 2026-10-12` | 9 540 findings → 3 281 actionable → P1 5 / P2 96 / P3 993 / P4 2 187; gate FAIL `new_P1_internet=5` (expected on a first run) |
| Second run (simulated) | nginx scan without its OpenSSL/curl findings, `--today 2026-11-01` | 76 fixed, MTTR 20 days, 3 P1 overdue (WordPress OpenSSL), gate FAIL `overdue_P1=3`, feeds flagged stale |
| Tests | `python -m pytest -q` | **102 passed** (unit on every module, decision table, ledger lifecycle, HTML escaping, end-to-end on the committed real scans with a dated feed snapshot, policy-tamper mutation) |
| Report | headless Chrome screenshot of `reports/report.html` | renders; `reports/example/report.png` |
| CI | push → run 38196458470 | `tests` green in 17 s; `weekly` job: Trivy (image by digest) rescanned the 3 images in CI, KEV + EPSS downloaded, **same numbers as locally** (9 540 / 3 281 / P1 5), gate **FAIL `new_P1_internet=5`** → job red as designed; reports + ledger uploaded as artifact |

## Problems found and fixed during the build

1. **HTML injection in the report.** `select_autoescape(["html"])` keys on the file extension
   and the template is `report.html.j2`, so nothing was escaped: a package name from a scan
   could inject HTML. Caught by `test_html_escapes_untrusted_scanner_text`; fixed with
   `autoescape=True`.
2. **Crash on EPSS rows without a percentile** (`None.__format__`). Guarded.
3. **Old CVEs with a high EPSS became P2** (CVE-2004-0230 at 80 %, CVE-2011-3389 at 73 %,
   both LOW and unfixable). Rule changed: "likely" exploitation with *partial* impact is P3.
4. **65 % of the WordPress findings were kernel-header CVEs** (`linux-libc-dev`, 6 258 rows,
   3 in KEV). Added component-level exceptions (`cve: "*"` + package) so the decision is
   written once with an owner and an expiry, instead of hidden in code.
5. **Counts disagreed** between the ledger run summary (included excepted findings) and the
   report totals. Both now count actionable findings only.
6. **Scan files were 39 MB.** `scripts/slim_scan.py` keeps the fields used (4 MB for
   WordPress); full scans stay in `work/` (ignored).

## Limits that remain (honest list)

- **One real date.** The ledger has one real run; MTTR and "fixed" numbers in the tests come
  from a simulated second scan, and the README says so.
- **Public upstream images at a tag**, not the hosting provider's real images or servers. The
  SME is fictitious (AgriSouss SARL, same as the GRC and IR projects).
- **Trivy only.** No Grype / OpenVAS / Nessus parser: supporting a format never run here would
  be a claim without a test. Trivy sees packages, not configuration or custom code.
- **EPSS and KEV are global**; exposure and criticality are human statements in policy.yml.
- **Thresholds are choices** (EPSS 10 %, CVSS 9 / 7, SLA 7/30/90/180); the policy-tamper test
  proves they are read from the file, not that they are right for every organisation.
- **Exceptions expire but nothing reminds anyone**: the report lists expired ones; there is
  no e-mail or ticket integration.
- **The ledger grows** (4.7 MB after one run with 9 540 rows); fine for an SME, not for a fleet.
- **`will_not_fix` findings keep their SLA** and will show as overdue; the intended answer is
  an exception with a justification, which forces the decision to be written down.
- **No SBOM diff, no VEX ingestion**: the pipeline emits OpenVEX but does not read VEX from
  upstream images (Trivy can, with `--vex`; not wired).

## Safety review

- Read-only: the pipeline reads scan files and two public feeds; it writes reports and a
  JSON ledger. No exploit, no scanning of third-party hosts (`trivy image` pulls public
  images from Docker Hub; `trivy fs` reads a local folder).
- CI pins actions by SHA and the Trivy image by digest (March 2026 Trivy compromise).
- `urllib` only fetches two fixed HTTPS URLs; the HTML report escapes all scanner text and
  has no script.

## Recommendations (next steps)

1. Patch or document the OpenSSL P1 in the ledger so the weekly gate badge goes green, then
   keep the badge honest week after week.
2. Feed Trivy's own `--vex` with `reports/openvex.json` so the scanner itself hides documented
   exceptions (closes the loop).
3. Add a second scanner format only when it has really been run (Grype on the same images).
4. Rescan weekly for a month to get real MTTR numbers instead of the simulated ones.
