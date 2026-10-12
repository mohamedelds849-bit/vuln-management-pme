# Method: from 9 540 scanner findings to 2 upgrades this week

This document explains every decision the pipeline makes, so that a reviewer can disagree
with a threshold rather than with a black box.

## 1. Inputs

| Input | Source | What it says | What it does not say |
|---|---|---|---|
| Scan | Trivy 0.75.0 (`trivy image`, `trivy fs`), JSON schema 2 | which package, which version, which CVE, which fixed version, distro status (`fixed`, `affected`, `will_not_fix`, `fix_deferred`) | whether the vulnerable code runs, how the asset is exposed |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed) | the CVE **has been exploited in the wild** (1 739 entries on 2026-10-08) | a CVE absent from KEV can still be exploited |
| FIRST EPSS | https://www.first.org/epss (daily CSV) | **probability** that the CVE is exploited in the next 30 days, 0 to 1, plus a percentile | nothing about *your* exposure; old CVEs with scanner noise can have high scores |
| policy.yml | the organisation | asset exposure and criticality, SLA, thresholds, exceptions, gate rules | — |

## 2. Decision tree (SSVC-inspired)

CISA's SSVC ("Stakeholder-Specific Vulnerability Categorization") deployer tree asks four
questions: exploitation, exposure, utility/automatable, human impact, and answers Track /
Track* / Attend / Act. An SME does not have the data for "automatable" and "mission
prevalence", so the tree here keeps three axes plus the asset's business criticality:

| Axis | Values | How it is computed |
|---|---|---|
| Exploitation | `active` / `likely` / `unlikely` | in KEV → active ; EPSS ≥ `epss_likely` (0.10) → likely ; else unlikely |
| Exposure | `internet` / `internal` / `isolated` | from the asset in policy.yml |
| Impact | `total` / `high` / `partial` | CVSS v3 ≥ `cvss_total` (9.0) or scanner CRITICAL → total ; ≥ `cvss_high` (7.0) or HIGH → high ; else partial |
| Criticality | `high` / `medium` / `low` | from the asset in policy.yml |

Rules, evaluated top-down (first match wins), `vmp/decide.py::priority`:

| # | Condition | Decision | Priority | SLA |
|---|---|---|---|---|
| 1 | active **and** (internet **or** criticality high) | Act | P1 | 7 days |
| 2 | likely **and** internet **and** impact total | Act | P1 | 7 days |
| 3 | active (other assets) | Attend | P2 | 30 days |
| 4 | likely **and** (impact total **or** (internet **and** impact high)) | Attend | P2 | 30 days |
| 5 | unlikely **and** internet **and** impact total **and** criticality high | Attend | P2 | 30 days |
| 6 | likely (other cases: limited impact) | Track+ | P3 | 90 days |
| 7 | impact total, or impact high on an internet asset | Track+ | P3 | 90 days |
| 8 | everything else | Track | P4 | 180 days |

Property checked by a test: for a fixed exposure / impact / criticality, the priority never
gets *better* when exploitation gets *worse* (monotonicity, `test_priority_never_worse_when_exploitation_increases`).

Why these choices:
- **KEV first.** Observed exploitation beats any score. On an internet-facing or critical
  asset it is P1 whatever the CVSS (rule 1): exploited LOW-rated bugs exist.
- **EPSS as the second signal, with a floor.** 10 % in 30 days is the common cut-off in the
  EPSS user guide and vendor practice. Rule 6 keeps a high-EPSS CVE with *partial* impact at
  P3: CVE-2011-3389 (BEAST, EPSS 73 %) on an unfixed LOW package is not a 30-day emergency.
- **CVSS last.** It measures *technical* severity, not likelihood. Alone it only makes P2
  on an internet-facing critical asset (rule 5).
- **SLA P1 = 7 days.** CISA BOD 22-01 gives US federal agencies 2 weeks for a new KEV entry;
  an SME with 4 assets and no change board can do better, and the number is in policy.yml.

## 3. No fix available

`action = mitigate`: priority and SLA are unchanged (the risk does not wait for the vendor),
but the expected answer is a compensating control (WAF rule, disabled module, network
restriction) and a watch on the fix. The distro status (`will_not_fix`, `fix_deferred`) is
copied into the reasons so the reader sees why. 1 794 of the 3 281 actionable findings on
2026-10-12 are in this state: Debian classifies many minor CVEs as "no DSA".

## 4. Exceptions = VEX

An exception needs a `status` (`not_affected`, `accepted`, `false_positive`), an `owner`, a
`justification` of at least five words and an `expires` date; the pipeline refuses the policy
otherwise. `cve: "*"` with a `package` is a **component-level** rule.

The real example: Trivy reports **6 258 kernel CVEs** (including **3 in KEV**) on the
`linux-libc-dev` package of the WordPress image. That package holds the kernel *headers*
(`.h` files used to compile); no kernel code runs from it, and a container runs the *host*
kernel. One rule, `not_affected`, owned by the hosting provider, expiring 2027-01-31, with
the host-kernel follow-up written in the justification. Without it the report is 65 % noise;
with it the KEV count to act on is 0 and the first real P1 appears (OpenSSL).

Exceptions are exported as **OpenVEX** statements (`reports/openvex.json`): `not_affected`
with justification `vulnerable_code_not_in_execute_path`, or `affected` with an
`action_statement` for accepted risks. An expired exception reopens the finding and the
report lists it under "Exceptions expirées".

## 5. The ledger: memory between runs

`data/ledger.json` keeps, per (asset, CVE, package): `first_seen`, `due` (= first seen +
SLA of the priority at that time), `last_seen`, `status`, `fixed_on`, `time_to_fix_days`,
and a `history` of escalations.

- A finding missing from a **scanned** asset is `fixed` (time to fix = fixed_on − first_seen).
  A missing *scan* is a warning, never a fix.
- If a finding's priority gets worse (a CVE enters KEV), the due date is shortened to
  min(old due, today + new SLA). A better priority never extends a due date.
- A fixed finding that comes back (image rollback) is `reopened` with a new first_seen.
- Metrics: mean time to remediate per priority, oldest open finding.

## 6. Fix plan = tickets

The patch list is grouped by (asset, package, fixed version): **one upgrade closes N CVEs**.
On 2026-10-12, 257 upgrades cover every patchable finding, and the top two
(OpenSSL 3.0.18 on nginx, OpenSSL 3.5.4-1~deb13u2 on WordPress) close 8 and 12 CVEs
including the only P1. `tickets.csv` is what the hosting provider receives.

## 7. The CI gate

| Rule | Meaning | Default |
|---|---|---|
| `overdue_P1` | a P1 is past its due date | fail |
| `new_P1_internet` | a P1 appeared today on an internet-facing asset | fail |
| `overdue_P2` | a P2 is past its due date | warn |
| `stale_feeds` | KEV or EPSS older than 7 days | warn |
| `new_P1`, `any_P1_open` | stricter variants | off |

A red first run is expected: it says "there is something to do this week", which is the
point. The job goes green when the ledger shows the P1 fixed or documented.

## 8. Limits (also in REVIEW.md)

- Trivy sees **packages**, not configuration, not custom PHP code, not WordPress plugins
  installed afterwards. Pair it with the AppSec pipeline (code) and the RSSI audit (exposure).
- EPSS and KEV are **global** signals; the asset's exposure in policy.yml is a human
  statement that must be kept true.
- The images are public upstream images at a tag; the real hosting provider may run patched
  derivatives. The scan metadata records the exact digest scanned.
- The pipeline has run on one real date; the second run in the tests is a **simulation**
  (nginx scan with the OpenSSL and curl findings removed, 20 days later).

## Sources

- CISA SSVC: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- CISA KEV catalog and BOD 22-01: https://www.cisa.gov/known-exploited-vulnerabilities-catalog , https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities
- FIRST EPSS user guide: https://www.first.org/epss/user-guide
- OpenVEX specification: https://github.com/openvex/spec
- Trivy JSON report format: https://trivy.dev/latest/docs/configuration/reporting/
- Debian security tracker statuses (no-dsa, will not fix): https://security-team.debian.org/security_tracker.html
