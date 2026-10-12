"""Shrink a Trivy JSON scan to the fields the pipeline uses (drops descriptions and references).

A full `trivy image` JSON of a WordPress image is ~39 MB because every CVE carries its text
and reference list. The pipeline only needs ids, versions, severity, CVSS, status and dates.

    python scripts/slim_scan.py work/scans/full.json data/scans/slim.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

KEEP_VULN = ("VulnerabilityID", "PkgName", "PkgID", "InstalledVersion", "FixedVersion", "Status",
             "Severity", "CVSS", "Title", "PublishedDate", "LastModifiedDate", "SeveritySource")
KEEP_RESULT = ("Target", "Class", "Type")
KEEP_TOP = ("SchemaVersion", "CreatedAt", "ArtifactName", "ArtifactType", "Metadata")


def slim(doc: dict) -> dict:
    out = {k: doc[k] for k in KEEP_TOP if k in doc}
    meta = dict(out.get("Metadata") or {})
    meta.pop("ImageConfig", None)  # layer history, not needed
    out["Metadata"] = meta
    results = []
    for r in doc.get("Results") or []:
        slim_r = {k: r[k] for k in KEEP_RESULT if k in r}
        slim_r["Vulnerabilities"] = [{k: v[k] for k in KEEP_VULN if k in v} for v in (r.get("Vulnerabilities") or [])]
        results.append(slim_r)
    out["Results"] = results
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(argv[1]), Path(argv[2])
    with open(src, encoding="utf-8") as fh:
        doc = json.load(fh)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(slim(doc), fh, ensure_ascii=False, separators=(",", ":"))
    print(f"{src.name}: {src.stat().st_size // 1024} KB -> {dst.name}: {dst.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
