"""Read Trivy JSON (schema version 2) and turn it into normalized Finding objects.

Only Trivy is supported on purpose: it is the scanner really run in this project.
`trivy image`, `trivy fs` and `trivy sbom` all produce the same JSON layout.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from .model import Finding

CVSS_SOURCE_ORDER = ("nvd", "ghsa", "redhat", "bitnami", "ubuntu", "debian")


def _cvss(v: dict) -> tuple[Optional[float], Optional[str]]:
    """Pick a CVSS v3 score: NVD first, then the other sources in a fixed order."""
    cvss = v.get("CVSS") or {}
    sources = list(CVSS_SOURCE_ORDER) + [s for s in cvss if s not in CVSS_SOURCE_ORDER]
    for src in sources:
        entry = cvss.get(src) or {}
        score = entry.get("V3Score")
        if isinstance(score, (int, float)):
            return float(score), entry.get("V3Vector")
    return None, None


def parse_trivy(doc: dict, asset_id: str) -> list[Finding]:
    if doc.get("SchemaVersion") != 2:
        raise ValueError(f"unsupported Trivy JSON schema: {doc.get('SchemaVersion')!r} (expected 2)")
    out: dict[str, Finding] = {}
    for result in doc.get("Results") or []:
        target = result.get("Target", "")
        pkg_type = result.get("Type", "")
        for v in result.get("Vulnerabilities") or []:
            cve = v.get("VulnerabilityID", "").strip()
            pkg = v.get("PkgName", "").strip()
            if not cve or not pkg:
                continue
            score, vector = _cvss(v)
            f = Finding(
                asset_id=asset_id,
                cve=cve,
                pkg=pkg,
                installed=v.get("InstalledVersion", ""),
                fixed=(v.get("FixedVersion") or None),
                scanner_severity=(v.get("Severity") or "UNKNOWN").upper(),
                cvss=score,
                cvss_vector=vector,
                title=(v.get("Title") or "")[:200],
                target=target,
                pkg_type=pkg_type,
                status=v.get("Status", ""),
                published=(v.get("PublishedDate") or "")[:10] or None,
            )
            # The same CVE on the same package can appear twice (two layers): keep one.
            out.setdefault(f.key, f)
    return list(out.values())


def load_trivy(path: str | Path, asset_id: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        return parse_trivy(json.load(fh), asset_id)


def scan_metadata(path: str | Path) -> dict:
    """Artifact name, OS and creation time of a Trivy scan (for the report header)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    meta = doc.get("Metadata") or {}
    os_ = meta.get("OS") or {}
    return {
        "artifact": doc.get("ArtifactName", ""),
        "artifact_type": doc.get("ArtifactType", ""),
        "created": (doc.get("CreatedAt") or "")[:19],
        "os": f"{os_.get('Family', '')} {os_.get('Name', '')}".strip(),
        "eosl": bool(os_.get("EOSL", False)),
        "image_id": meta.get("ImageID", ""),
        "repo_digests": meta.get("RepoDigests") or [],
    }


def count_by(findings: Iterable[Finding], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        k = str(getattr(f, attr))
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items()))
