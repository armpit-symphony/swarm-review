"""Triage agent to de-duplicate, score, and assign vuln IDs to findings.

Vuln ID scheme (Shannon-inspired): [TYPE]-VULN-NNNN
Examples: XSS-VULN-0001, TLS-VULN-0002, Headers-VULN-0001
"""

from __future__ import annotations

import hashlib
from collections import defaultdict


def _fingerprint(finding: dict) -> str:
    key_parts = [
        str(finding.get("type", "")),
        str(finding.get("url", "")),
        str(finding.get("parameter", "")),
        str(finding.get("payload", "")),
        str(finding.get("issue", "")),
    ]
    raw = "|".join(key_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def triage_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    triaged = []
    for f in findings:
        fp = _fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        f = dict(f)
        f["confidence"] = _score(f)
        triaged.append(f)
    assign_vuln_ids(triaged)
    return triaged


def assign_vuln_ids(findings: list[dict]) -> None:
    """Add Shannon-style vuln IDs ([TYPE]-VULN-NNNN) to each finding in-place.

    IDs are scoped per finding type so each type restarts its counter.
    Example: XSS-VULN-0001, TLS-VULN-0001, Headers-VULN-0002
    """
    counters: dict[str, int] = defaultdict(int)
    for f in findings:
        vuln_type = str(f.get("type", "MISC")).upper().replace(" ", "_")
        counters[vuln_type] += 1
        f["vuln_id"] = f"{vuln_type}-VULN-{counters[vuln_type]:04d}"


def _score(finding: dict) -> float:
    severity = (finding.get("severity") or "MEDIUM").upper()
    base = {
        "CRITICAL": 0.9,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.3,
    }.get(severity, 0.4)
    indicators = finding.get("indicators") or finding.get("details") or []
    if indicators:
        base += 0.1
    return min(base, 0.99)
