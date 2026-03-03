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
    enforce_no_proof_no_report(triaged)
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


def _has_evidence(finding: dict) -> bool:
    evidence = finding.get("evidence") or []
    if isinstance(evidence, list) and evidence:
        return True

    indicators = finding.get("indicators") or []
    if isinstance(indicators, list) and indicators:
        return True

    if finding.get("repro_steps") or finding.get("reproduction_steps"):
        return True
    if finding.get("header_evidence"):
        return True
    if finding.get("screenshot") or finding.get("screenshot_artifact"):
        return True
    if finding.get("raw_http") or finding.get("request_excerpt") or finding.get("response_excerpt"):
        return True
    if finding.get("tool_output_ref"):
        return True
    return False


def enforce_no_proof_no_report(findings: list[dict]) -> None:
    """Demote HIGH/CRITICAL findings without evidence to INFO."""
    for finding in findings:
        severity = str(finding.get("severity", "MEDIUM")).upper()
        if severity in {"HIGH", "CRITICAL"} and not _has_evidence(finding):
            finding["severity"] = "INFO"
            finding["verification_status"] = "Needs Verification"
