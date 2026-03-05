"""Stable finding schema helpers for bugbounty-swarm."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ALLOWED_CONFIDENCE = {"high", "medium", "low", "unknown"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a finding to the stable schema."""
    severity = str(raw.get("severity") or "MEDIUM").upper()
    if severity not in ALLOWED_SEVERITIES:
        severity = "INFO"

    confidence_raw = raw.get("confidence")
    if isinstance(confidence_raw, (float, int)):
        if confidence_raw >= 0.8:
            confidence = "high"
        elif confidence_raw >= 0.5:
            confidence = "medium"
        elif confidence_raw > 0:
            confidence = "low"
        else:
            confidence = "unknown"
    else:
        confidence = str(confidence_raw or "unknown").lower()
        if confidence not in ALLOWED_CONFIDENCE:
            confidence = "unknown"

    now = _utc_now()
    timestamps = raw.get("timestamps") if isinstance(raw.get("timestamps"), dict) else {}
    first_seen = str(timestamps.get("first_seen") or raw.get("first_seen") or now)
    last_seen = str(timestamps.get("last_seen") or raw.get("last_seen") or now)

    finding_id = str(raw.get("id") or raw.get("vuln_id") or "")
    finding_type = str(raw.get("type") or "MISC").upper()
    title = str(raw.get("title") or raw.get("issue") or "Uncategorized finding")

    return {
        "id": finding_id,
        "type": finding_type,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": [str(x) for x in _to_list(raw.get("evidence")) if str(x).strip()],
        "affected_urls": [str(x) for x in _to_list(raw.get("affected_urls") or raw.get("url")) if str(x).strip()],
        "cwe": [str(x) for x in _to_list(raw.get("cwe")) if str(x).strip()],
        "tags": [str(x) for x in _to_list(raw.get("tags")) if str(x).strip()],
        "remediation": [str(x) for x in _to_list(raw.get("remediation")) if str(x).strip()],
        "timestamps": {
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
        "raw": raw,
    }


def validate_finding(finding: dict[str, Any]) -> list[str]:
    """Validate normalized finding payload."""
    errors: list[str] = []
    required = [
        "id",
        "type",
        "title",
        "severity",
        "confidence",
        "evidence",
        "affected_urls",
        "cwe",
        "tags",
        "remediation",
        "timestamps",
    ]
    for key in required:
        if key not in finding:
            errors.append(f"Missing required key: {key}")

    for key in ("id", "type", "title"):
        value = finding.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{key} must be a non-empty string")

    if finding.get("severity") not in ALLOWED_SEVERITIES:
        errors.append(f"Invalid severity: {finding.get('severity')}")
    if finding.get("confidence") not in ALLOWED_CONFIDENCE:
        errors.append(f"Invalid confidence: {finding.get('confidence')}")

    for list_key in ("evidence", "affected_urls", "cwe", "tags", "remediation"):
        if not isinstance(finding.get(list_key), list):
            errors.append(f"{list_key} must be a list")

    ts = finding.get("timestamps")
    if not isinstance(ts, dict):
        errors.append("timestamps must be an object")
    else:
        if "first_seen" not in ts:
            errors.append("timestamps.first_seen is required")
        if "last_seen" not in ts:
            errors.append("timestamps.last_seen is required")

    return errors


def normalize_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_finding(item) for item in raw_findings]
