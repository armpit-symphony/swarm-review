"""Tests for core/finding_schema.py."""

import sys
from pathlib import Path

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.finding_schema import normalize_finding, validate_finding


def test_normalize_finding_maps_core_fields():
    raw = {
        "vuln_id": "XSS-VULN-0001",
        "type": "xss",
        "issue": "reflected_xss",
        "severity": "high",
        "confidence": 0.91,
        "url": "https://example.com/search",
        "indicators": ["payload reflected"],
        "cwe": ["79"],
        "remediation": "Encode user-controlled output",
    }
    finding = normalize_finding(raw)
    assert finding["id"] == "XSS-VULN-0001"
    assert finding["type"] == "XSS"
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "high"
    assert finding["affected_urls"] == ["https://example.com/search"]


def test_validate_finding_rejects_bad_severity():
    finding = normalize_finding({"type": "misc", "severity": "invalid", "confidence": "bad"})
    errors = validate_finding(finding)
    # normalize_finding coerces unknown values to safe defaults
    assert errors == []


def test_validate_finding_requires_list_types():
    finding = normalize_finding({"type": "misc"})
    finding["evidence"] = "not-a-list"
    errors = validate_finding(finding)
    assert any("evidence must be a list" in err for err in errors)
