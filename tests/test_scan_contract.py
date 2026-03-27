"""Contract tests for scan output schema and disclosure formatting."""

import json
import sys
from pathlib import Path

import pytest

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from swarm_review_cli import _consent_file_path, _enforce_deep_consent, _prepare_schema_findings
from core.disclosure_formatter import format_disclosure_email
from core.finding_schema import validate_finding


def test_findings_json_contract_roundtrip(tmp_path):
    raw = [
        {
            "type": "Headers",
            "severity": "HIGH",
            "issue": "csp_missing",
            "url": "https://example.com",
            "vuln_id": "HEADERS-VULN-0001",
            "indicators": ["Missing: Content-Security-Policy"],
            "remediation": "Add CSP.",
        }
    ]
    normalized = _prepare_schema_findings(raw)
    out = tmp_path / "findings.json"
    out.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(loaded, list)
    assert len(loaded) == 1
    assert validate_finding(loaded[0]) == []


def test_disclosure_includes_required_sections():
    findings = [
        {
            "type": "Headers",
            "severity": "MEDIUM",
            "issue": "xfo_missing",
            "url": "https://example.com",
            "vuln_id": "HEADERS-VULN-0002",
            "detail": "XFO not present",
            "evidence": ["Server: nginx/1.24.0", "token=abc12345"],
            "remediation": "Set X-Frame-Options: DENY",
            "confidence": 0.8,
        },
        {
            "type": "XSS",
            "severity": "INFO",
            "issue": "reflected_xss",
            "url": "https://example.com/search",
            "vuln_id": "XSS-VULN-0001",
            "verification_status": "Needs Verification",
            "confidence": 0.2,
        },
    ]
    doc = format_disclosure_email(
        "example.com",
        findings,
        run_id="run-123",
        generated_at="2026-03-03T14:20:00+00:00",
    )
    body = doc["body"]
    assert "Target:     example.com" in body
    assert "Run ID:     run-123" in body
    assert "Timestamp:  2026-03-03T14:20:00+00:00" in body
    assert "Findings:" in body
    assert "VALIDATED FINDINGS" in body
    assert "NEEDS VERIFICATION" in body
    assert "[redacted]" in body or "[redacted_ip]" in body or "[redacted_email]" in body


def test_deep_mode_requires_token_and_matching_consent(tmp_path):
    out_dir = tmp_path / "run_001"
    out_dir.mkdir()
    target = "example.com"
    with pytest.raises(SystemExit):
        _enforce_deep_consent("deep", "", str(out_dir), target)

    consent = _consent_file_path(str(out_dir), target)
    consent.parent.mkdir(parents=True, exist_ok=True)
    consent.write_text("TOKEN: right-token\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        _enforce_deep_consent("deep", "wrong-token", str(out_dir), target)

    _enforce_deep_consent("deep", "right-token", str(out_dir), target)
