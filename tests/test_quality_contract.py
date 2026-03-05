"""Quality contract tests: redaction, triage discipline, and schema strictness."""

import sys
from pathlib import Path

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agents.triage_agent import triage_findings
from core.disclosure_formatter import _redact_snippet, format_disclosure_email
from core.finding_schema import normalize_finding, validate_finding


def test_redact_snippet_masks_email_ip_and_tokens():
    text = "Contact admin@example.com from 10.0.0.7 token=abc123"
    redacted = _redact_snippet(text)
    assert "admin@example.com" not in redacted
    assert "10.0.0.7" not in redacted
    assert "abc123" not in redacted
    assert "[redacted_email]" in redacted
    assert "[redacted_ip]" in redacted
    assert "[redacted]" in redacted


def test_redact_snippet_truncates_long_input():
    text = "a" * 260
    redacted = _redact_snippet(text)
    assert redacted.endswith("...")
    assert len(redacted) == 223


def test_no_proof_no_report_demotes_high_without_evidence():
    findings = [
        {"type": "xss", "issue": "reflected_xss", "url": "https://example.com", "severity": "HIGH"},
    ]
    triaged = triage_findings(findings)
    assert len(triaged) == 1
    assert triaged[0]["severity"] == "INFO"
    assert triaged[0]["verification_status"] == "Needs Verification"


def test_no_proof_no_report_keeps_high_with_evidence():
    findings = [
        {
            "type": "xss",
            "issue": "reflected_xss",
            "url": "https://example.com",
            "severity": "HIGH",
            "evidence": ["request/response excerpt"],
        },
    ]
    triaged = triage_findings(findings)
    assert len(triaged) == 1
    assert triaged[0]["severity"] == "HIGH"
    assert "verification_status" not in triaged[0]


def test_disclosure_output_single_subject_line():
    findings = [
        {
            "type": "Headers",
            "severity": "LOW",
            "issue": "xfo_missing",
            "url": "https://example.com",
            "vuln_id": "HEADERS-VULN-0001",
            "detail": "XFO missing",
            "evidence": ["token=abc123"],
            "remediation": "Set X-Frame-Options: DENY",
        }
    ]
    doc = format_disclosure_email("example.com", findings, run_id="run-1", generated_at="2026-03-05T00:00:00+00:00")
    lines = doc["body"].splitlines()
    assert sum(1 for line in lines if line.startswith("Subject: ")) == 1


def test_validate_finding_rejects_empty_id_after_normalize():
    finding = normalize_finding({"type": "misc", "issue": "missing_id"})
    errors = validate_finding(finding)
    assert any("id must be a non-empty string" in err for err in errors)
