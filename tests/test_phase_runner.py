"""Tests for phase execution and no-proof triage behavior."""

import json
import sys
from pathlib import Path

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agents.triage_agent import triage_findings
from core.phase_runner import PhaseRunner


def test_phase_runner_records_duration_and_status(tmp_path):
    runner = PhaseRunner()
    result = runner.run_phase("Recon", lambda: {"ok": True}, meta={"risk": "low"})
    assert result == {"ok": True}
    assert len(runner.events) == 1
    event = runner.events[0]
    assert event["phase"] == "Recon"
    assert event["status"] == "ok"
    assert isinstance(event["duration_ms"], int)
    out = tmp_path / "run.log"
    runner.write_jsonl(str(out))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["phase"] == "Recon"


def test_no_proof_no_report_demotes_high_without_evidence():
    findings = [
        {"type": "xss", "severity": "HIGH", "url": "https://example.com", "issue": "reflected_xss"},
        {
            "type": "headers",
            "severity": "HIGH",
            "url": "https://example.com",
            "issue": "missing_csp",
            "indicators": ["Content-Security-Policy header missing"],
        },
    ]
    triaged = triage_findings(findings)
    by_issue = {item["issue"]: item for item in triaged}
    assert by_issue["reflected_xss"]["severity"] == "INFO"
    assert by_issue["reflected_xss"]["verification_status"] == "Needs Verification"
    assert by_issue["missing_csp"]["severity"] == "HIGH"
