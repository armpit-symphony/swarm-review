"""Disclosure email formatter.

Converts triaged findings (post triage_agent.triage_findings) into a ready-to-send
responsible disclosure email body.  Shannon-inspired structure:
  - Subject line suggestion
  - Executive summary
  - Per-finding blocks with vuln ID, severity, detail, reproduction, remediation
  - Standard disclosure footer
"""

from __future__ import annotations

from datetime import datetime, timezone
import re


# ---------------------------------------------------------------------------
# Severity ordering for sorting (highest first)
# ---------------------------------------------------------------------------
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _sev_key(f: dict) -> int:
    return _SEV_ORDER.get((f.get("severity") or "MEDIUM").upper(), 9)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def format_disclosure_email(
    target: str,
    findings: list[dict],
    researcher_name: str = "SparkPit Labs Security Research",
    researcher_contact: str = "security@thesparkpit.com",
    include_footer: bool = True,
    run_id: str = "",
    generated_at: str = "",
) -> dict[str, str]:
    """Return a dict with keys ``subject`` and ``body``.

    Parameters
    ----------
    target:
        The scanned domain or URL.
    findings:
        Triaged findings list from ``triage_agent.triage_findings()``.
        Each finding should have: type, vuln_id, issue, detail, severity,
        url, remediation, confidence, indicators.
    researcher_name:
        Name shown in the email header.
    researcher_contact:
        Reply-to email address.
    include_footer:
        Whether to append the standard responsible-disclosure footer.
    """
    if not findings:
        return {
            "subject": f"Security Research — No Findings for {target}",
            "body": f"No vulnerabilities were identified during the assessment of {target}.",
        }

    sorted_findings = sorted(findings, key=_sev_key)
    needs_verification = [
        f for f in sorted_findings
        if str(f.get("verification_status", "")).lower() == "needs verification"
    ]
    validated = [f for f in sorted_findings if f not in needs_verification]

    # Count by severity
    by_sev: dict[str, list[dict]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in sorted_findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        by_sev.setdefault(sev, []).append(f)

    top_sev = (validated[0] if validated else sorted_findings[0]).get("severity", "MEDIUM").upper()
    subject = (
        f"Responsible Disclosure: {top_sev} Severity Vulnerabilities Found on {target}"
    )

    now = generated_at or datetime.now(timezone.utc).isoformat()
    total = len(sorted_findings)

    lines: list[str] = []
    lines.append(f"Subject: {subject}")
    lines.append("")
    lines.append("=" * 72)
    lines.append("RESPONSIBLE DISCLOSURE REPORT")
    lines.append("=" * 72)
    lines.append(f"Researcher: {researcher_name}")
    lines.append(f"Contact:    {researcher_contact}")
    lines.append(f"Target:     {target}")
    lines.append(f"Run ID:     {run_id or 'N/A'}")
    lines.append(f"Timestamp:  {now}")
    lines.append(f"Findings:   {total} ({_sev_counts_str(by_sev)})")
    lines.append("=" * 72)
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(
        f"During a security assessment of {target}, we identified {total} "
        f"{'vulnerability' if total == 1 else 'vulnerabilities'} "
        f"({_sev_counts_str(by_sev)}). These issues are documented below "
        "with reproduction guidance and remediation recommendations."
    )
    lines.append("")
    if by_sev.get("CRITICAL") or by_sev.get("HIGH"):
        lines.append(
            "We recommend prioritizing CRITICAL and HIGH severity items for immediate remediation."
        )
        lines.append("")

    lines.append("VALIDATED FINDINGS")
    lines.append("-" * 40)
    if not validated:
        lines.append("No validated findings in this run.")
        lines.append("")
    for idx, f in enumerate(validated, start=1):
        vuln_id = f.get("vuln_id") or f"FINDING-{idx:04d}"
        severity = (f.get("severity") or "MEDIUM").upper()
        vuln_type = f.get("type", "Unknown")
        issue = f.get("issue", "unknown_issue").replace("_", " ").title()
        detail = f.get("detail", "No detail provided.")
        url = f.get("url", target)
        remediation = f.get("remediation", "No remediation provided.")
        indicators = f.get("evidence") or f.get("indicators") or []
        confidence = _format_confidence(f.get("confidence", 0.0))

        lines.append(f"{'─' * 72}")
        lines.append(f"[{vuln_id}] {vuln_type} — {issue}")
        lines.append(f"Severity:   {severity}")
        lines.append(f"Confidence: {confidence}")
        lines.append(f"URL:        {url}")
        lines.append("")
        lines.append("Description:")
        lines.append(f"  {detail}")
        lines.append("")
        if indicators:
            lines.append("Evidence Snippets (redacted):")
            for ind in indicators[:5]:
                lines.append(f"  • {_redact_snippet(str(ind))}")
            lines.append("")
        lines.append("Remediation:")
        lines.append(f"  {remediation}")
        rubric = _quality_rubric(f)
        lines.append("")
        lines.append(
            "Quality Rubric: "
            f"{rubric['total']}/4 "
            f"(evidence={rubric['evidence_present']}, "
            f"scope={rubric['scope_confirmed']}, "
            f"severity_rationale={rubric['severity_rationale']}, "
            f"fix_guidance={rubric['fix_guidance']})"
        )
        lines.append("")

    lines.append("NEEDS VERIFICATION")
    lines.append("-" * 40)
    if not needs_verification:
        lines.append("No findings flagged as Needs Verification.")
    for idx, f in enumerate(needs_verification, start=1):
        vuln_id = f.get("vuln_id") or f"UNVERIFIED-{idx:04d}"
        severity = (f.get("severity") or "INFO").upper()
        vuln_type = f.get("type", "Unknown")
        issue = f.get("issue", "unknown_issue").replace("_", " ").title()
        url = f.get("url", target)
        lines.append(f"[{vuln_id}] {vuln_type} — {issue}")
        lines.append(f"Severity:   {severity}")
        lines.append(f"URL:        {url}")
        lines.append("Reason:     Missing proof artifact; manual validation required before reporting as high-impact.")
        lines.append("")

    # -----------------------------------------------------------------------
    # Footer
    # -----------------------------------------------------------------------
    if include_footer:
        lines.append("=" * 72)
        lines.append("DISCLOSURE POLICY")
        lines.append("-" * 40)
        lines.append(
            "This report is submitted under responsible disclosure principles. "
            "We request a 90-day remediation window before public disclosure. "
            "We are happy to provide technical clarification or re-test after fixes are applied."
        )
        lines.append("")
        lines.append(f"Contact: {researcher_contact}")
        lines.append("=" * 72)

    body = "\n".join(lines)
    return {"subject": subject, "body": body}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sev_counts_str(by_sev: dict[str, list]) -> str:
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = len(by_sev.get(sev, []))
        if n:
            parts.append(f"{n} {sev}")
    return ", ".join(parts) if parts else "none"


def _format_confidence(value) -> str:
    if isinstance(value, (int, float)):
        return f"{float(value):.0%}"
    text = str(value).strip().lower()
    if not text:
        return "unknown"
    return text


def _redact_snippet(text: str) -> str:
    text = re.sub(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", r"[redacted_email]", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[redacted_ip]", text)
    text = re.sub(r"(token|apikey|api_key|secret)\s*[:=]\s*['\"]?[^'\"\s]+", r"\1=[redacted]", text, flags=re.I)
    if len(text) > 220:
        return text[:220] + "..."
    return text


def _quality_rubric(f: dict) -> dict[str, int]:
    evidence_present = 1 if (f.get("evidence") or f.get("indicators")) else 0
    scope_confirmed = 1 if f.get("url") or f.get("affected_urls") else 0
    sev_rationale = 1 if f.get("detail") or f.get("severity_rationale") else 0
    fix_guidance = 1 if f.get("remediation") else 0
    total = evidence_present + scope_confirmed + sev_rationale + fix_guidance
    return {
        "evidence_present": evidence_present,
        "scope_confirmed": scope_confirmed,
        "severity_rationale": sev_rationale,
        "fix_guidance": fix_guidance,
        "total": total,
    }


def write_disclosure_email(
    output_path: str,
    target: str,
    findings: list[dict],
    **kwargs,
) -> str:
    """Format and write disclosure email to *output_path*. Returns the path."""
    result = format_disclosure_email(target, findings, **kwargs)
    body = result["body"]
    if body.lstrip().startswith("Subject:"):
        full_text = body
    else:
        full_text = f"Subject: {result['subject']}\n\n{body}"
    with open(output_path, "w") as f:
        f.write(full_text)
    return output_path
