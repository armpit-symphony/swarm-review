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
from typing import Sequence


# ---------------------------------------------------------------------------
# Severity ordering for sorting (highest first)
# ---------------------------------------------------------------------------
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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

    # Count by severity
    by_sev: dict[str, list[dict]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in sorted_findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        by_sev.setdefault(sev, []).append(f)

    top_sev = sorted_findings[0].get("severity", "MEDIUM").upper()
    subject = (
        f"Responsible Disclosure: {top_sev} Severity Vulnerabilities Found on {target}"
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
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
    lines.append(f"Date:       {now}")
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

    # -----------------------------------------------------------------------
    # Per-finding blocks
    # -----------------------------------------------------------------------
    for idx, f in enumerate(sorted_findings, start=1):
        vuln_id = f.get("vuln_id") or f"FINDING-{idx:04d}"
        severity = (f.get("severity") or "MEDIUM").upper()
        vuln_type = f.get("type", "Unknown")
        issue = f.get("issue", "unknown_issue").replace("_", " ").title()
        detail = f.get("detail", "No detail provided.")
        url = f.get("url", target)
        remediation = f.get("remediation", "No remediation provided.")
        indicators = f.get("indicators") or []
        confidence = f.get("confidence", 0.0)

        lines.append(f"{'─' * 72}")
        lines.append(f"[{vuln_id}] {vuln_type} — {issue}")
        lines.append(f"Severity:   {severity}")
        lines.append(f"Confidence: {confidence:.0%}")
        lines.append(f"URL:        {url}")
        lines.append("")
        lines.append("Description:")
        lines.append(f"  {detail}")
        lines.append("")
        if indicators:
            lines.append("Evidence / Indicators:")
            for ind in indicators:
                lines.append(f"  • {ind}")
            lines.append("")
        lines.append("Remediation:")
        lines.append(f"  {remediation}")
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
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = len(by_sev.get(sev, []))
        if n:
            parts.append(f"{n} {sev}")
    return ", ".join(parts) if parts else "none"


def write_disclosure_email(
    output_path: str,
    target: str,
    findings: list[dict],
    **kwargs,
) -> str:
    """Format and write disclosure email to *output_path*. Returns the path."""
    result = format_disclosure_email(target, findings, **kwargs)
    full_text = f"Subject: {result['subject']}\n\n{result['body']}"
    with open(output_path, "w") as f:
        f.write(full_text)
    return output_path
