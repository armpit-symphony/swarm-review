#!/usr/bin/env python3
"""
HTTP Security Headers Scanner
Checks: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
Outputs structured findings ready for disclosure emails.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence.store import EvidenceStore
from core.rate_limit import from_env as budget_from_env

OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[2] / "output")

# -----------------------------------------------------------------------
# Header definitions
# Each entry: header_name, issue_key, severity, missing_detail, remediation
# -----------------------------------------------------------------------
REQUIRED_HEADERS = [
    {
        "header": "Content-Security-Policy",
        "issue": "csp_missing",
        "severity": "HIGH",
        "detail": (
            "Content-Security-Policy (CSP) header is absent. Without CSP an attacker can "
            "inject arbitrary scripts (XSS) that execute in users' browsers."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start with: "
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'."
        ),
    },
    {
        "header": "X-Frame-Options",
        "issue": "xfo_missing",
        "severity": "MEDIUM",
        "detail": (
            "X-Frame-Options (XFO) header is absent. The site may be embedded in an iframe, "
            "enabling clickjacking attacks."
        ),
        "remediation": (
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing by same origin is needed). "
            "Alternatively, set frame-ancestors in CSP."
        ),
    },
    {
        "header": "X-Content-Type-Options",
        "issue": "xcto_missing",
        "severity": "LOW",
        "detail": (
            "X-Content-Type-Options: nosniff is absent. Browsers may MIME-sniff responses, "
            "potentially executing scripts served as non-script content types."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "Referrer-Policy",
        "issue": "referrer_policy_missing",
        "severity": "LOW",
        "detail": (
            "Referrer-Policy header is absent. By default, full URLs (including paths and query "
            "parameters) may leak to third-party sites in the Referer header."
        ),
        "remediation": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin  "
            "(or no-referrer for maximum privacy)."
        ),
    },
    {
        "header": "Permissions-Policy",
        "issue": "permissions_policy_missing",
        "severity": "LOW",
        "detail": (
            "Permissions-Policy (formerly Feature-Policy) header is absent. Browser features "
            "(camera, microphone, geolocation, payment) are unrestricted by policy."
        ),
        "remediation": (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()"
        ),
    },
]

# CSP quality checks — flag dangerous directives
CSP_DANGEROUS = [
    ("unsafe-inline", "csp_unsafe_inline", "HIGH",
     "'unsafe-inline' in CSP script-src defeats XSS protection.",
     "Remove 'unsafe-inline'. Use nonces or hashes instead."),
    ("unsafe-eval", "csp_unsafe_eval", "HIGH",
     "'unsafe-eval' in CSP allows eval() and similar dangerous functions.",
     "Remove 'unsafe-eval'. Refactor code to avoid eval()."),
    ("*", "csp_wildcard_src", "MEDIUM",
     "CSP contains wildcard (*) source, allowing any origin to load resources.",
     "Replace wildcard with explicit allowlisted origins."),
]

# XFO valid values
XFO_VALID = {"DENY", "SAMEORIGIN"}

# Referrer-Policy safe values
REFERRER_SAFE = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


class HeadersScanner:
    def __init__(self, target: str):
        self.target = target
        self.findings: list[dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountySwarm/1.0 (security research)"})

        parsed = urlparse(target if "://" in target else f"https://{target}")
        scheme = parsed.scheme or "https"
        host = parsed.netloc or parsed.path
        self.url = f"{scheme}://{host}"

    # ------------------------------------------------------------------
    def scan(self) -> list[dict]:
        print(f"   🛡️  Headers Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()

        try:
            self._budget.wait_for_budget()
            resp = self.session.get(self.url, timeout=10, verify=True)
        except Exception as exc:
            print(f"      ⚠️  Headers fetch error: {exc}")
            self._save_results()
            return self.findings

        self._evidence.save_http(
            self.url,
            "GET",
            {},
            {"status": resp.status_code, "headers": dict(resp.headers)},
        )

        headers = resp.headers

        self._check_required_headers(headers)
        self._check_csp_quality(headers)
        self._check_xfo_value(headers)
        self._check_referrer_value(headers)
        self._check_server_disclosure(headers)

        self._save_results()
        return self.findings

    # ------------------------------------------------------------------
    def _check_required_headers(self, headers) -> None:
        for hdr in REQUIRED_HEADERS:
            name = hdr["header"]
            if name not in headers:
                self._add(
                    issue=hdr["issue"],
                    detail=hdr["detail"],
                    severity=hdr["severity"],
                    url=self.url,
                    remediation=hdr["remediation"],
                    indicators=[f"Missing: {name}"],
                )
            else:
                print(f"      ✅  {name}: present")

    def _check_csp_quality(self, headers) -> None:
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            return
        for substr, issue, severity, detail, remediation in CSP_DANGEROUS:
            if substr in csp:
                self._add(
                    issue=issue,
                    detail=detail,
                    severity=severity,
                    url=self.url,
                    remediation=remediation,
                    indicators=[substr],
                )

    def _check_xfo_value(self, headers) -> None:
        xfo = headers.get("X-Frame-Options", "").strip().upper()
        if xfo and xfo not in XFO_VALID:
            self._add(
                issue="xfo_invalid_value",
                detail=f"X-Frame-Options has unrecognized value: {xfo!r} (expected DENY or SAMEORIGIN).",
                severity="LOW",
                url=self.url,
                remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                indicators=[xfo],
            )

    def _check_referrer_value(self, headers) -> None:
        policy = headers.get("Referrer-Policy", "").strip().lower()
        if policy and policy not in REFERRER_SAFE:
            self._add(
                issue="referrer_policy_weak",
                detail=f"Referrer-Policy value {policy!r} may leak URL data to cross-origin requests.",
                severity="LOW",
                url=self.url,
                remediation="Use: Referrer-Policy: strict-origin-when-cross-origin",
                indicators=[policy],
            )

    def _check_server_disclosure(self, headers) -> None:
        """Flag Server/X-Powered-By headers that disclose version info."""
        for hdr_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            val = headers.get(hdr_name, "")
            if val:
                # Only flag if it contains version numbers (digits + dots)
                if re.search(r"\d", val):
                    self._add(
                        issue="server_version_disclosure",
                        detail=f"{hdr_name} header discloses version: {val!r}",
                        severity="LOW",
                        url=self.url,
                        remediation=f"Remove or suppress version info from {hdr_name} header.",
                        indicators=[f"{hdr_name}: {val}"],
                    )

    # ------------------------------------------------------------------
    def _add(
        self,
        issue: str,
        detail: str,
        severity: str,
        url: str,
        remediation: str = "",
        indicators: list | None = None,
    ) -> None:
        finding = {
            "type": "Headers",
            "issue": issue,
            "detail": detail,
            "severity": severity,
            "url": url,
            "remediation": remediation,
            "indicators": indicators or [],
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.findings.append(finding)
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚠️")
        print(f"      {sev_icon} [{severity}] Headers/{issue}: {url}")

    def _save_results(self) -> None:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        path = f"{OUTPUT_DIR}/headers_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(path, "w") as f:
            json.dump({"target": self.target, "findings": self.findings, "count": len(self.findings)}, f, indent=2)
        print(f"      💾 Headers findings: {len(self.findings)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python headers_scanner.py <target>")
        sys.exit(1)
    HeadersScanner(sys.argv[1]).scan()
