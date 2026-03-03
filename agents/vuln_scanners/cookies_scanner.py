#!/usr/bin/env python3
"""
Cookies Scanner
Checks: Secure flag, HttpOnly flag, SameSite attribute, session cookie detection.
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

# Patterns that strongly indicate a session/auth cookie by name
SESSION_COOKIE_PATTERNS = re.compile(
    r"(sess|session|auth|token|jwt|sid|user_?id|remember|logged|csrftoken|xsrf)",
    re.I,
)

# SameSite values that are considered safe
SAMESITE_SAFE = {"strict", "lax"}


class CookiesScanner:
    def __init__(self, target: str):
        self.target = target
        self.findings: list[dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountySwarm/1.0 (security research)"})

        parsed = urlparse(target if "://" in target else f"https://{target}")
        scheme = parsed.scheme or "https"
        host = parsed.netloc or parsed.path
        self.url = f"{scheme}://{host}"
        self.is_https = scheme == "https"

    # ------------------------------------------------------------------
    def scan(self) -> list[dict]:
        print(f"   🍪 Cookies Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()

        try:
            self._budget.wait_for_budget()
            resp = self.session.get(self.url, timeout=10, verify=True)
        except Exception as exc:
            print(f"      ⚠️  Cookies fetch error: {exc}")
            self._save_results()
            return self.findings

        raw_cookies = resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else []
        if not raw_cookies:
            raw_cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

        # Also capture via requests CookieJar for attribute inspection
        jar_cookies = list(resp.cookies)

        self._evidence.save_http(
            self.url,
            "GET",
            {},
            {
                "status": resp.status_code,
                "set_cookie_headers": raw_cookies,
                "cookies": {c.name: c.value for c in jar_cookies},
            },
        )

        if not raw_cookies and not jar_cookies:
            print("      ℹ️  No Set-Cookie headers found.")
        else:
            self._analyze_raw_cookies(raw_cookies)

        self._save_results()
        return self.findings

    # ------------------------------------------------------------------
    def _analyze_raw_cookies(self, raw_cookies: list[str]) -> None:
        """Parse each raw Set-Cookie header and check flags."""
        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue

            # First part is name=value
            name_val = parts[0]
            name = name_val.split("=", 1)[0].strip()
            directives_lower = [p.lower() for p in parts[1:]]
            directives_orig = parts[1:]

            is_session = bool(SESSION_COOKIE_PATTERNS.search(name))
            label = f"session/auth cookie {name!r}" if is_session else f"cookie {name!r}"

            # --- Secure flag ---
            if "secure" not in directives_lower:
                sev = "HIGH" if is_session else "MEDIUM"
                self._add(
                    issue="cookie_missing_secure_flag",
                    detail=(
                        f"The {label} is missing the Secure flag. "
                        "It may be transmitted over plain HTTP, enabling interception."
                    ),
                    severity=sev,
                    url=self.url,
                    remediation=f"Add the Secure flag to the {name} cookie.",
                    indicators=[name],
                )
            else:
                print(f"      ✅  {name}: Secure")

            # --- HttpOnly flag ---
            if "httponly" not in directives_lower:
                sev = "HIGH" if is_session else "MEDIUM"
                self._add(
                    issue="cookie_missing_httponly_flag",
                    detail=(
                        f"The {label} is missing the HttpOnly flag. "
                        "JavaScript can access this cookie, increasing XSS impact."
                    ),
                    severity=sev,
                    url=self.url,
                    remediation=f"Add the HttpOnly flag to the {name} cookie.",
                    indicators=[name],
                )
            else:
                print(f"      ✅  {name}: HttpOnly")

            # --- SameSite attribute ---
            samesite_val = None
            for d in directives_lower:
                if d.startswith("samesite"):
                    parts_ss = d.split("=", 1)
                    samesite_val = parts_ss[1].strip() if len(parts_ss) > 1 else ""
                    break

            if samesite_val is None:
                sev = "MEDIUM" if is_session else "LOW"
                self._add(
                    issue="cookie_missing_samesite",
                    detail=(
                        f"The {label} has no SameSite attribute. "
                        "Without SameSite, the browser sends the cookie on cross-site requests, "
                        "enabling CSRF attacks."
                    ),
                    severity=sev,
                    url=self.url,
                    remediation=(
                        f"Add SameSite=Strict or SameSite=Lax to the {name} cookie. "
                        "Use Strict for session cookies; Lax is the safe browser default."
                    ),
                    indicators=[name],
                )
            elif samesite_val not in SAMESITE_SAFE:
                if samesite_val == "none":
                    # SameSite=None requires Secure
                    if "secure" not in directives_lower:
                        self._add(
                            issue="cookie_samesite_none_without_secure",
                            detail=(
                                f"The {label} uses SameSite=None without Secure. "
                                "Browsers reject this and may treat it as SameSite=Strict."
                            ),
                            severity="MEDIUM",
                            url=self.url,
                            remediation=f"Add Secure flag when using SameSite=None for {name}.",
                            indicators=[name],
                        )
                    else:
                        # SameSite=None + Secure is a deliberate cross-site cookie
                        if is_session:
                            self._add(
                                issue="session_cookie_samesite_none",
                                detail=(
                                    f"Session/auth cookie {name!r} uses SameSite=None, "
                                    "allowing cross-site requests. Verify this is intentional."
                                ),
                                severity="MEDIUM",
                                url=self.url,
                                remediation=(
                                    "Use SameSite=Strict for session cookies unless a cross-site "
                                    "use case (e.g., embedded iframe) explicitly requires None."
                                ),
                                indicators=[name],
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
            "type": "Cookies",
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
        print(f"      {sev_icon} [{severity}] Cookies/{issue}: {url}")

    def _save_results(self) -> None:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        path = f"{OUTPUT_DIR}/cookies_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(path, "w") as f:
            json.dump({"target": self.target, "findings": self.findings, "count": len(self.findings)}, f, indent=2)
        print(f"      💾 Cookies findings: {len(self.findings)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cookies_scanner.py <target>")
        sys.exit(1)
    CookiesScanner(sys.argv[1]).scan()
