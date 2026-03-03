#!/usr/bin/env python3
"""
TLS Scanner
Checks: TLS protocol/cipher strength, HSTS (present + valid), cert expiry, HTTP→HTTPS redirect.
Outputs structured findings ready for disclosure emails.
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests.exceptions import SSLError, ConnectionError as ReqConnError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence.store import EvidenceStore
from core.rate_limit import from_env as budget_from_env

OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[2] / "output")

# Weak TLS versions — flag these
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# Weak cipher substrings — flag these
WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA",
]

# HSTS min age we consider "valid" (6 months in seconds)
HSTS_MIN_AGE = 15_552_000

# Days before expiry we consider "expiring soon"
CERT_EXPIRY_WARN_DAYS = 30


class TLSScanner:
    def __init__(self, target: str):
        self.target = target
        self.findings: list[dict] = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountySwarm/1.0 (security research)"})
        self.session.max_redirects = 3

        parsed = urlparse(target if "://" in target else f"https://{target}")
        self.host = parsed.hostname or target
        self.port = parsed.port or 443
        self.https_url = f"https://{self.host}" + (f":{self.port}" if self.port != 443 else "")
        self.http_url = f"http://{self.host}" + (f":{parsed.port or 80}" if (parsed.port or 80) != 80 else "")

    # ------------------------------------------------------------------
    def scan(self) -> list[dict]:
        print(f"   🔒 TLS Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()

        self._check_https_redirect()
        self._check_tls_version_and_cipher()
        self._check_cert_expiry()
        self._check_hsts()
        self._save_results()
        return self.findings

    # ------------------------------------------------------------------
    def _check_https_redirect(self) -> None:
        """Confirm that HTTP redirects to HTTPS."""
        try:
            self._budget.wait_for_budget()
            resp = self.session.get(
                self.http_url,
                timeout=10,
                allow_redirects=False,
            )
            self._evidence.save_http(
                self.http_url,
                "GET",
                {},
                {"status": resp.status_code, "headers": dict(resp.headers)},
            )
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                # Good — redirect exists
                if resp.status_code != 301:
                    self._add(
                        issue="http_to_https_redirect_non_permanent",
                        detail=f"Redirect to HTTPS uses {resp.status_code} (prefer 301 for HSTS pre-load)",
                        severity="LOW",
                        url=self.http_url,
                        remediation="Change redirect to 301 Permanent.",
                    )
            else:
                self._add(
                    issue="http_no_redirect_to_https",
                    detail=f"HTTP endpoint returns {resp.status_code} without redirecting to HTTPS. "
                           f"Location: {location or 'none'}",
                    severity="HIGH",
                    url=self.http_url,
                    remediation="Configure server to redirect all HTTP traffic to HTTPS with a 301.",
                )
        except ReqConnError:
            pass  # Port 80 not open — not a vuln
        except Exception as exc:
            print(f"      ⚠️  HTTPS-redirect check error: {exc}")

    # ------------------------------------------------------------------
    def _check_tls_version_and_cipher(self) -> None:
        """Connect with ssl module and inspect negotiated version + cipher."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    version = ssock.version() or ""
                    cipher_name, _, _ = ssock.cipher() or ("", "", "")

            if version in WEAK_TLS_VERSIONS:
                self._add(
                    issue="weak_tls_version",
                    detail=f"Server negotiated weak TLS version: {version}",
                    severity="HIGH",
                    url=self.https_url,
                    remediation="Disable TLS 1.0 and 1.1. Support only TLS 1.2+ (prefer 1.3).",
                    indicators=[version],
                )
            else:
                print(f"      ✅  TLS version: {version}")

            if cipher_name:
                matched = [p for p in WEAK_CIPHER_PATTERNS if p in cipher_name.upper()]
                if matched:
                    self._add(
                        issue="weak_tls_cipher",
                        detail=f"Server negotiated weak cipher: {cipher_name} (matched: {matched})",
                        severity="HIGH",
                        url=self.https_url,
                        remediation="Restrict cipher suites to ECDHE+AES-GCM or ChaCha20-Poly1305.",
                        indicators=[cipher_name],
                    )
                else:
                    print(f"      ✅  Cipher: {cipher_name}")

        except ssl.SSLError as exc:
            self._add(
                issue="tls_ssl_error",
                detail=f"SSL handshake error: {exc}",
                severity="MEDIUM",
                url=self.https_url,
                remediation="Review TLS configuration for protocol support issues.",
            )
        except Exception as exc:
            print(f"      ⚠️  TLS version/cipher check error: {exc}")

    # ------------------------------------------------------------------
    def _check_cert_expiry(self) -> None:
        """Check certificate expiry date."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()

            not_after_str = cert.get("notAfter", "")
            if not not_after_str:
                return

            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days

            if days_left < 0:
                self._add(
                    issue="cert_expired",
                    detail=f"TLS certificate expired {abs(days_left)} days ago ({not_after_str})",
                    severity="CRITICAL",
                    url=self.https_url,
                    remediation="Renew TLS certificate immediately.",
                    indicators=[not_after_str],
                )
            elif days_left <= CERT_EXPIRY_WARN_DAYS:
                self._add(
                    issue="cert_expiring_soon",
                    detail=f"TLS certificate expires in {days_left} days ({not_after_str})",
                    severity="MEDIUM",
                    url=self.https_url,
                    remediation=f"Renew TLS certificate before {not_after_str}.",
                    indicators=[not_after_str],
                )
            else:
                print(f"      ✅  Cert valid for {days_left} more days")

        except Exception as exc:
            print(f"      ⚠️  Cert expiry check error: {exc}")

    # ------------------------------------------------------------------
    def _check_hsts(self) -> None:
        """Check Strict-Transport-Security header presence and validity."""
        try:
            self._budget.wait_for_budget()
            resp = self.session.get(self.https_url, timeout=10, verify=True)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            self._evidence.save_http(
                self.https_url,
                "GET",
                {},
                {"status": resp.status_code, "hsts_header": hsts},
            )

            if not hsts:
                self._add(
                    issue="hsts_missing",
                    detail="Strict-Transport-Security header not present on HTTPS response.",
                    severity="MEDIUM",
                    url=self.https_url,
                    remediation=(
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                )
                return

            # Parse max-age
            ma_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if not ma_match:
                self._add(
                    issue="hsts_malformed",
                    detail=f"HSTS header present but max-age missing or unparseable: {hsts!r}",
                    severity="MEDIUM",
                    url=self.https_url,
                    remediation="Set a valid max-age (minimum 15552000 / 6 months).",
                )
                return

            max_age = int(ma_match.group(1))
            if max_age < HSTS_MIN_AGE:
                self._add(
                    issue="hsts_max_age_too_short",
                    detail=f"HSTS max-age={max_age} is below recommended minimum {HSTS_MIN_AGE} (6 months).",
                    severity="LOW",
                    url=self.https_url,
                    remediation="Increase HSTS max-age to at least 31536000 (1 year) for preload eligibility.",
                    indicators=[f"max-age={max_age}"],
                )
            else:
                print(f"      ✅  HSTS max-age={max_age}")

            if "includeSubDomains" not in hsts:
                self._add(
                    issue="hsts_no_includeSubDomains",
                    detail="HSTS header missing includeSubDomains directive.",
                    severity="LOW",
                    url=self.https_url,
                    remediation="Add includeSubDomains to HSTS header.",
                )

        except SSLError as exc:
            self._add(
                issue="tls_cert_error",
                detail=f"SSL/TLS certificate error when connecting: {exc}",
                severity="HIGH",
                url=self.https_url,
                remediation="Fix TLS certificate (expired, self-signed, or hostname mismatch).",
            )
        except Exception as exc:
            print(f"      ⚠️  HSTS check error: {exc}")

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
            "type": "TLS",
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
        print(f"      {sev_icon} [{severity}] TLS/{issue}: {url}")

    def _save_results(self) -> None:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        path = f"{OUTPUT_DIR}/tls_{safe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(path, "w") as f:
            json.dump({"target": self.target, "findings": self.findings, "count": len(self.findings)}, f, indent=2)
        print(f"      💾 TLS findings: {len(self.findings)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tls_scanner.py <target>")
        sys.exit(1)
    TLSScanner(sys.argv[1]).scan()
