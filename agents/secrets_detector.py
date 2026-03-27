#!/usr/bin/env python3
"""
Secrets Detector Agent — SwarmReview
Detects API keys, tokens, passwords, private keys, and other sensitive data in code.
Uses detect-secrets if available, falls back to regex patterns.
"""

import os
import sys
import json
import re
import subprocess
import base64
import entropy
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


# High-confidence secret patterns
SECRET_PATTERNS = [
    # Cloud & Infrastructure
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CRITICAL", "aws-key"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Access Key", "CRITICAL", "aws-secret"),
    (r"(?i)aws[_-]?(access[_-]?key[_-]?id|secret[_-]?key)\s*[=:]\s*['\"][^'\"]{20,}['\"]", "AWS Credential", "CRITICAL", "aws-credential"),

    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "CRITICAL", "github-token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "CRITICAL", "github-oauth"),
    (r"ghu_[A-Za-z0-9]{36}", "GitHub User-to-Server Token", "CRITICAL", "github-utokens"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub Server-to-Server Token", "CRITICAL", "github-server"),
    (r"ghr_[A-Za-z0-9]{36}", "GitHub Refresh Token", "CRITICAL", "github-refresh"),

    # OpenAI / AI APIs
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API Key", "CRITICAL", "openai-key"),
    (r"sk-proj-[A-Za-z0-9_-]{20,}", "OpenAI Project Key", "CRITICAL", "openai-project-key"),

    # Slack
    (r"xox[baprs]-[A-Za-z0-9]{10,}", "Slack Token", "CRITICAL", "slack-token"),

    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "CRITICAL", "stripe-live"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Live Restricted Key", "CRITICAL", "stripe-restricted"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", "MEDIUM", "stripe-publishable"),

    # Generic secrets
    (r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"][A-Za-z0-9_-]{20,}['\"]", "Potential API Key", "HIGH", "api-key"),
    (r"(?i)secret\s*[=:]\s*['\"][^'\"]{16,}['\"]", "Potential Secret Value", "HIGH", "secret-value"),
    (r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password", "HIGH", "password"),
    (r"(?i)passwd\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password (passwd)", "HIGH", "password"),
    (r"(?i)bearer\s+[A-Za-z0-9_-]{20,}", "Bearer Token in Header", "HIGH", "bearer-token"),

    # Private keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "Private Key", "CRITICAL", "private-key"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate", "HIGH", "certificate"),

    # Database
    (r"(?i)(mysql|postgres|postgresql|mongodb|redis)[_-]?(conn|connection|uri|url)\s*[=:]\s*['\"][^'\"]{20,}['\"]", "Database Connection String", "HIGH", "db-connection"),

    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", "HIGH", "twilio-key"),

    # SendGrid
    (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key", "CRITICAL", "sendgrid-key"),

    # JWT
    (r"eyJ[A-Za-z0-9_-]\.eyJ[A-Za-z0-9_-]\.[A-Za-z0-9_-]*", "JWT Token", "HIGH", "jwt-token"),

    # Telegram
    (r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token", "CRITICAL", "telegram-token"),

    # Discord
    (r"[MN][A-Za-z\\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token", "CRITICAL", "discord-token"),

    # Google Cloud
    (r"[a-zA-Z0-9_-]+@([a-z]|d){2,}[-.]?g(serviceaccount)?\\.iam\\.gserviceaccount\\.com", "Google Service Account", "CRITICAL", "gcp-service-account"),
]

# File extensions that should be scanned
SCAN_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".cpp", ".cs", ".yaml", ".yml", ".json", ".sh", ".bash",
    ".env", ".ini", ".cfg", ".conf", ".toml", ".xml", ".sql",
}


def compute_entropy(text: str) -> float:
    """Compute Shannon entropy of a string."""
    if not text:
        return 0.0
    import math
    freq = {}
    for byte in text.encode():
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class SecretsDetector:
    """Detect secrets in code, files, or diffs."""

    def __init__(
        self,
        target_path: str,
        profile: str = "cautious",
        output_dir: Optional[str] = None,
        min_entropy: float = 4.5,
    ):
        self.target_path = target_path
        self.profile = profile
        self.output_dir = output_dir or os.getenv("SWARM_OUTPUT_DIR", str(REPO_ROOT / "output"))
        self.min_entropy = min_entropy if profile == "deep" else 5.0
        self.findings = []
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self) -> list[dict]:
        """Run secret detection on the target path."""
        self.findings = []

        # Try detect-secrets first
        detect_secrets_found = self._run_detect_secrets()
        if detect_secrets_found:
            return self.findings

        # Fallback to regex scan
        self._scan_with_patterns()
        return self.findings

    def _run_detect_secrets(self) -> bool:
        """Run detect-secrets tool if available."""
        try:
            result = subprocess.run(
                ["detect-secrets", "scan", self.target_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    for filename, secrets in data.get("results", {}).items():
                        for secret in secrets:
                            self.findings.append({
                                "tool": "detect-secrets",
                                "type": "secrets",
                                "severity": "HIGH",
                                "title": f"Potential secret: {secret.get('type', 'unknown')}",
                                "file": filename,
                                "line": secret.get("line_number"),
                                "description": f"Type: {secret.get('type', 'unknown')} — verify and revoke if legitimate",
                                "is_verified": secret.get("is_verified", False),
                                "secret_type": secret.get("type"),
                            })
                    return True
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            print("[SecretsDetector] detect-secrets not installed — pip install detect-secrets")
        except subprocess.TimeoutExpired:
            print("[SecretsDetector] detect-secrets timed out")
        except Exception as e:
            print(f"[SecretsDetector] detect-secrets error: {e}")
        return False

    def _scan_with_patterns(self):
        """Scan files with regex patterns + entropy analysis."""
        for root, dirs, files in os.walk(self.target_path):
            # Skip non-code dirs
            dirs[:] = [d for d in dirs if d not in (
                ".git", "node_modules", "__pycache__", ".venv", "venv",
                ".pytest_cache", ".tox", "dist", "build", ".egg-info"
            )]

            for fname in files:
                ext = Path(fname).suffix.lower()
                # Skip binary and lock files
                if ext in {".png", ".jpg", ".jpeg", ".gif", ".zip", ".tar", ".gz", ".pdf", ".mp4", ".mp3"}:
                    continue
                # Skip package lock files (too noisy)
                if fname in {"package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock", "Gemfile.lock"}:
                    continue

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        for lineno, line in enumerate(f, 1):
                            # Skip comments and docstrings
                            stripped = line.strip()
                            if stripped.startswith(("#", "//", "/*", "*/", "*", "<!--")):
                                continue

                            self._check_line(fpath, lineno, line)
                except (OSError, IOError):
                    pass

    def _check_line(self, fpath: str, lineno: int, line: str):
        """Check a single line for secrets."""
        # Pattern-based detection
        for pattern, label, severity, secret_type in SECRET_PATTERNS:
            try:
                match = re.search(pattern, line)
                if match:
                    # Don't flag false positives in examples/docs
                    context = line.lower()
                    if any(x in context for x in ["example", "placeholder", "xxx", "your_", "your-", "test", "foo", "bar", "dummy"]):
                        continue

                    # Extract the secret value for entropy check
                    secret_value = match.group(0)
                    ent = compute_entropy(secret_value)
                    if ent < self.min_entropy:
                        continue

                    self.findings.append({
                        "tool": "regex-patterns",
                        "type": "secrets",
                        "severity": severity,
                        "title": label,
                        "file": fpath,
                        "line": lineno,
                        "description": f"{label} detected at line {lineno}",
                        "secret_type": secret_type,
                        "entropy": round(ent, 2),
                    })
            except re.error:
                pass

        # Entropy-based detection (flag high-entropy strings that look like secrets)
        if self.profile == "deep":
            for match in re.finditer(r"['\"][A-Za-z0-9/+=]{20,}['\"]", line):
                val = match.group(0)[1:-1]
                ent = compute_entropy(val)
                if ent >= self.min_entropy:
                    # Skip if already caught by pattern
                    if not any(f.get("file") == fpath and f.get("line") == lineno for f in self.findings):
                        self.findings.append({
                            "tool": "entropy-analysis",
                            "type": "secrets",
                            "severity": "MEDIUM",
                            "title": "High-entropy string (possible secret)",
                            "file": fpath,
                            "line": lineno,
                            "description": f"Entropy: {ent:.2f} — review manually",
                            "secret_type": "high-entropy-string",
                            "entropy": round(ent, 2),
                        })

    def write_output(self, suffix: str = "secrets") -> str:
        """Write findings to JSON output."""
        path = os.path.join(self.output_dir, f"secrets_findings_{suffix}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "tool": "secrets-detector",
                "profile": self.profile,
                "target": self.target_path,
                "findings_count": len(self.findings),
                "findings": self.findings,
            }, f, indent=2)
        return path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Detect secrets in code")
    parser.add_argument("path", help="Path to code directory or file")
    parser.add_argument("--profile", default="cautious", choices=["passive", "cautious", "deep"])
    parser.add_argument("--out", help="Output directory")
    args = parser.parse_args()

    detector = SecretsDetector(args.path, profile=args.profile, output_dir=args.out)
    findings = detector.run()
    out_path = detector.write_output(Path(args.path).name)

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    print(f"SecretsDetector: {len(findings)} findings — CRITICAL:{critical} HIGH:{high} MEDIUM:{medium}")
    print(f"Output: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
