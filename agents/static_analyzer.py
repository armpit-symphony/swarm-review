#!/usr/bin/env python3
"""
Static Analyzer Agent — SAST wrapper for SwarmReview
Supports Bandit (Python), Semgrep (multi-language), and manual pattern matching.
"""

import os
import sys
import json
import subprocess
import re
from pathlib import Path
from typing import Optional

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


class StaticAnalyzer:
    """Run SAST scans on a codebase or diff."""

    def __init__(
        self,
        target_path: str,
        profile: str = "cautious",
        output_dir: Optional[str] = None,
    ):
        self.target_path = target_path
        self.profile = profile
        self.output_dir = output_dir or os.getenv("SWARM_OUTPUT_DIR", str(REPO_ROOT / "output"))
        self.findings = []
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self) -> list[dict]:
        """Run all enabled SAST tools and return consolidated findings."""
        self.findings = []

        # Detect language mix
        languages = self._detect_languages()

        # Run Bandit for Python files
        if "python" in languages:
            self._run_bandit()

        # Run Semgrep for all languages
        self._run_semgrep()

        # Run custom pattern matching
        self._run_custom_patterns()

        return self.findings

    def _detect_languages(self) -> set[str]:
        """Detect programming languages in the target path."""
        languages = set()
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
        }
        try:
            for root, dirs, files in os.walk(self.target_path):
                # Skip non-code dirs
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache")]
                for fname in files:
                    ext = Path(fname).suffix.lower()
                    lang = ext_map.get(ext)
                    if lang:
                        languages.add(lang)
        except OSError:
            pass
        return languages

    def _run_bandit(self):
        """Run Bandit Python SAST scanner."""
        try:
            result = subprocess.run(
                ["bandit", "-r", self.target_path, "-f", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode in (0, 1):
                try:
                    data = json.loads(result.stdout)
                    for issue in data.get("results", []):
                        self.findings.append({
                            "tool": "bandit",
                            "type": "sast",
                            "severity": self._bandit_to_severity(issue.get("issue_severity", "LOW")),
                            "confidence": issue.get("issue_confidence", "LOW"),
                            "title": issue.get("issue_text", "Bandit finding"),
                            "file": issue.get("filename"),
                            "line": issue.get("line"),
                            "column": issue.get("line_range", [None, None])[1],
                            "description": issue.get("issue_text"),
                            "test_id": issue.get("test_id"),
                            "more_info": issue.get("more_info"),
                        })
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            print("[StaticAnalyzer] Bandit not installed — pip install bandit")
        except subprocess.TimeoutExpired:
            print("[StaticAnalyzer] Bandit timed out after 300s")
        except Exception as e:
            print(f"[StaticAnalyzer] Bandit error: {e}")

    def _run_semgrep(self):
        """Run Semgrep multi-language SAST scanner."""
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", self.target_path],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode in (0, 1):
                try:
                    data = json.loads(result.stdout)
                    for result_item in data.get("results", []):
                        extra = result_item.get("extra", {})
                        metadata = extra.get("metadata", {})
                        self.findings.append({
                            "tool": "semgrep",
                            "type": "sast",
                            "severity": self._semgrep_to_severity(extra.get("severity", "INFO")),
                            "confidence": "HIGH",  # Semgrep rules are curated
                            "title": result_item.get("check_id", "semgrep finding"),
                            "file": result_item.get("path"),
                            "line": result_item.get("start", {}).get("line"),
                            "column": result_item.get("start", {}).get("col"),
                            "description": extra.get("message"),
                            "cwe": metadata.get("cwe"),
                            "owasp": metadata.get("owasp"),
                            "license": extra.get("licenses", [None])[0],
                        })
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            print("[StaticAnalyzer] Semgrep not installed — see https://semgrep.dev/install")
        except subprocess.TimeoutExpired:
            print("[StaticAnalyzer] Semgrep timed out after 600s")
        except Exception as e:
            print(f"[StaticAnalyzer] Semgrep error: {e}")

    def _run_custom_patterns(self):
        """Run custom regex patterns for quick security hotspots."""
        patterns = [
            # SQL Injection patterns
            (r"execute\s*\(\s*[\"'].*?%s.*?[\"']", "Potential SQL injection (string formatting)", "HIGH", "sql-injection-format"),
            (r"\.format\s*\(.*?(?:request|user|input)", "Potential SQL injection (.format)", "MEDIUM", "sql-injection-format"),

            # Command injection
            (r"os\.system\s*\(", "os.system() call — command injection risk", "HIGH", "command-injection"),
            (r"subprocess\.(call|run|popen)\s*\(.*?shell\s*=\s*True", "subprocess with shell=True — command injection risk", "HIGH", "command-injection"),

            # Path traversal
            (r"open\s*\([^)]*request\.(args|values|form|files)", "File operation with user input — path traversal risk", "HIGH", "path-traversal"),
            (r"send_file\s*\(.*?request\.", "Flask send_file with user input — path traversal risk", "HIGH", "path-traversal"),

            # Hardcoded secrets patterns
            (r"(?i)api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9]{20,}['\"]", "Hardcoded API key", "CRITICAL", "hardcoded-secret"),
            (r"(?i)secret[_-]?key\s*[=:]\s*['\"][^'\"]{16,}['\"]", "Hardcoded secret key", "CRITICAL", "hardcoded-secret"),
            (r"sk-[A-Za-z0-9]{20,}", "Potential OpenAI/GitHub secret", "CRITICAL", "hardcoded-secret"),
            (r"ghp_[A-Za-z0-9]{36}", "Potential GitHub token", "CRITICAL", "hardcoded-secret"),
            (r"xox[baprs]-[A-Za-z0-9]{10,}", "Potential Slack token", "CRITICAL", "hardcoded-secret"),

            # Auth issues
            (r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Hardcoded password", "HIGH", "hardcoded-secret"),
            (r"DEBUG\s*=\s*True", "Debug mode enabled in production", "MEDIUM", "misconfiguration"),

            # XSS patterns (Python web)
            (r"render_template_string\s*\(", "render_template_string — XSS risk", "HIGH", "xss"),
            (r"Markup\s*\(.*?\)", "Manual Markup usage — XSS risk if unescaped", "MEDIUM", "xss"),

            # Insecure dependencies
            (r"requests\s*<\s*2\.", "Outdated requests library — security risk", "MEDIUM", "insecure-dependency"),
        ]

        try:
            for root, dirs, files in os.walk(self.target_path):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache")]
                for fname in files:
                    if not fname.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php")):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            for lineno, line in enumerate(f, 1):
                                for pattern, label, severity, vuln_type in patterns:
                                    if re.search(pattern, line):
                                        self.findings.append({
                                            "tool": "custom-patterns",
                                            "type": "sast",
                                            "severity": severity,
                                            "confidence": "MEDIUM",
                                            "title": label,
                                            "file": fpath,
                                            "line": lineno,
                                            "description": f"Line {lineno}: {label}",
                                            "vuln_type": vuln_type,
                                        })
                    except (OSError, IOError):
                        pass
        except Exception as e:
            print(f"[StaticAnalyzer] Custom pattern scan error: {e}")

    @staticmethod
    def _bandit_to_severity(level: str) -> str:
        mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        return mapping.get(level.upper(), "MEDIUM")

    @staticmethod
    def _semgrep_to_severity(level: str) -> str:
        mapping = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        return mapping.get(level.upper(), "MEDIUM")

    def write_output(self, suffix: str = "sast") -> str:
        """Write findings to JSON output file."""
        slug = f"sast_findings_{suffix}"
        path = os.path.join(self.output_dir, f"{slug}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "tool": "static-analyzer",
                "profile": self.profile,
                "target": self.target_path,
                "findings_count": len(self.findings),
                "findings": self.findings,
            }, f, indent=2)
        return path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run SAST scan on a codebase")
    parser.add_argument("path", help="Path to code directory or file")
    parser.add_argument("--profile", default="cautious", choices=["passive", "cautious", "deep"])
    parser.add_argument("--out", help="Output directory")
    args = parser.parse_args()

    analyzer = StaticAnalyzer(args.path, profile=args.profile, output_dir=args.out)
    findings = analyzer.run()
    out_path = analyzer.write_output(Path(args.path).name)

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print(f"StaticAnalyzer: {len(findings)} findings — {by_sev}")
    print(f"Output: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
