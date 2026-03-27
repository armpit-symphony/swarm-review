#!/usr/bin/env python3
"""
SwarmReview — Code Review Pipeline
Multi-pass autonomous code review for AI-generated code.

Pass 1: SAST (Bandit/Semgrep)
Pass 2: Secrets Detection
Pass 3: LLM Logic Analysis
Pass 4: Cross-pass Correlation

Usage:
    python3 code_review_pipeline.py --github-repo owner/repo --pr-number 42
    python3 code_review_pipeline.py --diff /path/to/changes.diff
    python3 code_review_pipeline.py --repo /path/to/local/repo
"""

import os
import sys
import json
import argparse
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add agents to path
AGENT_DIR = Path(__file__).parent
sys.path.insert(0, str(AGENT_DIR))

from core.report import write_json, write_markdown
from core.config import load_profiles, load_budget, repo_root

OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).parent / "output")


class CodeReviewPipeline:
    """Multi-pass code review orchestrator."""

    def __init__(
        self,
        target_repo: str = None,
        pr_number: int = None,
        diff_path: str = None,
        local_repo: str = None,
        profile: str = "cautious",
        output_dir: str = OUTPUT_DIR,
        github_token: str = None,
        openclaw: bool = False,
    ):
        self.target_repo = target_repo
        self.pr_number = pr_number
        self.diff_path = diff_path
        self.local_repo = local_repo
        self.profile = profile
        self.output_dir = output_dir
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.openclaw = openclaw
        self.findings = []
        self.run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.work_dir = None

        os.makedirs(output_dir, exist_ok=True)

    def run(self) -> dict:
        """Execute the full multi-pass review pipeline."""
        print(f"[SwarmReview] Starting review pipeline — run_id={self.run_id}")
        print(f"[SwarmReview] Profile: {self.profile}")

        # Pass 1: SAST
        sast_results = self._pass1_sast()
        self.findings.extend(sast_results)
        print(f"[SwarmReview] Pass 1 (SAST): {len(sast_results)} findings")

        # Pass 2: Secrets Detection
        secrets_results = self._pass2_secrets()
        self.findings.extend(secrets_results)
        print(f"[SwarmReview] Pass 2 (Secrets): {len(secrets_results)} findings")

        # Pass 3: LLM Logic Analysis (if profile=deep)
        if self.profile == "deep":
            llm_results = self._pass3_llm()
            self.findings.extend(llm_results)
            print(f"[SwarmReview] Pass 3 (LLM): {len(llm_results)} findings")

            # Pass 4: Correlation
            correlated = self._pass4_correlate()
            print(f"[SwarmReview] Pass 4 (Correlation): {len(correlated)} refined findings")

        # Write outputs
        self._write_outputs()

        return {
            "run_id": self.run_id,
            "profile": self.profile,
            "total_findings": len(self.findings),
            "findings": self.findings,
        }

    def _pass1_sast(self) -> list:
        """Pass 1: Static Analysis via Bandit + Semgrep."""
        findings = []

        # Try Bandit (Python)
        try:
            result = subprocess.run(
                ["bandit", "-r", self.work_dir or ".", "-f", "json"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode in (0, 1):  # 0=no issues, 1=issues found
                try:
                    data = json.loads(result.stdout)
                    for issue in data.get("results", []):
                        findings.append({
                            "pass": 1,
                            "tool": "bandit",
                            "type": "sast",
                            "severity": issue.get("issue_severity", "LOW"),
                            "confidence": issue.get("issue_confidence", "LOW"),
                            "title": issue["issue_text"],
                            "file": issue.get("filename"),
                            "line": issue.get("line"),
                            "description": issue.get("issue_text"),
                        })
                except json.JSONDecodeError:
                    pass
        except (subprocess.Expiredaresult.TimedExc, FileNotFoundError):
            print("[SwarmReview] Bandit not available — skipping Python SAST")

        # Try Semgrep (multi-language)
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", self.work_dir or "."],
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode in (0, 1):
                try:
                    data = json.loads(result.stdout)
                    for result_item in data.get("results", []):
                        findings.append({
                            "pass": 1,
                            "tool": "semgrep",
                            "type": "sast",
                            "severity": result_item.get("extra", {}).get("severity", "INFO"),
                            "title": result_item.get("check_id"),
                            "file": result_item.get("path"),
                            "line": result_item.get("start", {}).get("line"),
                            "description": result_item.get("extra", {}).get("message"),
                        })
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[SwarmReview] Semgrep not available — skipping multi-lang SAST")

        return findings

    def _pass2_secrets(self) -> list:
        """Pass 2: Secrets detection via detect-secrets."""
        findings = []

        try:
            # Use detect-secrets if available
            result = subprocess.run(
                ["detect-secrets", "scan", self.work_dir or "."],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    for secret in data.get("results", {}).values():
                        findings.append({
                            "pass": 2,
                            "tool": "detect-secrets",
                            "type": "secrets",
                            "severity": "HIGH",
                            "title": f"Potential secret: {secret.get('type', 'unknown')}",
                            "file": secret.get("filename"),
                            "line": secret.get("line_number"),
                            "description": f"Detected {secret.get('type')} — review and revoke if legitimate",
                            "is_verified": secret.get("is_verified", False),
                        })
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback: basic regex scan
            print("[SwarmReview] detect-secrets not available — using fallback regex scan")
            findings.extend(self._secrets_fallback())

        return findings

    def _secrets_fallback(self) -> list:
        """Basic regex-based secrets detection (fallback)."""
        findings = []
        patterns = [
            (r"api[_-]?key\s*=\s*['\"][A-Za-z0-9]{20,}['\"]", "Potential API key"),
            (r"sk-[A-Za-z0-9]{20,}", "Potential OpenAI/GitHub secret"),
            (r"ghp_[A-Za-z0-9]{36}", "Potential GitHub token"),
            (r"xox[baprs]-[A-Za-z0-9]{10,}", "Potential Slack token"),
            (r"password\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded password"),
            (r"aws[_-]?access[_-]?key[_-]?id\s*=\s*['\"][A-Z0-9]{16,}['\"]", "Potential AWS key"),
        ]

        import re
        for root, dirs, files in os.walk(self.work_dir or "."):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]

            for fname in files:
                if fname.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".sh")):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            for lineno, line in enumerate(f, 1):
                                for pattern, label in patterns:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        findings.append({
                                            "pass": 2,
                                            "tool": "regex-fallback",
                                            "type": "secrets",
                                            "severity": "HIGH",
                                            "title": label,
                                            "file": fpath,
                                            "line": lineno,
                                            "description": f"Potential secret in {fname}:{lineno}",
                                        })
                    except (OSError, IOError):
                        pass
        return findings

    def _pass3_llm(self) -> list:
        """Pass 3: LLM-powered logic analysis (requires Grok or MiniMax)."""
        # TODO: Implement when Phase 2 is approved
        print("[SwarmReview] Pass 3 (LLM) — Phase 2 feature, not yet implemented")
        return []

    def _pass4_correlate(self) -> list:
        """Pass 4: Cross-pass correlation of findings."""
        # TODO: Implement when Phase 2 is approved
        print("[SwarmReview] Pass 4 (Correlation) — Phase 2 feature, not yet implemented")
        return self.findings

    def _write_outputs(self):
        """Write findings and summary to output directory."""
        slug = f"review_{self.run_id}"
        prefix = os.path.join(self.output_dir, slug)

        # JSON findings
        findings_file = f"{prefix}_findings.json"
        write_json(findings_file, {
            "run_id": self.run_id,
            "timestamp": datetime.utcnow().isoformat(),
            "profile": self.profile,
            "target": self.target_repo or self.diff_path or self.local_repo,
            "total_findings": len(self.findings),
            "findings": self.findings,
        })

        # Markdown summary
        summary_file = f"{prefix}_report.md"
        lines = [
            f"# SwarmReview Report — {self.run_id}",
            f"",
            f"**Profile:** {self.profile}",
            f"**Target:** {self.target_repo or self.diff_path or self.local_repo}",
            f"**Total Findings:** {len(self.findings)}",
            f"",
        ]

        by_severity = {}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            by_severity.setdefault(sev, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in by_severity:
                lines.append(f"## {sev} ({len(by_severity[sev])})")
                for item in by_severity[sev]:
                    lines.append(f"- **{item.get('title', 'Unknown')}** — `{item.get('file', '?')}:{item.get('line', '?')}` ({item.get('tool', '?')})")
                lines.append("")

        write_markdown(summary_file, "\n".join(lines))

        print(f"[SwarmReview] Outputs written to {self.output_dir}/")


def main():
    parser = argparse.ArgumentParser(description="SwarmReview — Multi-pass code review pipeline")
    parser.add_argument("--github-repo", help="owner/repo format")
    parser.add_argument("--pr-number", type=int, help="GitHub PR number")
    parser.add_argument("--diff", help="Path to diff/patch file")
    parser.add_argument("--repo", help="Path to local repository")
    parser.add_argument("--profile", default="cautious", choices=["passive", "cautious", "deep"])
    parser.add_argument("--out", default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--token", help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--openclaw", action="store_true", help="Emit OpenClaw schema")
    parser.add_argument("--summary-json", help="OpenClaw summary JSON path")
    parser.add_argument("--artifact-dir", help="Artifact bundle directory")

    args = parser.parse_args()

    if not any([args.github_repo, args.diff, args.repo]):
        parser.error("One of --github-repo, --diff, or --repo is required")

    pipeline = CodeReviewPipeline(
        target_repo=args.github_repo,
        pr_number=args.pr_number,
        diff_path=args.diff,
        local_repo=args.repo,
        profile=args.profile,
        output_dir=args.out,
        github_token=args.token,
        openclaw=args.openclaw,
    )

    result = pipeline.run()
    print(f"[SwarmReview] Complete — {result['total_findings']} findings")

    if args.summary_json:
        write_json(args.summary_json, result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
