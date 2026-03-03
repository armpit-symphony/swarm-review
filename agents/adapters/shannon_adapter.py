"""Optional Shannon external adapter.

This adapter does not bundle Shannon code. It only runs a user-installed binary
when SHANNON_BIN is set and parses JSON output into the local finding shape.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


class ShannonAdapter:
    def __init__(self, shannon_bin: str | None = None) -> None:
        self.shannon_bin = shannon_bin or os.getenv("SHANNON_BIN", "")

    def enabled(self) -> bool:
        return bool(self.shannon_bin)

    def run(self, target: str, output_dir: str) -> list[dict]:
        if not self.enabled():
            return []
        cmd = [self.shannon_bin, "--target", target, "--output", str(Path(output_dir) / "shannon.json")]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return []
        out_file = Path(output_dir) / "shannon.json"
        if not out_file.exists():
            return []
        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception:
            return []
        return _to_local_findings(raw)


def _to_local_findings(raw: dict) -> list[dict]:
    findings: list[dict] = []
    items = raw.get("findings") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return findings
    for item in items:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "type": str(item.get("type") or "MISC").upper(),
                "severity": str(item.get("severity") or "MEDIUM").upper(),
                "issue": str(item.get("title") or item.get("issue") or "external_finding"),
                "detail": str(item.get("description") or "Imported external finding."),
                "url": item.get("url") or "",
                "evidence": item.get("evidence") or [],
                "remediation": item.get("remediation") or "Review and remediate.",
                "source": "shannon_external_adapter",
            }
        )
    return findings
