"""Version helpers for bugbounty-swarm CLI."""

from __future__ import annotations

import subprocess
from pathlib import Path

__version__ = "0.4.0"


def get_commit_short() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    sha = (proc.stdout or "").strip()
    return sha or "unknown"


def get_version_string() -> str:
    return f"bugbounty-swarm v{__version__} (commit {get_commit_short()})"
