"""Version helpers for swarm-review CLI."""

from __future__ import annotations

import subprocess
from pathlib import Path

__version__ = "1.0.0"  # SwarmReview 1.0 — rebrand from bugbounty-swarm 0.4


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
    return f"swarm-review v{__version__} (commit {get_commit_short()}) — formerly bugbounty-swarm"
