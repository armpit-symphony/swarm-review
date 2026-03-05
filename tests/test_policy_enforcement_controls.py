"""Regression tests for capability and consent enforcement controls."""

import sys
from pathlib import Path

import pytest

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from bugbounty_swarm_cli import _consent_file_path
from core.focus import require_focus_target
from core.scope import ScopeConfig, require_in_scope


def test_consent_file_path_uses_host_only_for_urls(tmp_path):
    out_dir = tmp_path / "run_001"
    p = _consent_file_path(str(out_dir), "https://Example.COM:443/path?q=1")
    assert p.name == "example.com.txt"
    assert p.parent == out_dir.resolve() / "consent"


def test_consent_file_path_stays_under_consent_dir(tmp_path):
    out_dir = tmp_path / "run_002"
    p = _consent_file_path(str(out_dir), "../../etc/passwd")
    consent_root = (out_dir.resolve() / "consent").as_posix()
    assert p.resolve().as_posix().startswith(consent_root)
    assert ".." not in p.name


def test_require_in_scope_allows_exact_and_subdomain():
    scope = ScopeConfig(domains=["example.com"], ips=[], notes="")
    require_in_scope(scope, "example.com")
    require_in_scope(scope, "api.example.com")
    require_in_scope(scope, "https://portal.example.com/login")


def test_require_in_scope_blocks_out_of_scope():
    scope = ScopeConfig(domains=["example.com"], ips=["127.0.0.1"], notes="")
    with pytest.raises(ValueError):
        require_in_scope(scope, "evil.com")
    with pytest.raises(ValueError):
        require_in_scope(scope, "api.evil-example.com")
    with pytest.raises(ValueError):
        require_in_scope(scope, "10.10.10.10")


def test_require_focus_target_blocks_non_focus_target():
    focus = {
        "enabled": True,
        "mode": "single",
        "target": "example.com",
        "rotate_targets": [],
        "rotate_start": "",
    }
    require_focus_target(focus, "example.com")
    with pytest.raises(ValueError):
        require_focus_target(focus, "api.example.com")
