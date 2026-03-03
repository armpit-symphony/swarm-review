"""CLI tests for doctor preflight and --version."""

from __future__ import annotations

import os
import re
import socket
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import requests

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from bugbounty_swarm_cli import run_doctor

CLI = [sys.executable, "./bugbounty-swarm"]


def _run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        CLI + args,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        env=merged_env,
        check=False,
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def _valid_policy(path: Path) -> Path:
    return _write(
        path,
        """
        version: "1"
        allow:
          targets:
            - example.com
          actions:
            - recon
            - crawl
            - vuln_scan
        """,
    )


def _valid_scope(path: Path) -> Path:
    return _write(path, '{ "domains": ["example.com"], "ips": [], "notes": "test" }')


def test_doctor_valid_config_exit_0(tmp_path):
    policy = _valid_policy(tmp_path / "policy.yml")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_ok"
    proc = _run(
        [
            "doctor",
            "--target",
            "example.com",
            "--auth",
            str(policy),
            "--scope",
            str(scope),
            "--out",
            str(out),
        ]
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: Ready to run scan" in proc.stdout


def test_doctor_missing_policy_exit_2(tmp_path):
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_missing_policy"
    proc = _run(
        [
            "doctor",
            "--target",
            "example.com",
            "--auth",
            str(tmp_path / "missing.yml"),
            "--scope",
            str(scope),
            "--out",
            str(out),
        ]
    )
    assert proc.returncode == 2
    assert "ERROR:" in proc.stdout


def test_doctor_invalid_policy_exit_2(tmp_path):
    policy = _write(tmp_path / "policy.yml", "version: [\nnope::")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_invalid_policy"
    proc = _run(
        [
            "doctor",
            "--target",
            "example.com",
            "--auth",
            str(policy),
            "--scope",
            str(scope),
            "--out",
            str(out),
        ]
    )
    assert proc.returncode == 2
    assert "policy validation failed" in proc.stdout


def test_doctor_out_not_writable_exit_2(tmp_path):
    policy = _valid_policy(tmp_path / "policy.yml")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "readonly"
    out.mkdir()
    out.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        proc = _run(
            [
                "doctor",
                "--target",
                "example.com",
                "--auth",
                str(policy),
                "--scope",
                str(scope),
                "--out",
                str(out),
            ]
        )
    finally:
        out.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    assert proc.returncode == 2
    assert "--out is not writable" in proc.stdout


def test_doctor_deep_missing_token_exit_2(tmp_path):
    policy = _valid_policy(tmp_path / "policy.yml")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_deep_missing_token"
    proc = _run(
        [
            "doctor",
            "--target",
            "example.com",
            "--auth",
            str(policy),
            "--scope",
            str(scope),
            "--out",
            str(out),
            "--deep",
        ]
    )
    assert proc.returncode == 2
    assert "--deep requires --consent-token" in proc.stdout


def test_doctor_deep_token_mismatch_exit_2(tmp_path):
    policy = _valid_policy(tmp_path / "policy.yml")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_deep_bad_token"
    consent = out / "consent" / "example.com.txt"
    consent.parent.mkdir(parents=True)
    consent.write_text("TOKEN: right-token\n", encoding="utf-8")
    proc = _run(
        [
            "doctor",
            "--target",
            "example.com",
            "--auth",
            str(policy),
            "--scope",
            str(scope),
            "--out",
            str(out),
            "--deep",
            "--consent-token",
            "wrong-token",
        ]
    )
    assert proc.returncode == 2
    assert "consent token mismatch" in proc.stdout


def test_doctor_use_shannon_without_env_exit_2(tmp_path):
    policy = _valid_policy(tmp_path / "policy.yml")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_shannon_missing"
    env = os.environ.copy()
    env.pop("SHANNON_BIN", None)
    proc = _run(
        [
            "doctor",
            "--target",
            "example.com",
            "--auth",
            str(policy),
            "--scope",
            str(scope),
            "--out",
            str(out),
            "--use-shannon",
        ],
        env=env,
    )
    assert proc.returncode == 2
    assert "--use-shannon requires SHANNON_BIN" in proc.stdout


def test_doctor_no_network_regression(monkeypatch, tmp_path):
    policy = _valid_policy(tmp_path / "policy.yml")
    scope = _valid_scope(tmp_path / "scope.json")
    out = tmp_path / "doctor_no_network"

    def fail_connect(*args, **kwargs):
        raise AssertionError("network call attempted via socket.connect")

    def fail_request(*args, **kwargs):
        raise AssertionError("network call attempted via requests")

    monkeypatch.setattr(socket.socket, "connect", fail_connect, raising=True)
    monkeypatch.setattr(requests.sessions.Session, "request", fail_request, raising=True)

    code = run_doctor(
        target="example.com",
        auth_path=str(policy),
        scope_path=str(scope),
        out_dir=str(out),
        use_shannon=False,
        deep=False,
        consent_token="",
    )
    assert code == 0


def test_version_output_semver():
    proc = _run(["--version"])
    assert proc.returncode == 0
    text = proc.stdout.strip()
    assert re.match(r"^bugbounty-swarm v\d+\.\d+\.\d+ \(commit (?:[a-f0-9]+|unknown)\)$", text)
