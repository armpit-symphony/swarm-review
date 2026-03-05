#!/usr/bin/env python3
"""Unified CLI for bugbounty-swarm workflows."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.auth_policy import default_policy_path, require_auth_policy, validate_policy_schema
from core.disclosure_formatter import write_disclosure_email
from core.finding_schema import normalize_findings, validate_finding
from core.focus import load_focus, require_focus_target
from core.phase_runner import PhaseRunner
from core.scope import ScopeConfig, default_scope_path, require_in_scope
from core.version import get_version_string


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def _default_out_dir() -> str:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return str(Path("artifacts") / run_id)


def _normalize_target(raw: str, scheme: str | None = None) -> str:
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return raw
    host = raw.split("/")[0].split(":")[0].lower()
    chosen = scheme if scheme else ("http" if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} else "https")
    return f"{chosen}://{raw}"


def _consent_target_id(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return host.strip().lower().rstrip(".")


def _consent_file_path(out_dir: str, target: str) -> Path:
    consent_id = _consent_target_id(target)
    if not consent_id:
        consent_id = target
    return Path(out_dir).resolve() / "consent" / f"{_safe_slug(consent_id)}.txt"


def _policy_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_files(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {str(p.resolve()) for p in path.rglob("*") if p.is_file()}


def _activate_run_sandbox(out_dir: str) -> None:
    out = Path(out_dir).resolve()
    os.environ["SWARM_OUTPUT_DIR"] = str(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "screenshots").mkdir(parents=True, exist_ok=True)

    recon_module = importlib.import_module("agents.recon_agent")
    crawl_module = importlib.import_module("agents.crawl_agent")
    xss_module = importlib.import_module("agents.vuln_scanners.xss_scanner")
    sqli_module = importlib.import_module("agents.vuln_scanners.sqli_scanner")
    idor_module = importlib.import_module("agents.vuln_scanners.idor_scanner")
    ssrf_module = importlib.import_module("agents.vuln_scanners.ssrf_scanner")
    auth_module = importlib.import_module("agents.vuln_scanners.auth_scanner")
    tls_module = importlib.import_module("agents.vuln_scanners.tls_scanner")
    headers_module = importlib.import_module("agents.vuln_scanners.headers_scanner")
    cookies_module = importlib.import_module("agents.vuln_scanners.cookies_scanner")

    # Rewire legacy module globals that were set at import-time.
    recon_module.OUTPUT_DIR = str(out)
    crawl_module.OUTPUT_DIR = str(out)
    crawl_module.SCREENSHOT_DIR = str(out / "screenshots")
    xss_module.OUTPUT_DIR = str(out)
    sqli_module.OUTPUT_DIR = str(out)
    idor_module.OUTPUT_DIR = str(out)
    ssrf_module.OUTPUT_DIR = str(out)
    auth_module.OUTPUT_DIR = str(out)
    tls_module.OUTPUT_DIR = str(out)
    headers_module.OUTPUT_DIR = str(out)
    cookies_module.OUTPUT_DIR = str(out)


def _enforce_deep_consent(mode: str, consent_token: str, out_dir: str, target: str) -> None:
    if mode != "deep":
        return
    if not consent_token:
        raise SystemExit("deep mode requires --consent-token")
    consent_file = _consent_file_path(out_dir, target)
    if not consent_file.exists():
        raise SystemExit(f"deep mode requires signed consent file: {consent_file}")
    text = consent_file.read_text(encoding="utf-8")
    if consent_token not in text:
        raise SystemExit(
            f"consent token mismatch: token not found in {consent_file}"
        )


def _best_effort(fn):
    try:
        return fn()
    except Exception:
        return []


def _prepare_schema_findings(findings: list[dict]) -> list[dict]:
    for finding in findings:
        if not finding.get("id") and finding.get("vuln_id"):
            finding["id"] = finding["vuln_id"]
        evidence = finding.get("evidence")
        if not evidence:
            indicators = finding.get("indicators") or []
            if isinstance(indicators, list):
                finding["evidence"] = [str(item) for item in indicators if str(item).strip()]
    normalized = normalize_findings(findings)
    all_errors: list[str] = []
    for idx, item in enumerate(normalized):
        errs = validate_finding(item)
        if errs:
            all_errors.extend([f"finding[{idx}]: {e}" for e in errs])
    if all_errors:
        raise SystemExit("finding schema validation failed:\n" + "\n".join(all_errors))
    return normalized


def _resolve_mode(deep: bool) -> str:
    return "deep" if deep else "exploratory"


def _doctor_error(msg: str) -> int:
    print(f"ERROR: {msg}")
    return 2


def _load_scope_json_strict(scope_path: str) -> dict:
    with open(scope_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("scope.json must be a JSON object with domains/ips keys")
    return data


def _load_policy_strict(policy_path: str) -> dict:
    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise RuntimeError(f"PyYAML not available: {exc}") from exc
    with open(policy_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("policy must be a YAML mapping")
    errors = validate_policy_schema(data)
    if errors:
        raise ValueError("; ".join(errors))
    return data


def run_doctor(
    target: str,
    auth_path: str,
    scope_path: str,
    out_dir: str,
    use_shannon: bool,
    deep: bool,
    consent_token: str,
) -> int:
    mode = _resolve_mode(deep)
    print(get_version_string())
    print(f"Target: {target}")
    print(f"Mode: {mode}")
    print(f"Out Dir: {Path(out_dir).resolve()}")

    # 1) Environment
    py_ver = ".".join(str(v) for v in sys.version_info[:3])
    print(f"Python: {py_ver}")
    if sys.version_info < (3, 8):
        return _doctor_error(f"Python {py_ver} is unsupported; use 3.8+")
    required_imports = [
        "core.auth_policy",
        "core.scope",
        "core.finding_schema",
        "agents.vuln_scanners.xss_scanner",
        "agents.vuln_scanners.sqli_scanner",
        "agents.vuln_scanners.idor_scanner",
        "agents.vuln_scanners.ssrf_scanner",
        "agents.vuln_scanners.auth_scanner",
        "agents.vuln_scanners.tls_scanner",
        "agents.vuln_scanners.headers_scanner",
        "agents.vuln_scanners.cookies_scanner",
    ]
    try:
        for mod in required_imports:
            importlib.import_module(mod)
    except Exception as exc:
        return _doctor_error(f"required import failed: {exc}")
    print("Imports: OK")

    # 2) Paths + permissions
    out = Path(out_dir).resolve()
    try:
        if out.exists() and not out.is_dir():
            return _doctor_error(f"--out path exists but is not a directory: {out}")
        out.mkdir(parents=True, exist_ok=True)
        probe = out / ".doctor_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except Exception as exc:
        return _doctor_error(f"--out is not writable: {out} ({exc})")
    print("Out Dir Writable: OK")

    # 3) Authorization gate (fail-closed)
    auth_resolved = str(Path(auth_path).resolve())
    if not Path(auth_resolved).exists():
        return _doctor_error(f"policy file not found: {auth_resolved}")
    try:
        _load_policy_strict(auth_resolved)
    except Exception as exc:
        return _doctor_error(f"policy validation failed: {exc}")
    auth_sha = _policy_sha256(auth_resolved)
    print(f"Auth Policy: {auth_resolved}")
    print(f"Auth SHA256: {auth_sha}")

    # 4) Scope contract
    scope_resolved = str(Path(scope_path).resolve())
    try:
        _load_scope_json_strict(scope_resolved)
        scope_cfg = ScopeConfig.load(scope_resolved)
        require_in_scope(scope_cfg, target)
    except Exception as exc:
        return _doctor_error(f"scope check failed: {exc}")
    print(f"Scope Path: {scope_resolved}")
    print("Scope Match: OK")

    # 5) Shannon adapter
    if use_shannon:
        shannon_bin = os.getenv("SHANNON_BIN", "").strip()
        if not shannon_bin:
            return _doctor_error("--use-shannon requires SHANNON_BIN environment variable")
        bin_path = Path(shannon_bin).expanduser()
        if not bin_path.exists():
            return _doctor_error(f"SHANNON_BIN not found: {bin_path}")
        if not os.access(str(bin_path), os.X_OK):
            return _doctor_error(f"SHANNON_BIN is not executable: {bin_path}")
        print(f"Shannon: OK ({bin_path})")
    else:
        print("Shannon: not requested")

    # 6) Deep mode consent
    if deep:
        if not consent_token:
            return _doctor_error("--deep requires --consent-token")
        try:
            _enforce_deep_consent("deep", consent_token, str(out), target)
        except SystemExit as exc:
            return _doctor_error(str(exc))
        except Exception as exc:
            return _doctor_error(f"consent check failed: {exc}")
        print(f"Consent: OK ({_consent_file_path(str(out), target)})")
    else:
        print("Consent: not required (exploratory)")

    print("OK: Ready to run scan")
    return 0


def run_scan(
    target: str,
    auth_path: str,
    scope_path: str,
    out_dir: str,
    mode: str,
    consent_token: str,
    use_shannon: bool,
    no_legacy_output: bool,
) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    run_id = out.resolve().name
    _activate_run_sandbox(str(out))
    ReconAgent = importlib.import_module("agents.recon_agent").ReconAgent
    CrawlAgent = importlib.import_module("agents.crawl_agent").CrawlAgent
    TLSScanner = importlib.import_module("agents.vuln_scanners.tls_scanner").TLSScanner
    HeadersScanner = importlib.import_module("agents.vuln_scanners.headers_scanner").HeadersScanner
    CookiesScanner = importlib.import_module("agents.vuln_scanners.cookies_scanner").CookiesScanner
    XSSScanner = importlib.import_module("agents.vuln_scanners.xss_scanner").XSSScanner
    SQLiScanner = importlib.import_module("agents.vuln_scanners.sqli_scanner").SQLiScanner
    IDORScanner = importlib.import_module("agents.vuln_scanners.idor_scanner").IDORScanner
    SSRFScanner = importlib.import_module("agents.vuln_scanners.ssrf_scanner").SSRFScanner
    AuthScanner = importlib.import_module("agents.vuln_scanners.auth_scanner").AuthScanner
    triage_findings = importlib.import_module("agents.triage_agent").triage_findings
    ShannonAdapter = importlib.import_module("agents.adapters.shannon_adapter").ShannonAdapter
    repo_output_dir = Path(__file__).resolve().parent / "output"
    legacy_before = _snapshot_files(repo_output_dir)

    auth_path_resolved = str(Path(auth_path).resolve())
    auth_sha = _policy_sha256(auth_path_resolved)
    require_auth_policy(auth_path_resolved, run_id=run_id)
    scope = ScopeConfig.load(scope_path)
    require_in_scope(scope, target)
    focus = load_focus(str(Path(__file__).resolve().parent / "configs" / "focus.yaml"))
    require_focus_target(focus, target)

    _enforce_deep_consent(mode, consent_token, out_dir, target)

    phase_runner = PhaseRunner()
    phase_runner.events.append(
        {
            "phase": "Authorization gate",
            "status": "ok",
            "started_at": _utc_now(),
            "ended_at": _utc_now(),
            "duration_ms": 0,
            "meta": {"policy_path": auth_path_resolved, "policy_sha256": auth_sha, "run_id": run_id},
        }
    )
    run_state: dict = {
        "run_id": run_id,
        "target": target,
        "target_url": _normalize_target(target),
        "mode": mode,
        "started_at": _utc_now(),
        "phases": {},
        "hypotheses": [],
    }

    def phase_recon() -> dict:
        recon = _best_effort(lambda: ReconAgent(target).run())
        crawl = {}
        try:
            crawl = CrawlAgent(run_state["target_url"], max_pages=20).run()
        except Exception as exc:
            crawl = {"error": str(exc)}
        return {"recon": recon, "crawl": crawl}

    run_state["phases"]["recon"] = phase_runner.run_phase(
        "Recon",
        phase_recon,
        meta={"risk": "low", "description": "asset and surface discovery"},
    )

    crawl_data = run_state["phases"]["recon"].get("crawl", {})
    forms = crawl_data.get("forms", []) if isinstance(crawl_data, dict) else []
    endpoints = crawl_data.get("endpoints", []) if isinstance(crawl_data, dict) else []

    def phase_passive() -> list[dict]:
        findings: list[dict] = []
        findings.extend(_best_effort(lambda: TLSScanner(target).scan()))
        findings.extend(_best_effort(lambda: HeadersScanner(target).scan()))
        findings.extend(_best_effort(lambda: CookiesScanner(target).scan()))
        return findings

    passive_findings = phase_runner.run_phase(
        "Passive checks",
        phase_passive,
        meta={"risk": "low", "description": "TLS, headers, cookies"},
    )
    run_state["phases"]["passive_checks"] = {"findings": len(passive_findings)}

    def phase_hypothesis() -> list[dict]:
        hypotheses: list[dict] = []
        if forms:
            hypotheses.append({"hypothesis": "input_reflection_paths", "reason": f"{len(forms)} forms discovered"})
        if endpoints:
            hypotheses.append({"hypothesis": "parameter_manipulation_paths", "reason": f"{len(endpoints)} endpoints discovered"})
        if any((f.get("severity") or "").upper() in {"HIGH", "CRITICAL"} for f in passive_findings):
            hypotheses.append({"hypothesis": "transport_layer_hardening_gap", "reason": "high-risk passive finding present"})
        return hypotheses

    run_state["hypotheses"] = phase_runner.run_phase(
        "Hypothesis generation",
        phase_hypothesis,
        meta={"risk": "low", "description": "reasoning over surfaced attack paths"},
    )

    validation_findings: list[dict] = []
    if mode == "deep":
        def phase_validation() -> list[dict]:
            findings: list[dict] = []
            findings.extend(_best_effort(lambda: XSSScanner(target, forms, endpoints).scan()))
            findings.extend(_best_effort(lambda: SQLiScanner(target, forms, endpoints).scan()))
            findings.extend(_best_effort(lambda: IDORScanner(target).scan()))
            findings.extend(_best_effort(lambda: SSRFScanner(target, endpoints).scan()))
            findings.extend(_best_effort(lambda: AuthScanner(target).scan()))
            if use_shannon:
                findings.extend(_best_effort(lambda: ShannonAdapter().run(target, out_dir)))
            return findings

        validation_findings = phase_runner.run_phase(
            "Validation",
            phase_validation,
            meta={"risk": "consented", "description": "non-destructive validation checks"},
        )
    else:
        phase_runner.events.append(
            {
                "phase": "Validation",
                "status": "skipped",
                "started_at": _utc_now(),
                "ended_at": _utc_now(),
                "duration_ms": 0,
                "meta": {"reason": "exploratory mode (default safe checks only)"},
            }
        )

    triaged = triage_findings(passive_findings + validation_findings)
    schema_findings = _prepare_schema_findings(triaged)

    def phase_disclosure() -> str:
        email_path = out / "disclosure_email.md"
        write_disclosure_email(
            str(email_path),
            target,
            triaged,
            run_id=run_id,
            generated_at=_utc_now(),
        )
        return str(email_path)

    disclosure_email_path = phase_runner.run_phase(
        "Disclosure draft",
        phase_disclosure,
        meta={"risk": "none", "description": "draft generation for human review"},
    )

    findings_path = out / "findings.json"
    findings_path.write_text(json.dumps(schema_findings, indent=2), encoding="utf-8")
    run_log_path = out / "run.log"
    phase_runner.write_jsonl(str(run_log_path))
    legacy_after = _snapshot_files(repo_output_dir)
    new_legacy = sorted(legacy_after - legacy_before)
    if new_legacy:
        message = (
            "legacy output writes detected outside --out:\n"
            + "\n".join(new_legacy[:20])
        )
        if no_legacy_output:
            raise SystemExit(message)
        print(f"WARNING: {message}")

    summary = {
        "run_id": run_id,
        "target": target,
        "target_url": run_state["target_url"],
        "mode": mode,
        "started_at": run_state["started_at"],
        "finished_at": _utc_now(),
        "findings_total": len(schema_findings),
        "paths": {
            "findings_json": str(findings_path),
            "disclosure_email": disclosure_email_path,
            "run_log": str(run_log_path),
        },
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bugbounty-swarm", description="Bug bounty swarm CLI")
    parser.add_argument("--version", action="store_true", help="Print bugbounty-swarm version and exit")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Run scan + disclosure draft workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"{get_version_string()}\n\n"
            "Examples:\n"
            "  bugbounty-swarm scan --target example.com --auth ./policy.yml --scope ./configs/scope.json\n"
            "  RUN=./artifacts/20260303_150000 && mkdir -p \"$RUN/consent\" && \\\n"
            "    printf \"TOKEN: abc123\\n\" > \"$RUN/consent/example.com.txt\" && \\\n"
            "    bugbounty-swarm scan --target example.com --auth ./policy.yml --scope ./configs/scope.json \\\n"
            "      --mode deep --consent-token abc123 --out \"$RUN\""
        ),
    )
    scan.add_argument("--target", required=True, help="Target URL or host")
    scan.add_argument("--auth", default=default_policy_path(), help="Path to auth policy YAML (must authorize target/actions)")
    scan.add_argument("--scope", default=default_scope_path(), help="Path to scope JSON allowlist (target must match)")
    scan.add_argument("--out", default=_default_out_dir(), help="Run output directory (default: ./artifacts/<run_id>/)")
    scan.add_argument("--mode", default="exploratory", choices=["exploratory", "deep"], help="Default exploratory (safe passive checks only).")
    scan.add_argument("--consent-token", default="", help="Required for deep mode; must match token in --out/consent/<target>.txt")
    scan.add_argument("--use-shannon", action="store_true", help="Use external Shannon adapter when SHANNON_BIN is set")
    scan.add_argument(
        "--no-legacy-output",
        dest="no_legacy_output",
        action="store_true",
        default=True,
        help="Fail if any artifact is written outside --out (default).",
    )
    scan.add_argument(
        "--legacy-output",
        dest="no_legacy_output",
        action="store_false",
        help="Allow legacy writes outside --out, but print a warning.",
    )

    doctor = sub.add_parser(
        "doctor",
        help="Run zero-risk local preflight checks (no network scanning)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"{get_version_string()}\n\n"
            "Examples:\n"
            "  bugbounty-swarm doctor --target example.com --auth ./policy.yml --scope ./configs/scope.json --out ./artifacts/preflight\n"
            "  bugbounty-swarm doctor --target example.com --auth ./policy.yml --scope ./configs/scope.json --out ./artifacts/preflight --deep --consent-token abc123\n"
        ),
    )
    doctor.add_argument("--target", required=True, help="Target URL or host")
    doctor.add_argument("--auth", default=default_policy_path(), help="Path to auth policy YAML")
    doctor.add_argument("--scope", default=default_scope_path(), help="Path to scope JSON allowlist")
    doctor.add_argument("--out", default=_default_out_dir(), help="Preflight output directory")
    doctor.add_argument("--use-shannon", action="store_true", help="Validate SHANNON_BIN executable when set")
    doctor.add_argument("--deep", action="store_true", help="Validate deep-mode consent gate")
    doctor.add_argument("--consent-token", default="", help="Required when --deep is used")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.version:
        print(get_version_string())
        return 0
    if args.command == "scan":
        summary = run_scan(
            target=args.target,
            auth_path=args.auth,
            scope_path=args.scope,
            out_dir=args.out,
            mode=args.mode,
            consent_token=args.consent_token,
            use_shannon=args.use_shannon,
            no_legacy_output=args.no_legacy_output,
        )
        print(json.dumps(summary, indent=2))
        return 0
    if args.command == "doctor":
        return run_doctor(
            target=args.target,
            auth_path=args.auth,
            scope_path=args.scope,
            out_dir=args.out,
            use_shannon=args.use_shannon,
            deep=args.deep,
            consent_token=args.consent_token,
        )
    print("ERROR: missing command. Use --help.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
