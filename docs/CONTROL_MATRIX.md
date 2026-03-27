# SwarmReview Control Matrix

This matrix documents current enforcement controls for authorization, scope, consent, and evidence discipline.

## Control Matrix

| Control ID | Control | Enforcement Point | Failure Behavior | Evidence Artifact |
|---|---|---|---|---|
| C-001 | Authorization policy required (fail-closed) | `core/auth_policy.py::require_auth_policy` and CLI `scan`/`doctor` | Exit non-zero on missing/invalid policy | `run.log` auth gate event + policy SHA |
| C-002 | Policy schema validation | `core/auth_policy.py::validate_policy_schema` | Exit non-zero on schema errors | test coverage in `tests/test_auth_policy.py` |
| C-003 | Scope allowlist required | `core/scope.py::require_in_scope` in `scan`/`doctor` | Raise error; run aborted | CLI error + tests |
| C-004 | Focus mode target lock (when enabled) | `core/focus.py::require_focus_target` in `scan` | Raise error; run aborted | CLI error + tests |
| C-005 | Deep mode consent token required | `bugbounty_swarm_cli.py::_enforce_deep_consent` | Exit non-zero if token missing | test coverage in `tests/test_scan_contract.py` |
| C-006 | Deep mode signed consent file required | `bugbounty_swarm_cli.py::_enforce_deep_consent` | Exit non-zero if file missing/mismatch | test coverage in `tests/test_scan_contract.py` |
| C-007 | Consent file path constrained to run output tree | `bugbounty_swarm_cli.py::_consent_file_path` | Path anchored under `<out>/consent` | tests in `tests/test_policy_enforcement_controls.py` |
| C-008 | Legacy output write detection | `bugbounty_swarm_cli.py::run_scan` | Exit non-zero by default (`--no-legacy-output`) | `summary.json`/CLI failure message |
| C-009 | No-proof-no-report severity discipline | `agents/triage_agent.py` | Unverified high/critical downgraded | `findings.json` + disclosure sections |
| C-010 | Schema-valid finding output contract | `bugbounty_swarm_cli.py::_prepare_schema_findings` | Exit non-zero on schema violations | `tests/test_scan_contract.py` |

## Step 3 Additions

- Added consent target canonicalization (host-only) for consent file resolution.
- Added regression tests for:
  - consent file path normalization and path anchoring
  - scope in/out behavior for exact domain, subdomain, URL host extraction, and out-of-scope targets
  - focus-target enforcement in single-target mode
