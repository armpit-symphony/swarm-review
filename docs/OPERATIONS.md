# SwarmReview Operations

This file is the canonical operations record for:
- work orders and change log entries
- operator runbook and safe defaults
- safety and consent policy
- validation checklist and execution proof

It consolidates content previously split across:
- `LOGBOOK.md`
- `OPERATOR_SHEET.md`
- `OPERATOR_SAFETY.md`
- `VALIDATION_CHECKLIST.md`
- `docs/OPERATOR_SAFETY_AND_CONSENT.md`

## Operator Quickstart

1. Set scope in `configs/scope.json`.
2. Run swarm + vuln:

```bash
python3 swarm_orchestrator.py example.com \
  --profile cautious \
  --run-vuln \
  --authorized \
  --openclaw \
  --schema-repair \
  --summary-json output/openclaw_summary.json \
  --artifact-dir output/artifacts
```

3. Build dashboard:

```bash
python3 scripts/build_dashboard.py
```

Safe defaults:
- profile: `cautious`
- evidence: `standard` (`configs/budget.yaml`)
- focus: disabled unless `configs/focus.yaml` is enabled

OpenClaw output:
- `output/openclaw_summary.json`
- `output/openclaw_schema_report.json`
- `output/artifacts/` (reports + evidence bundle)

Evidence bundle:

```bash
python3 scripts/package_evidence.py --output-dir output
```

Dry run (no network):

```bash
python3 swarm_orchestrator.py example.com --dry-run
python3 vuln_scanner_orchestrator.py https://example.com --dry-run
```

Focus rotation:

```bash
python3 scripts/rotate_focus.py --targets "example.com,example.org" --days 56 --enable
```

Cron example:

```cron
0 3 * * * /usr/bin/python3 /home/sparky/bugbounty-swarm/scripts/run_focus.py >> /home/sparky/bugbounty-swarm/output/cron.log 2>&1
```

## Safety And Consent Policy

Purpose: This tool is for authorized exploratory research and responsible disclosure drafting. Operate legally, safely, and with minimal harm.

1. Authorization required (fail closed)
- Run only against authorized targets in `policy.yml` (or equivalent policy).
- If authorization policy is missing/invalid, stop execution.
- Operator must ensure scope boundaries (domain/path/time/method).

2. Two modes only
- Exploratory mode (default):
  - allowed: TLS posture checks, security headers checks, cookie attribute checks, passive fingerprinting
  - disallowed: exfiltration payloads, auth bypass, brute force, DoS/load testing, destructive actions
- Deep dive mode (consent-gated):
  - requires explicit written permission
  - requires `artifacts/consent/<target>.txt` with target, consenting party, allowed techniques/time window, permission statement, and date
  - requires runtime token gate (`--consent-token`)

3. Safety controls
- Prefer read-only checks first.
- Respect rate limits and avoid peak windows if requested.
- Stop immediately on user-impact signals (5xx spikes, latency spikes, lockouts).
- Never hardcode secrets.
- Log each run with timestamp, policy hash, target, mode, and major actions.

4. Evidence standard (no proof, no report)
- High/critical claims require at least one evidence source:
  - redacted request/response excerpt
  - header/cert evidence
  - exact repro steps
  - tool output reference with timestamps
  - screenshot/artifact references
- Insufficient evidence must be marked unconfirmed or downgraded.

5. Responsible disclosure rule
- Human review is required before sending disclosure drafts.
- Do not include sensitive data.
- Include practical remediation guidance.
- Follow the target program timeline (for example, 90 days where applicable).

6. Operator accountability
- Operator is responsible for legal authorization, consent-scope adherence, minimizing harm, and law/program compliance.

## Validation Checklist (Current)

Mission: Validate `armpit-symphony/bugbounty-swarm` end-to-end in a safe, authorized way.

Proof of execution:
- Fix 1: safe scheme handling
  - `normalize_target()` implemented
  - localhost auto-HTTP, non-localhost default HTTPS
  - `--scheme http|https` and `--force-http` added
- Fix 2: graceful error handling
  - crawl failures no longer crash orchestrator
  - errors captured and reports still generated
- Fix 3: `--dry-run` mode
  - validates config without network
  - writes dry-run artifact
  - checks output directory permissions

Test results:
- Dry run localhost: pass
- Dry run example.com: pass
- Full run (Juice Shop 127.0.0.1:3000): completed with errors, artifacts generated

Acceptance criteria:
- localhost target avoids SSL mismatch: pass
- crawl failures avoid orchestrator crash: pass
- `--dry-run` creates artifact: pass

Remaining issue:
- CrawlAgent filename sanitization for `:` in URLs still needs hardening.

## Work Orders And Logbook

Append newest entries at the top. Entry format:
- date
- work-order ref
- worker
- changes
- verification commands

---

### 2026-03-03 | WO-03032026-02.1 | Kojak

Work Order: `03032026-02.1`  
Agent: Kojak (SparkPit Labs)  
Status: Completed

Changes:
- Added `doctor` preflight command in `bugbounty_swarm_cli.py`
  - fail-fast local validation (environment, imports, writable out, auth policy, scope, optional Shannon, optional deep consent)
  - exits `0` when ready, `2` on configuration error
  - prints policy SHA256 and operator summary lines
- Added single-source versioning:
  - `core/version.py` defines `__version__`
  - `./bugbounty-swarm --version` prints `bugbounty-swarm vX.Y.Z (commit <shortsha|unknown>)`
- Refactored CLI for minimal doctor-side imports and lazy scan imports.
- Added tests in `tests/test_doctor_cli.py` (including no-network regression coverage).
- Updated README with Doctor and Versioning sections.

Verification:

```bash
cd /home/sparky/bugbounty-swarm
python3 -B -m pytest -q -p no:cacheprovider tests/
./bugbounty-swarm doctor --target example.com --auth ./policy.yml --scope /tmp/bbsmoke/scope.json --out /tmp/bbsmoke/doctor_run
./bugbounty-swarm --version
```

### 2026-03-03 | WO-03032026-02 | Kojak

Work Order: `03032026-02`  
Agent: Kojak (SparkPit Labs)  
Status: Completed

Changes:
- Project 1 pipeline + report integrity:
  - added phase execution/event logging in `core/phase_runner.py`
  - enforced "No Proof, No Report" in `agents/triage_agent.py`
  - added rubric scoring in `core/disclosure_formatter.py`
- Optional Shannon external adapter:
  - added `agents/adapters/shannon_adapter.py`
  - only runs if `SHANNON_BIN` is present
  - ingests external output into local schema
- Project 2 market readiness UX:
  - added finding schema helpers in `core/finding_schema.py`
  - added unified CLI (`bugbounty_swarm_cli.py` and `./bugbounty-swarm`)
  - added consent gates for deep mode
  - updated README quickstart and consent workflow
- Post-review hardening:
  - forced legacy module outputs into `--out` sandbox
  - added `--no-legacy-output` default and `--legacy-output` opt-out
  - added strict detection for writes outside `--out`
  - moved deep consent artifact path to `<out>/consent/<target>.txt`
  - added auth gate audit event to `run.log`
  - improved disclosure draft structure/redaction
  - added contract tests in `tests/test_scan_contract.py`

Verification:

```bash
cd /home/sparky/bugbounty-swarm
python3 -B -m pytest -q -p no:cacheprovider tests/test_finding_schema.py tests/test_phase_runner.py tests/test_auth_policy.py tests/test_playbook_loader.py
python3 -B -m pytest -q -p no:cacheprovider tests/test_scan_contract.py
python3 -B bugbounty-swarm scan --help
./bugbounty-swarm scan --target example.com --auth ./policy.yml --scope /tmp/bbsmoke/scope.json --out /tmp/bbsmoke/run4
```

Still blocked:
- deep-mode smoke needs explicit consent token + consent file
- Shannon adapter smoke depends on user-provided Shannon binary/output

### 2026-03-03 | WO-03032026-01 | Cobra Commander

Work Order: `03032026-01`  
Agent: Cobra Commander (SparkPit Labs)  
Status: Completed

Changes:
- Project 1 Shannon integration:
  - added vuln ID scheme `[TYPE]-VULN-NNNN` in `agents/triage_agent.py`
  - added `core/disclosure_formatter.py` for disclosure draft output
- Project 2 TLS/Headers/Cookies modules:
  - added scanners:
    - `agents/vuln_scanners/tls_scanner.py`
    - `agents/vuln_scanners/headers_scanner.py`
    - `agents/vuln_scanners/cookies_scanner.py`
  - added playbooks:
    - `playbooks/tls.yaml`
    - `playbooks/headers.yaml`
    - `playbooks/cookies.yaml`
  - updated `vuln_scanner_orchestrator.py` scanner list

Verification:

```bash
cd /home/sparky/bugbounty-swarm
python3 vuln_scanner_orchestrator.py --target example.com --dry-run
python3 -c "from agents.vuln_scanners.tls_scanner import TLSScanner; print('TLS OK')"
python3 -c "from agents.vuln_scanners.headers_scanner import HeadersScanner; print('Headers OK')"
python3 -c "from agents.vuln_scanners.cookies_scanner import CookiesScanner; print('Cookies OK')"
python3 -c "from core.disclosure_formatter import format_disclosure_email; print('Formatter OK')"
```

Still blocked:
- disclosure formatter needs triaged live findings for realistic output
- TLS cert expiry checks depend on valid TLS endpoints
- external browser-based exploit PoC engine is not integrated

---

Logbook created on `2026-03-03`. Prior session history exists in `sparkpitlabs_handoff.md`.
