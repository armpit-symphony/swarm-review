# 🐞 Bug Bounty Swarm

<p align="center">
  <img src="https://img.shields.io/badge/Bug%20Bounty-Autonomous%20Agents-blue" alt="Bug Bounty Swarm">
  <img src="https://img.shields.io/badge/Python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-orange" alt="License">
</p>

> Autonomous agent swarm for bug bounty reconnaissance and vulnerability hunting. Built for security researchers, by autonomous agents.

## 🚀 Features

### Reconnaissance
- **DNS Enumeration** - A records, MX, TXT, WHOIS
- **Subdomain Discovery** - CRT.sh, certificate enumeration
- **Port Scanning** - Service detection
- **Shodan/Censys Integration** - Paid APIs supported

### Web Crawling
- **Deep Crawling** - Recursive page discovery
- **Screenshot Capture** - Visual evidence with Puppeteer
- **Form Discovery** - Input extraction for testing
- **JavaScript Analysis** - Endpoint extraction from JS files

### Vulnerability Scanning
- **XSS Scanner** - Reflected, Stored, DOM-based
- **SQL Injection** - Error-based, Union-based
- **IDOR** - Object reference testing
- **SSRF** - Server-side request forgery
- **Authentication** - Login, password reset, sessions

### Enrichment
- **CVE Lookup** - Free cve.circl.lu
- **VirusTotal** - Paid API integration
- **Technology Detection** - Framework fingerprinting

## 📁 Architecture

```
bugbounty-swarm/
├── agents/
│   ├── recon_agent.py           # Domain & network recon
│   ├── crawl_agent.py           # Web crawling & screenshots
│   ├── enrichment_agent.py      # CVE & VT enrichment
│   └── vuln_scanners/
│       ├── xss_scanner.py       # Cross-Site Scripting
│       ├── sqli_scanner.py      # SQL Injection
│       ├── idor_scanner.py      # Insecure Direct Object Reference
│       ├── ssrf_scanner.py      # Server-Side Request Forgery
│       └── auth_scanner.py      # Authentication issues
├── scripts/
│   ├── api_detector.py          # Auto-detect free/paid APIs
│   └── setup_mcp.sh             # MCP server setup
├── configs/
│   └── swarm.conf               # Configuration
├── swarm_orchestrator.py         # Main recon + crawl runner
└── vuln_scanner_orchestrator.py # Vulnerability scanner runner
```

## 🔧 Quick Start

### Basic Usage

```bash
# Clone the repository
git clone https://github.com/armpit-symphony/bugbounty-swarm.git
cd bugbounty-swarm

# Run full reconnaissance + crawl
python3 swarm_orchestrator.py example.com

# Run vulnerability scanners
python3 vuln_scanner_orchestrator.py https://example.com
```

### Operator Quickstart (Scan + Draft)

Authorized targets only. The workflow is:
authorized exploration -> structured findings -> draft disclosure -> human review/send -> consented deep dive.

```bash
cd /home/sparky/bugbounty-swarm

# Exploratory mode (default; safe checks only)
./bugbounty-swarm scan \
  --target example.com \
  --auth ./policy.yml \
  --scope ./configs/scope.json \
  --out ./artifacts/$(date -u +%Y%m%d_%H%M%S)
```

Outputs in `--out`:
- `findings.json` (stable finding schema)
- `disclosure_email.md` (draft only; human must review before sending)
- `run.log` (phase start/stop events + durations)
- default behavior enforces `--no-legacy-output` (fails if anything writes outside `--out`)

### Consent Gate For Deep Dive

Deep mode requires both:
1. `--consent-token <token>`
2. Signed consent file at `<out>/consent/<target>.txt` containing that token

```bash
RUN_DIR=./artifacts/$(date -u +%Y%m%d_%H%M%S)
mkdir -p "$RUN_DIR/consent"
printf "Authorized deep testing for example.com\nTOKEN: abc123\n" > "$RUN_DIR/consent/example.com.txt"

./bugbounty-swarm scan \
  --target example.com \
  --auth ./policy.yml \
  --scope ./configs/scope.json \
  --mode deep \
  --consent-token abc123 \
  --out "$RUN_DIR"
```

Optional external adapter (off by default):

```bash
export SHANNON_BIN=/path/to/shannon
./bugbounty-swarm scan --target example.com --auth ./policy.yml --scope ./configs/scope.json --use-shannon
```

### Doctor (Preflight)

Run local preflight validation before scanning. `doctor` does not run vulnerability probes and should not perform network scanning.

```bash
./bugbounty-swarm doctor \
  --target example.com \
  --auth ./policy.yml \
  --scope ./configs/scope.json \
  --out ./artifacts/preflight
```

Deep-mode preflight:

```bash
RUN_DIR=./artifacts/preflight_deep
mkdir -p "$RUN_DIR/consent"
printf "TOKEN: abc123\n" > "$RUN_DIR/consent/example.com.txt"

./bugbounty-swarm doctor \
  --target example.com \
  --auth ./policy.yml \
  --scope ./configs/scope.json \
  --out "$RUN_DIR" \
  --deep \
  --consent-token abc123
```

Exit codes:
- `0`: ready to run `scan`
- `2`: configuration error (actionable message printed)

### Versioning

```bash
./bugbounty-swarm --version
```

Output format:
- `bugbounty-swarm vX.Y.Z (commit <shortsha|unknown>)`

### API Configuration

The swarm works **free by default**. Set API keys to enable enhanced features:

```bash
# Paid APIs (optional)
export SHODAN_API_KEY=your_key
export CENSYS_API_KEY=your_key
export CENSYS_API_SECRET=your_secret
export VIRUSTOTAL_API_KEY=your_key
export GITHUB_TOKEN=your_token

# Check what's enabled
python3 scripts/api_detector.py
```

| API | Free Alternative | Paid Benefit |
|-----|------------------|--------------|
| Shodan | Native DNS | Full subnet data |
| Censys | CRT.sh | Certificate search |
| VirusTotal | cve.circl.lu | IP/domain reputation |
| GitHub | Public API | Rate limits |

## 🎯 Usage Examples

### Full Bug Bounty Workflow

```bash
# 1. Recon + Crawl
python3 swarm_orchestrator.py target.com

# 2. Vulnerability Scanning
python3 vuln_scanner_orchestrator.py https://target.com

# 3. Check output/
ls -la output/
```

### Individual Agents

```bash
# Just recon
python3 agents/recon_agent.py target.com

# Just crawl
python3 agents/crawl_agent.py target.com

# Just XSS scan
python3 agents/vuln_scanners/xss_scanner.py https://target.com
```

## 📊 Output

Results are saved to `output/`:

| File | Description |
|------|-------------|
| `recon_*.json` | DNS, WHOIS, subdomains |
| `crawl_*.json` | Pages, forms, screenshots |
| `vuln_scan_*.json` | All vulnerabilities found |
| `swarm_report_*.md` | Human-readable summary |
| `*_*.html` | Professional HTML report |

## ✅ Profiles

Run modes are defined in `configs/profiles.yaml` and default to `cautious`.

- `passive`: Recon + crawl only
- `cautious`: Recon + crawl + gated active tests
- `active`: Deeper scans (authorized only)

## 🔒 Authorization Gate

The swarm **fails closed** — it will not execute unless a valid auth policy YAML loads successfully.

### Default policy path

`policy.yml` in the repo root.  Edit it before running:

```yaml
version: "1"
allow:
  targets:
    - target.com          # domains you are explicitly authorized to test
  actions:
    - recon
    - crawl
    - enrichment
    - vuln_scan
```

### CLI flags

```bash
# Use default ./policy.yml (auto-enforced)
python3 swarm_orchestrator.py target.com

# Specify a different policy file
python3 swarm_orchestrator.py target.com --auth /path/to/policy.yml

# Bypass (prints big warning — not recommended)
python3 swarm_orchestrator.py target.com --no-require-auth
```

### Audit log

Every successful policy load prints to stdout:

```
AUTHZ_ENFORCED run_id=<uuid> policy_sha256=<sha256> policy_path=<path>
```

Set `SWARM_AUTH_LOG=/path/to/auth.log` to also append the event to a file.

### Failure cases (all exit nonzero)

| Condition | Exit |
|-----------|------|
| Policy file missing | 1 |
| YAML parse error | 1 |
| Schema invalid (missing version/allow/targets/actions) | 1 |
| Empty allow.targets or allow.actions | 1 |

## 🔐 Scope

Targets must be added to `configs/scope.json` before running.

```
{
  "domains": ["example.com"],
  "ips": [],
  "notes": "Authorized targets only"
}
```

## 🧪 Validation

Run the validation harness on a scan report:

```bash
python3 -m core.harness.validate output/vuln_scan_example_com_YYYYMMDD_HHMMSS.json
```

Package evidence:

```bash
python3 scripts/package_evidence.py --output-dir output
```

## 🧾 Evidence Level

Set evidence verbosity in `configs/budget.yaml`:

```
evidence_level: lite | standard | full
```

## 🎯 Focus Mode

Enable target focus in `configs/focus.yaml` to lock the swarm to a single target:

```
enabled: true
target: "example.com"
days: 56
mode: single | rotate
rotate_targets:
  - example.com
  - example.org
rotate_start: "2026-02-01T00:00:00Z"
```

## 🧭 OpenClaw Schema

Schema definition lives in `configs/openclaw_schema.json`.

## ⏱️ Rate Limits

Configure request budgets in `configs/budget.yaml`:

```
requests:
  max_per_minute: 120
  max_per_run: 1000
```

## 🔁 Focus Rotation

Configure rotation quickly:

```bash
python3 scripts/rotate_focus.py --targets "example.com,example.org" --days 56 --enable
```

## ⏲️ Cron Example

Run every day at 3am UTC:

```
0 3 * * * /usr/bin/python3 /home/sparky/bugbounty-swarm/scripts/run_focus.py >> /home/sparky/bugbounty-swarm/output/cron.log 2>&1
```

## 🧰 Make Targets

```bash
make test
make validate
```

## 🤖 OpenClaw Integration

Emit a structured summary for OpenClaw and package artifacts:

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

For vuln scans:

```bash
python3 vuln_scanner_orchestrator.py https://example.com \
  --authorized \
  --profile cautious \
  --tech "Next.js,React" \
  --openclaw \
  --schema-repair \
  --summary-json output/openclaw_vuln_summary.json \
  --artifact-dir output/artifacts
```

Note: schema validation is strict by default. Use `--schema-repair` to auto-fix.

## 🧾 Schema Report

Each run writes `output/openclaw_schema_report.json` with validation status.

## 🧪 Dry Run

Validate configs and emit empty reports without network requests:

```bash
python3 swarm_orchestrator.py example.com --dry-run
python3 vuln_scanner_orchestrator.py https://example.com --dry-run
```

## 📐 Findings Schema

`configs/findings_schema.json` is copied into each vuln output directory.

## 📊 Dashboard

Build a dashboard across runs:

```bash
python3 scripts/build_dashboard.py
```

The dashboard includes:
- Total report counts and target summary
- Per-target aggregation
- Filtering by type and text search

## 📎 Operator Sheet

See `docs/OPERATIONS.md` for the merged runbook, safety policy, validation checklist, and work-order logbook.

## 🧩 Self-Install (Agent)

To install this repo as an agent skill on the server:

```bash
bash scripts/install_self.sh
```

## 🚀 One-Command Bootstrap

```bash
bash scripts/bootstrap.sh example.com
```

Bootstrap now checks:
- `python3` + `pip3`
- installs Python deps
- warns if `node` / `puppeteer` missing
- validates `configs/scope.json`

## 🔒 Safety & Consent

- [Operations Doc (includes Safety & Consent)](./docs/OPERATIONS.md) - **Required reading** before running any production scans.

## 📋 Product Contract (scan interface)

This defines the **sellable spec** — any run that doesn't meet these requirements is not a valid product run.

### Operators must use: `./bugbounty-swarm scan`

The `scan` command is the **only stable interface** for production runs.

- **Exploratory is default** — safe, read-only checks (TLS, headers, cookies, passive recon)
- **Deep mode consent** requires ALL of:
  - Consent file at `<out>/consent/<target>.txt` with:
    - Target identifier
    - Consenting party contact
    - Allowed techniques + time window
    - "permission granted" statement + date
  - Matching `--consent-token` argument at runtime

### Required artifacts under `--out`:

| File | Description |
|------|-------------|
| `findings.json` | Structured vulnerability findings |
| `disclosure_email.md` | Draft disclosure email (human review required) |
| `run.log` | Full execution log |

### run.log first event:

```
AUTHZ_ENFORCED policy_sha256=<hash> target=<target> mode=<exploratory|deep>
```

This audit trail is **mandatory** for product-grade runs.

---

## 🔒 Safety & Ethics

> **⚠️ WARNING: For authorized testing only**

- Always obtain **written authorization** before testing any target
- This tool is designed for **legitimate security research**
- Unauthorized access is **illegal** and **unethical**
- The authors assume **no liability** for misuse

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Submit a PR

---

**Note:** This project follows the methodology from [First-Bounty](https://github.com/BehiSecc/First-Bounty) - the beginner-friendly bug bounty roadmap.

