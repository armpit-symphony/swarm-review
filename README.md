# 🐝 SwarmReview

<p align="center">
  <img src="https://img.shields.io/badge/Code%20Review-Autonomous%20Swarm-blue" alt="SwarmReview">
  <img src="https://img.shields.io/badge/Python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-orange" alt="License">
</p>

> Autonomous multi-pass code review for AI-generated code. A swarm of specialized agents catches what single-pass scanners miss.

**⚠️ Rebrand in progress:** SwarmReview was formerly "Bug Bounty Swarm." Core architecture is proven (300+ production runs). Positioning is pivoting from external vulnerability hunting to internal AI code review.

---

## The Problem

AI coding tools are merging PRs **98% faster** — but human review capacity hasn't kept up. AI-generated code has **1.7x more issues per PR** vs human-written (GitClear 2025). Logic errors up 75%, security vulnerabilities up 1.5-2x.

**The bottleneck shifted:** Writing code → Reviewing code.

SwarmReview addresses this with a multi-agent swarm that runs multiple review passes — SAST, secrets detection, LLM logic analysis — and delivers findings as GitHub PR comments, ready-to-use reports, or continuous monitoring alerts.

---

## 🚀 Features

### Multi-Pass Review Architecture
- **Pass 1: SAST** — Bandit/Semgrep for security hotspots and code quality
- **Pass 2: Secrets Detection** — API keys, tokens, passwords in diffs
- **Pass 3: LLM Analysis** — Logic errors, business rule violations, exploitability
- **Pass 4: Correlation** — Cross-reference findings across passes

### Integrations
- **GitHub PRs** — Webhook-triggered review on PR open/update
- **GitHub App** — One-click install, no server required
- **CLI** — `./swarm-review scan --diff <patch>` for local/offline review

### Output Formats
- GitHub PR comments (per-finding, actionable)
- JSON report (`findings.json`) with severity + evidence
- Markdown summary (`report.md`) for teams
- Continuous monitoring alerts (email/Slack — Pro tier)

### Safety & Consent
- Self-authorized: You're reviewing your own code — no external authorization needed
- Strict scope enforcement via `configs/scope.json`
- Evidence bundling with redaction by default
- No exfiltration of proprietary code (all analysis runs locally)

---

## 📁 Architecture

```
swarm-review/
├── agents/
│   ├── static_analyzer.py       # SAST (Bandit/Semgrep)
│   ├── secrets_detector.py      # detect-secrets integration
│   ├── llm_review_agent.py      # LLM-powered logic analysis
│   ├── comment_agent.py         # GitHub PR comment posting
│   ├── crawl_agent.py           # Web app review (legacy)
│   └── vuln_scanners/           # Active testing (legacy)
├── github_app/
│   ├── webhook_server.py        # PR webhook receiver
│   └── server.py               # GitHub App entry point
├── code_review_pipeline.py       # New: PR review orchestrator
├── swarm_orchestrator.py        # Original: web app recon (legacy)
├── vuln_scanner_orchestrator.py # Original: active vuln scan (legacy)
└── configs/
    ├── profiles.yaml             # Review profiles (passive/cautious/deep)
    ├── scope.json               # Authorized targets
    └── focus.yaml               # Continuous monitoring config
```

---

## 🔧 Quick Start

### GitHub App (Recommended)

1. Install the GitHub App on your repo
2. That's it — PRs automatically trigger SwarmReview
3. Findings appear as PR comments within minutes

### CLI

```bash
# Install
git clone https://github.com/armpit-symphony/swarm-review.git
cd swarm-review
pip install -r requirements.txt

# Review a diff locally
./swarm-review scan --diff /path/to/pull.diff --token <gh-token>

# Full codebase scan (one-shot)
python3 code_review_pipeline.py /path/to/repo --profile cautious
```

### Docker

```bash
docker build -t swarm-review .
docker run -e GITHUB_APP_ID=xxx -e GITHUB_APP_PRIVATE_KEY=@/path/to/key.pem \
  -v $(pwd)/output:/app/output swarm-review
```

---

## 🎯 Usage Modes

### Passive (Default — Free Tier)
- SAST via Bandit/Semgrep on changed files
- Secrets scan via detect-secrets
- No LLM calls (no cost)
- GitHub PR comments for High/Medium findings

### Cautious (+ Secrets — Starter Tier, $29/mo)
- Everything in Passive
- Full secrets detection with regex + entropy
- Email summary report per PR

### Deep (+ LLM — Pro Tier, $99/mo)
- Everything in Cautious
- LLM-powered logic analysis (Grok/MiniMax)
- Cross-pass correlation (correlate SAST + secrets + logic findings)
- Slack alerts for critical findings

### Continuous Monitoring (Enterprise, $299/mo)
- Weekly re-scan of baseline
- Drift detection (new exposures since last merge)
- Dashboard with historical trends
- Self-hosted option available

---

## 🔒 Safety & Ethics

- **Self-authorized:** You are reviewing your own code
- **No exfiltration:** All analysis runs locally or in your infrastructure
- **No touching production:** Only diffs and PR-level access
- **Redaction:** Secrets auto-redacted from evidence bundles

---

## 📊 Comparison with Alternatives

| Tool | Approach | Pricing | Best For |
|------|----------|---------|---------|
| **SwarmReview** | Multi-pass swarm | Free-$299/mo | Indie hackers, small teams |
| CodeRabbit | Single-pass AI | $20/user/mo | GitHub-native teams |
| Claude Code Security | Enterprise SAST | Enterprise | Big enterprises |
| Shannon | Autonomous pentest | OSS / Enterprise | Security teams |
| Semgrep | Rule-based SAST | Free-$150/mo | DevSecOps pipelines |

SwarmReview differentiates on: **swarm multi-pass architecture**, **indie/small team pricing**, **GitHub App one-click install**.

---

## 🤖 OpenClaw Integration

Emit structured summaries for OpenClaw dashboards:

```bash
python3 code_review_pipeline.py /path/to/repo \
  --profile cautious \
  --openclaw \
  --summary-json output/openclaw_summary.json \
  --artifact-dir output/artifacts
```

---

## 🧪 Validation

Run the validation harness on a review report:

```bash
python3 -m core.harness.validate output/findings_<repo>_YYYYMMDD_HHMMSS.json
```

---

## 🔄 Legacy: Bug Bounty Swarm Mode

The original Bug Bounty Swarm recon/orchestrator is preserved at:
- `swarm_orchestrator.py` — Web app recon + crawl
- `vuln_scanner_orchestrator.py` — Active vulnerability scanning

These are maintained for backward compatibility but are **not the primary product direction**.

---

## Roadmap

| Phase | Target | Features |
|-------|--------|---------|
| Phase 0 | Now | Repo rebrand, GitHub App scaffold, SAST integration |
| Phase 1 | 2 weeks | Secrets detection, PR webhook + comments |
| Phase 2 | 1 month | LLM review pass, cross-correlation |
| Phase 3 | Q2 2026 | Gumroad/Lemon Squeezy payments, Free/Pro/Enterprise tiers |

---

## 📝 License

MIT License — See [LICENSE](LICENSE) for details.

---

*Formerly: Bug Bounty Swarm — `https://github.com/armpit-symphony/bugbounty-swarm`*
