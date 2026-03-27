---
name: swarm-review
description: Autonomous multi-pass code review for AI-generated code via OpenClaw. Review PRs, scan codebases, and catch vulnerabilities with a swarm of specialized agents.
version: 1.1.0
---

# SwarmReview Skill

Autonomous multi-pass code review system. Install as an agent skill and trigger reviews via CLI or webhook.

## Install

```bash
bash scripts/install_self.sh
```

## Run Code Review (PR / Diff)

```bash
# Review a GitHub PR
python3 code_review_pipeline.py \
  --github-repo owner/repo \
  --pr-number 42 \
  --profile cautious \
  --openclaw \
  --summary-json output/openclaw_summary.json \
  --artifact-dir output/artifacts

# Review a local diff
./swarm-review scan \
  --diff /path/to/changes.diff \
  --token <gh-token> \
  --out ./output
```

## Run Web App Review (Legacy Bug Bounty Mode)

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

## Key Outputs

| Output | Description |
|--------|-------------|
| `findings.json` | Structured findings with severity + evidence refs |
| `report.md` | Human-readable summary for team |
| `openclaw_summary.json` | OpenClaw dashboard integration |
| `artifacts/` | Evidence bundle (redacted) |

## Review Profiles

- `passive`: SAST only, no active tests
- `cautious`: SAST + secrets detection
- `deep`: SAST + secrets + LLM logic analysis + cross-correlation

## Safety

- Self-authorized (reviewing own code — no external consent needed)
- Secrets auto-redacted in evidence bundles
- Scope enforced via `configs/scope.json`
- Focus mode via `configs/focus.yaml` for continuous monitoring
