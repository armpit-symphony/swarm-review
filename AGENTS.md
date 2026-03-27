# AGENTS.md

## Purpose
Plug-and-play agent skill for SwarmReview — autonomous multi-pass AI code review.

## Auto-Install
Run:
```bash
bash scripts/install_self.sh
```

## Auto-Run (OpenClaw default)
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

## Required Setup
- Add authorized targets to `configs/scope.json`
- If using focus mode, set `configs/focus.yaml`
