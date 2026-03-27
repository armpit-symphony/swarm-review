# Surface Control Map

**Last updated:** 2026-03-01
**Canonical state:** sparkpitlabs_handoff repo
**Control authority:** OpenClaw (Sparky) — execution orchestrator

---

## Authority

| Role | Owner | Mandate |
|------|-------|---------|
| Control Authority | OpenClaw (Sparky) | Execution orchestrator — coordinates all surfaces |
| Canonical State | sparkpitlabs_handoff repo | Single source of truth for all infra + app state |
| Change Discipline | All agents | No silent changes — every change must be (a) committed (b) logged in handoff |

---

## Surfaces

### AWS EC2 — TheSparkPit.com (Product)

| Field | Value |
|-------|-------|
| Owner | Phil + Bob |
| Purpose | Public product + UI (thesparkpit.com) |
| Must NOT host | Security tooling scans, bot swarms, disclosure automation |
| Key services | Web app, public-facing APIs |
| Snapshot command | `bash tools/surface_snapshot.sh` |

### DigitalOcean Droplet — SparkpitLabs.com (Research + Ops)

| Field | Value |
|-------|-------|
| Owner | Sparky |
| Purpose | Security tooling, bot infra, disclosures, cron jobs |
| Must NOT host | Public product UX |
| Key services | swarm-review (cron every 2h), sparkbot-v2 (port 8091), kalshi-bot, pump-me-fun |
| Snapshot command | `bash tools/surface_snapshot.sh` |

### Laptop 1 / Laptop 2 — Dev Surfaces

| Field | Value |
|-------|-------|
| Owner | Phil |
| Purpose | Local dev, testing, drafting disclosures, reviewing PRs |
| Must NOT be | Source of production secrets or long-running jobs |
| Key repos | sparkpitlabs_handoff, bugbounty-swarm |
| Snapshot command | `bash tools/surface_snapshot.sh` |

### OpenClaw — Orchestrator

| Field | Value |
|-------|-------|
| Owner | Sparky |
| Purpose | Agent control plane, permissioned execution, audit trail |
| Must NOT do | Bypass auth gates or run destructive commands without explicit callout |
| Key workspace | `/home/sparky/.openclaw/workspace/` |
| Snapshot command | `bash tools/surface_snapshot.sh` |

---

## Required Surface Invariants

Every surface MUST:

1. **Expose a status snapshot** — `bash tools/surface_snapshot.sh` runs without error
2. **Write a daily heartbeat** — `python3 tools/heartbeat_write.py` appended to `control/heartbeats/<surface>.jsonl`
3. **Record current git commit** for all key repos in the heartbeat
4. **Log all state changes** — commit + session note + handoff update before leaving any surface

---

## Change Rules (No Silent Changes)

```
Before any infra/app change on any surface:
  1. Confirm change is in scope (check scope guard in sparkpitlabs_handoff.md)
  2. Make the change
  3. git add + git commit with descriptive message
  4. Update sparkpitlabs_handoff.md with session note
  5. git push to canonical repo
```

Violations = drift. Drift = entropy. Entropy = the main risk.

---

## Surface Status at 2026-03-01

| Surface | Status | Last Known Commit |
|---------|--------|-------------------|
| AWS EC2 | ✅ Operational | unknown — run snapshot |
| DO Droplet | ✅ Operational | unknown — run snapshot |
| Laptop 1 | ✅ Dev active | unknown — run snapshot |
| Laptop 2 | ✅ Dev active | unknown — run snapshot |
| OpenClaw | ✅ Operational | see handoff repo |

> Update this table after every surface snapshot run.
