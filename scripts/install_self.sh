#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="${HOME}/.agents/skills/swarm-review"

mkdir -p "$(dirname "$AGENT_DIR")"

if [ -e "$AGENT_DIR" ]; then
  echo "Already installed at $AGENT_DIR"
  exit 0
fi

cp -a "$REPO_DIR" "$AGENT_DIR"
echo "Installed to $AGENT_DIR"
echo "Restart your agent to pick up the skill."
