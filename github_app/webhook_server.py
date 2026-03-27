#!/usr/bin/env python3
"""
SwarmReview — GitHub App Webhook Server
Receives PR opened/updated webhooks and triggers code review pipeline.

Usage:
    GITHUB_APP_ID=xxx GITHUB_APP_PRIVATE_KEY=@/path/to/key.pem \
    python3 github_app/webhook_server.py --port 9000
"""

import os
import sys
import json
import hmac
import hashlib
import argparse
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


WEBHOOK_SECRET = os.getenv("SWARM_WEBHOOK_SECRET", "")  # Set in GitHub App settings


class WebhookHandler(BaseHTTPRequestHandler):
    """Handle GitHub PR webhook events."""

    def do_POST(self):
        """Process incoming webhook."""
        # Verify signature
        signature = self.headers.get("X-Hub-Signature-256", "")
        if WEBHOOK_SECRET:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            expected = "sha256=" + hmac.new(
                WEBHOOK_SECRET.encode(), body, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Invalid signature")
                return
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))

        event = self.headers.get("X-GitHub-Event", "")
        delivery_id = self.headers.get("X-GitHub-Delivery", "")

        logger.info(f"Webhook {delivery_id} event={event}")

        if event == "pull_request":
            try:
                payload = json.loads(body)
                action = payload.get("action", "")
                pr = payload.get("pull_request", {})
                repo = payload.get("repository", {}).get("full_name", "")

                if action in ("opened", "synchronize", "reopened"):
                    logger.info(f"Triggering review for {repo} PR #{pr.get('number')}")
                    self._trigger_review(repo, pr.get("number"), pr.get("head", {}).get("sha"))
                    self._respond(200, {"status": "review_triggered"})
                else:
                    self._respond(200, {"status": "ignored", "action": action})

            except Exception as e:
                logger.error(f"Error processing webhook: {e}")
                self._respond(500, {"error": str(e)})
        else:
            self._respond(200, {"status": "ignored", "event": event})

    def _trigger_review(self, repo: str, pr_number: int, commit_sha: str):
        """Trigger the code review pipeline for a PR."""
        # Import here to avoid circular deps
        import subprocess
        import os as os_mod

        env = os_mod.environ.copy()
        env["SWARM_TARGET_REPO"] = repo
        env["SWARM_PR_NUMBER"] = str(pr_number)
        env["SWARM_COMMIT_SHA"] = commit_sha or ""

        # Run pipeline asynchronously
        cmd = [
            sys.executable, "-m", "code_review_pipeline",
            "--github-repo", repo,
            "--pr-number", str(pr_number),
            "--profile", os.getenv("SWARM_REVIEW_PROFILE", "cautious"),
        }
        logger.info(f"Running: {' '.join(cmd)}")

        # TODO: Use proper async/queue for production
        subprocess.Popen(
            cmd,
            cwd=Path(__file__).parent.parent,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _respond(self, code: int, body: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


def main():
    parser = argparse.ArgumentParser(description="SwarmReview GitHub webhook server")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), WebhookHandler)
    logger.info(f"SwarmReview webhook server listening on :{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
