# SwarmReview GitHub App

One-click GitHub App installation for automated PR code review.

## Features

- **Automatic PR review** on every PR open, update, or reopen
- **Multi-pass analysis**: SAST → Secrets → LLM (configurable profile)
- **Inline PR comments** with findings organized by severity
- **No server required** — uses GitHub App webhooks

## Prerequisites

- Python 3.8+
- `pip install -r requirements.txt`
- GitHub App credentials (App ID + private key)

## Setup

### 1. Create a GitHub App

1. Go to GitHub Settings → Developer Settings → GitHub Apps → **New GitHub App**
2. Fill in:
   - **GitHub App name**: `SwarmReview` (must be unique)
   - **Homepage URL**: `https://swarmreview.dev`
   - **Webhook URL**: Your server URL (e.g., `https://yourserver.com`)
   - **Webhook secret**: Generate a random secret, save it for later
3. **Permissions** (set under "Permissions"):
   - Repository permissions:
     - `Contents`: Read-only (read code for review)
     - `Pull requests`: Read & Write (post comments)
     - `Commit statuses`: Read-only (check CI status)
     - `Pull request metadata`: Read-only
4. **Subscribe to events**:
   - `Pull request`
5. Create the app → download the private key (`.pem` file)

### 2. Configure Environment

```bash
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY=@/path/to/your/app.private-key.pem
export SWARM_WEBHOOK_SECRET=your_webhook_secret
export SWARM_REVIEW_PROFILE=cautious
export SWARM_OUTPUT_DIR=/var/log/swarm-review
```

Or create a `.env` file:

```bash
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY=@/path/to/your/app.private-key.pem
SWARM_WEBHOOK_SECRET=your_webhook_secret
SWARM_REVIEW_PROFILE=cautious
SWARM_OUTPUT_DIR=/var/log/swarm-review
```

### 3. Install the App

1. Go to your GitHub App page
2. Click **Install App**
3. Select the repositories you want to enable SwarmReview on

### 4. Run the Webhook Server

```bash
python3 github_app/webhook_server.py --port 9000
```

For production, use a process manager (systemd, PM2):

```bash
# systemd service example
[Unit]
Description=SwarmReview GitHub App
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/swarm-review
EnvironmentFile=/path/to/swarm-review/.env
ExecStart=/usr/bin/python3 github_app/webhook_server.py --port 9000
Restart=always

[Install]
WantedBy=multi-user.target
```

### 5. Test

Open a PR in one of your installed repos. You should see a SwarmReview check appear within a few minutes.

## Profiles

| Profile | SAST | Secrets | LLM |
|---------|------|---------|-----|
| `passive` | ✅ | ❌ | ❌ |
| `cautious` | ✅ | ✅ | ❌ |
| `deep` | ✅ | ✅ | ✅ |

## Local Development

```bash
# Clone the repo
git clone https://github.com/armpit-symphony/swarm-review.git
cd swarm-review

# Install dependencies
pip install -r requirements.txt

# Run ngrok for webhook testing
ngrok http 9000

# Set env vars
export GITHUB_APP_ID=xxx
export GITHUB_APP_PRIVATE_KEY=@/path/to/key.pem
export SWARM_WEBHOOK_SECRET=dev-secret

# Run server
python3 github_app/webhook_server.py --port 9000
```

## File Structure

```
github_app/
├── README.md           # This file
├── webhook_server.py   # Webhook receiver + PR trigger
└── server.py          # (Future: GitHub App HTTP handler)
```

## Troubleshooting

**PR comment not appearing?**
- Check webhook delivery in GitHub App settings → Advanced
- Verify the server is reachable from the internet
- Check logs for errors

**Rate limiting?**
- GitHub App webhook delivery retries automatically
- For heavy usage, implement a job queue

**Secrets false positives?**
- Use `--profile passive` to disable secrets scanning
- Add `SWARM_EXCLUDE_PATHS` to skip directories

---

*Part of [SwarmReview](https://github.com/armpit-symphony/swarm-review)*
