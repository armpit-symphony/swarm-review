# BugBounty-Swarm — Operator Safety & Consent Policy (One Page)

**Purpose:** This tool is designed for authorized exploratory security research and responsible disclosure drafting. It must be operated in a way that prioritizes safety, legality, and minimizing harm.

## 1) Authorization Required (Fail-Closed)

- Scans must only run against targets authorized by the operator under the project's authorization policy (e.g., `policy.yml`).
- If authorization policy is missing/invalid, execution must stop (fail closed).
- Operator is responsible for ensuring the target is within scope (domain, subdomains, paths, time window, and testing method).

## 2) Two Modes Only

### A) Exploratory Mode (Default)

Exploratory mode is designed for **authorized passive/reconnaissance** and must avoid actions that risk service interruption or data exposure.

**Allowed:**
- TLS posture checks (protocol/cipher, cert expiry, HSTS presence)
- Security header presence/quality checks (CSP/XFO/XCTO/etc.)
- Cookie attribute checks (Secure/HttpOnly/SameSite)
- Passive fingerprinting and metadata collection that does not alter state

**Disallowed in Exploratory:**
- payloads intended to exfiltrate data
- authentication bypass attempts
- credential stuffing / brute force
- denial-of-service, load testing, stress testing
- destructive file upload, DB tampering, or mass scanning across third parties

### B) Deep Dive Mode (Consent-Gated)

Deep dive testing is only allowed when explicit consent is obtained from the site/system owner and recorded. Deep dive requires ALL of:

1) Operator possession of written permission (email, ticket, contract, or signed statement)
2) A repo-stored consent artifact: `artifacts/consent/<target>.txt` containing:
   - target identifier
   - consenting party + contact
   - allowed techniques + time window
   - "permission granted" statement + date
3) A runtime consent gate: `--consent-token` or equivalent control that prevents accidental deep execution.

## 3) Safety Controls (Must Use)

- Prefer read-only checks first; escalate only with authorization + consent.
- Respect rate limits: keep concurrency bounded and avoid peak hours if requested.
- Stop immediately if instability is observed (5xx spike, latency spike, WAF lockouts, user impact).
- Store secrets safely: never hardcode credentials; use env vars / secret stores.
- Log every run: timestamp, authorized policy hash, target, mode, and major actions taken.

## 4) Evidence Standard ("No Proof, No Report")

High/critical claims must include at least one:
- raw request/response excerpt (redacted)
- header/cert evidence
- exact reproduction steps
- tool output reference with timestamps
- screenshots/artifacts (if applicable)

If evidence is insufficient, findings must be labeled as unconfirmed or downgraded.

## 5) Responsible Disclosure Rule

- Draft emails must be reviewed by a human before sending.
- Do not include sensitive data in disclosures.
- Provide practical remediation guidance and offer a consented deep dive if appropriate.
- Follow a reasonable timeline (e.g., 90 days) unless the program/owner specifies otherwise.

## 6) Operator Accountability

Operators are solely responsible for:
- ensuring legal authorization
- adhering to consent scope and allowed techniques
- minimizing harm and avoiding data exposure
- complying with applicable laws and program terms

If unsure, do less—seek clarification and written consent before escalation.
