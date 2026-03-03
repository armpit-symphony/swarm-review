#!/usr/bin/env python3
"""
Vulnerability Scanner - Runs all vulnerability scanners
Coordinates XSS, SQLi, IDOR, SSRF, and Auth scanners
"""

import os
import sys
import json
import argparse
import re
import shutil
from datetime import datetime
from pathlib import Path

# Add agents to path
AGENT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(AGENT_DIR))

from agents.vuln_scanners.xss_scanner import XSSScanner
from agents.vuln_scanners.sqli_scanner import SQLiScanner
from agents.vuln_scanners.idor_scanner import IDORScanner
from agents.vuln_scanners.ssrf_scanner import SSRFScanner
from agents.vuln_scanners.auth_scanner import AuthScanner
from agents.vuln_scanners.tls_scanner import TLSScanner
from agents.vuln_scanners.headers_scanner import HeadersScanner
from agents.vuln_scanners.cookies_scanner import CookiesScanner
from core.scope import ScopeConfig, require_in_scope, require_authorized, default_scope_path
from core.auth_policy import require_auth_policy, default_policy_path
from core.report import write_json, write_markdown, write_html
from core.config import load_profiles, load_budget, repo_root
from core.focus import load_focus, require_focus_target, resolve_focus_target
from core.openclaw_schema import load_schema, validate as validate_schema, repair as repair_schema
from core.openclaw_report import write_report as write_schema_report
from core.playbooks import load_all_playbooks
from core.tech_router import route_playbooks
from agents.triage_agent import triage_findings
from core.disclosure_formatter import write_disclosure_email
from scripts.package_evidence import package as package_evidence

OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).parent / "output")


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")

class VulnScannerOrchestrator:
    def __init__(self, target, crawl_data=None, output_dir: str = OUTPUT_DIR, tech_detected=None):
        self.target = target
        self.crawl_data = crawl_data or {}
        self.output_dir = output_dir
        self.tech_detected = tech_detected or []
        self.results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "scans": {},
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_all_scanners(self, active_tests: bool = True):
        """Run all vulnerability scanners"""
        print("\n" + "=" * 50)
        print("🎯 VULNERABILITY SCANNERS")
        print("=" * 50)

        if not active_tests:
            print("⚪ Active tests disabled for this profile.")
            self.report_paths = self.save_report()
            self.print_summary()
            return self.results

        forms = self.crawl_data.get("forms", [])
        endpoints = self.crawl_data.get("endpoints", [])

        # XSS Scanner
        print("\n[1/8] XSS Scanner...")
        try:
            xss = XSSScanner(self.target, forms, endpoints)
            xss_results = xss.scan()
            self.results["scans"]["xss"] = xss_results
            self.count_findings(xss_results)
        except Exception as e:
            print(f"   ❌ XSS failed: {e}")
        
        # SQLi Scanner
        print("\n[2/8] SQLi Scanner...")
        try:
            sqli = SQLiScanner(self.target, forms, endpoints)
            sqli_results = sqli.scan()
            self.results["scans"]["sqli"] = sqli_results
            self.count_findings(sqli_results)
        except Exception as e:
            print(f"   ❌ SQLi failed: {e}")
        
        # IDOR Scanner
        print("\n[3/8] IDOR Scanner...")
        try:
            idor = IDORScanner(self.target)
            idor_results = idor.scan()
            self.results["scans"]["idor"] = idor_results
            self.count_findings(idor_results)
        except Exception as e:
            print(f"   ❌ IDOR failed: {e}")
        
        # SSRF Scanner
        print("\n[4/8] SSRF Scanner...")
        try:
            ssrf = SSRFScanner(self.target, endpoints)
            ssrf_results = ssrf.scan()
            self.results["scans"]["ssrf"] = ssrf_results
            self.count_findings(ssrf_results)
        except Exception as e:
            print(f"   ❌ SSRF failed: {e}")
        
        # Auth Scanner
        print("\n[5/8] Auth Scanner...")
        try:
            auth = AuthScanner(self.target)
            auth_results = auth.scan()
            self.results["scans"]["auth"] = auth_results
            self.count_findings(auth_results)
        except Exception as e:
            print(f"   ❌ Auth failed: {e}")

        # TLS Scanner
        print("\n[6/8] TLS Scanner...")
        try:
            tls = TLSScanner(self.target)
            tls_results = tls.scan()
            self.results["scans"]["tls"] = tls_results
            self.count_findings(tls_results)
        except Exception as e:
            print(f"   ❌ TLS failed: {e}")

        # Headers Scanner
        print("\n[7/8] Headers Scanner...")
        try:
            headers = HeadersScanner(self.target)
            headers_results = headers.scan()
            self.results["scans"]["headers"] = headers_results
            self.count_findings(headers_results)
        except Exception as e:
            print(f"   ❌ Headers failed: {e}")

        # Cookies Scanner
        print("\n[8/8] Cookies Scanner...")
        try:
            cookies = CookiesScanner(self.target)
            cookies_results = cookies.scan()
            self.results["scans"]["cookies"] = cookies_results
            self.count_findings(cookies_results)
        except Exception as e:
            print(f"   ❌ Cookies failed: {e}")

        # Triage + de-dupe
        all_findings = []
        for _, findings in self.results["scans"].items():
            all_findings.extend(findings)
        triaged = triage_findings(all_findings)
        playbooks = load_all_playbooks(str(repo_root() / "playbooks"))
        routed = route_playbooks(self.tech_detected)
        for f in triaged:
            pb = playbooks.get(str(f.get("type", "")).lower(), {})
            if pb and str(f.get("type", "")).lower() in routed:
                f["playbook"] = pb
        self.results["triaged_findings"] = triaged
        self._recount(triaged)

        self.report_paths = self.save_report()
        self.print_summary()
        
        return self.results
    
    def count_findings(self, findings):
        """Count findings by severity"""
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            if severity in self.results["by_severity"]:
                self.results["by_severity"][severity] += 1
            self.results["total_findings"] += 1
    
    def print_summary(self):
        """Print summary"""
        print("\n" + "=" * 50)
        print("📊 VULNERABILITY SCAN SUMMARY")
        print("=" * 50)
        print(f"Target: {self.target}")
        print(f"Total Findings: {self.results['total_findings']}")
        print(f"  CRITICAL: {self.results['by_severity']['CRITICAL']}")
        print(f"  HIGH: {self.results['by_severity']['HIGH']}")
        print(f"  MEDIUM: {self.results['by_severity']['MEDIUM']}")
        print(f"  LOW: {self.results['by_severity']['LOW']}")
        print("=" * 50)

    def _recount(self, findings):
        self.results["by_severity"] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            if severity in self.results["by_severity"]:
                self.results["by_severity"][severity] += 1
        self.results["total_findings"] = len(findings)

    def save_report(self):
        """Save full report"""
        slug = _safe_slug(self.target)
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"vuln_scan_{slug}_{stamp}"
        json_path = write_json(self.output_dir, base, self.results)
        md = self._build_markdown()
        md_path = write_markdown(self.output_dir, base, md)
        html_body = self._build_html()
        html_path = write_html(self.output_dir, base, f"Vulnerability Scan - {self.target}", html_body)
        self._write_findings_schema()
        print(f"\n💾 Report: {json_path}")
        print(f"📝 Markdown: {md_path}")
        print(f"🌐 HTML: {html_path}")

        # Write disclosure email draft if there are findings
        triaged = self.results.get("triaged_findings", [])
        if triaged:
            email_path = str(Path(self.output_dir) / f"disclosure_draft_{slug}_{stamp}.txt")
            write_disclosure_email(email_path, self.target, triaged)
            print(f"📧 Disclosure draft: {email_path}")
        else:
            email_path = None

        return json_path, md_path, html_path

    def _write_findings_schema(self):
        schema_path = Path(repo_root() / "configs" / "findings_schema.json")
        if schema_path.exists():
            dest = Path(self.output_dir) / "findings_schema.json"
            dest.write_text(schema_path.read_text())

    def _build_markdown(self) -> str:
        summary = self.results.get("by_severity", {})
        md = f"""# Vulnerability Scan - {self.target}

**Generated:** {self.results.get('timestamp')}

## Summary

| Severity | Count |
|---------|-------|
| CRITICAL | {summary.get('CRITICAL', 0)} |
| HIGH | {summary.get('HIGH', 0)} |
| MEDIUM | {summary.get('MEDIUM', 0)} |
| LOW | {summary.get('LOW', 0)} |

## Findings
"""
        for f in self.results.get("triaged_findings", []):
            md += (
                f"- **{f.get('type')}** `{f.get('severity', 'MEDIUM')}` "
                f"{f.get('url', '')} (confidence: {f.get('confidence', 0):.2f})\n"
            )
            pb = f.get("playbook", {})
            if pb:
                steps = self._step_names(pb.get("steps", []))
                md += f"  Steps: {', '.join(steps)}\n"
                md += f"  Evidence: {', '.join(pb.get('evidence', []))}\n"
        return md

    def _build_html(self) -> str:
        summary = self.results.get("by_severity", {})
        rows = ""
        for f in self.results.get("triaged_findings", []):
            pb = f.get("playbook", {})
            steps = ", ".join(self._step_names(pb.get("steps", []))) if pb else ""
            evidence = ", ".join(pb.get("evidence", [])) if pb else ""
            rows += (
                "<tr>"
                f"<td>{f.get('type')}</td>"
                f"<td>{f.get('severity','MEDIUM')}</td>"
                f"<td>{f.get('confidence', 0):.2f}</td>"
                f"<td>{f.get('url','')}</td>"
                f"<td>{steps}</td>"
                f"<td>{evidence}</td>"
                "</tr>"
            )
        return f"""
<h1>Vulnerability Scan - {self.target}</h1>
<p><strong>Generated:</strong> {self.results.get('timestamp')}</p>
<h2>Summary</h2>
<table>
  <tr><th>CRITICAL</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th></tr>
  <tr>
    <td>{summary.get('CRITICAL',0)}</td>
    <td>{summary.get('HIGH',0)}</td>
    <td>{summary.get('MEDIUM',0)}</td>
    <td>{summary.get('LOW',0)}</td>
  </tr>
</table>
<h2>Findings</h2>
<table>
  <tr>
    <th>Type</th><th>Severity</th><th>Confidence</th><th>URL</th><th>Playbook Steps</th><th>Evidence</th>
  </tr>
  {rows}
</table>
"""

    def _step_names(self, steps) -> list:
        names = []
        if isinstance(steps, list):
            for item in steps:
                if isinstance(item, dict) and item:
                    names.append(next(iter(item.keys())))
        elif isinstance(steps, dict):
            names.extend(list(steps.keys()))
        return names

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug Bounty Swarm Vulnerability Scanners")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--authorized", action="store_true", help="Confirm explicit authorization")
    parser.add_argument("--profile", default="cautious", choices=["passive", "cautious", "active"])
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--tech", default="", help="Comma-separated tech labels to route playbooks")
    parser.add_argument("--openclaw", action="store_true", help="Emit OpenClaw-friendly summary")
    parser.add_argument("--artifact-dir", default="", help="Copy reports and evidence bundle here")
    parser.add_argument("--summary-json", default="", help="Write summary JSON to this path")
    parser.add_argument("--schema-strict", action="store_true", help="Fail if OpenClaw schema validation fails")
    parser.add_argument("--schema-repair", action="store_true", help="Auto-repair OpenClaw summary fields")
    parser.add_argument("--dry-run", action="store_true", help="Emit empty report without requests")
    parser.add_argument("--auth", default="", metavar="PATH",
                        help="Path to auth policy YAML (default: ./policy.yml)")
    parser.add_argument("--require-auth", default=True, action=argparse.BooleanOptionalAction,
                        help="Require valid auth policy before running (default: true)")
    args = parser.parse_args()

    # --- Authorization Gate (fail-closed) ---
    auth_path = args.auth or default_policy_path()
    if args.require_auth:
        require_auth_policy(auth_path)
    else:
        print(
            "[auth_policy] WARNING: --no-require-auth set. "
            "Running WITHOUT authorization gate enforcement.",
            flush=True,
        )

    scope = ScopeConfig.load(default_scope_path())
    require_in_scope(scope, args.target)
    require_authorized(args.authorized)
    focus = load_focus(str(repo_root() / "configs" / "focus.yaml"))
    require_focus_target(focus, args.target)
    focus_target = resolve_focus_target(focus)

    os.environ["SWARM_OUTPUT_DIR"] = args.output_dir
    budget_cfg = load_budget(str(repo_root() / "configs" / "budget.yaml"))
    os.environ["EVIDENCE_LEVEL"] = str(budget_cfg.get("evidence_level", "standard"))
    reqs = budget_cfg.get("requests", {})
    os.environ["BUDGET_MAX_PER_MINUTE"] = str(reqs.get("max_per_minute", 120))
    profiles = load_profiles(str(repo_root() / "configs" / "profiles.yaml"))
    profile_cfg = profiles.get("profiles", {}).get(args.profile, {})
    active_tests = bool(profile_cfg.get("active_tests", True))

    tech_list = [t.strip() for t in args.tech.split(",") if t.strip()]
    scanner = VulnScannerOrchestrator(args.target, output_dir=args.output_dir, tech_detected=tech_list)
    if args.dry_run:
        scanner.results = {
            "target": args.target,
            "timestamp": datetime.utcnow().isoformat(),
            "scans": {},
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "note": "dry_run_no_requests",
        }
        scanner.report_paths = scanner.save_report()
    else:
        scanner.run_all_scanners(active_tests=active_tests)

    report_paths = getattr(scanner, "report_paths", None) or (None, None, None)
    evidence_zip = package_evidence(args.output_dir)
    if evidence_zip:
        print(f"📦 Evidence bundle: {evidence_zip}")

    summary = {
        "schema_version": "1.0",
        "target": args.target,
        "profile": args.profile,
        "reports": {
            "json": report_paths[0],
            "markdown": report_paths[1],
            "html": report_paths[2],
        },
        "evidence_zip": evidence_zip,
        "total_findings": scanner.results.get("total_findings", 0),
        "focus_target": focus_target,
    }

    schema_path = str(repo_root() / "configs" / "openclaw_schema.json")
    try:
        schema = load_schema(schema_path)
        if args.schema_repair:
            summary = repair_schema(summary, schema)
        errors = validate_schema(summary, schema)
        report_path = write_schema_report(args.output_dir, errors)
        if errors:
            print(f"⚠️ OpenClaw schema validation errors: {errors}")
            print(f"🧾 Schema report: {report_path}")
            raise SystemExit(2)
    except Exception:
        raise

    if args.summary_json:
        with open(args.summary_json, "w") as f:
            json.dump(summary, f, indent=2)

    if args.artifact_dir:
        os.makedirs(args.artifact_dir, exist_ok=True)
        for p in [report_paths[0], report_paths[1], report_paths[2], evidence_zip]:
            if p and os.path.exists(p):
                shutil.copy2(p, args.artifact_dir)

    if args.openclaw:
        print(json.dumps(summary))
