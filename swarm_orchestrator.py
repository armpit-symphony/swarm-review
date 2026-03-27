#!/usr/bin/env python3
"""
SwarmReview Orchestrator
Coordinates recon, crawl, and enrichment agents

Features:
- Safe scheme handling (auto-HTTP for localhost)
- --scheme flag to force HTTP/HTTPS
- Graceful error handling (no crashes on crawl failure)
"""

import os
import sys
import json
import subprocess
import argparse
import re
import shutil
from datetime import datetime
from pathlib import Path

# Add agents to path
AGENT_DIR = Path(__file__).parent
sys.path.insert(0, str(AGENT_DIR))

from agents.recon_agent import ReconAgent
from agents.crawl_agent import CrawlAgent
from agents.enrichment_agent import EnrichmentAgent
from core.scope import ScopeConfig, require_in_scope, default_scope_path
from core.report import write_json, write_markdown, write_html
from core.config import load_profiles, load_mcp, load_budget, repo_root
from core.focus import load_focus, require_focus_target, resolve_focus_target
from core.openclaw_schema import load_schema, validate as validate_schema, repair as repair_schema
from core.openclaw_report import write_report as write_schema_report
from mcp.recon_adapter import ReconMCPAdapter
from mcp.crawl_adapter import CrawlMCPAdapter
from mcp.enrichment_adapter import EnrichmentMCPAdapter
from scripts.package_evidence import package as package_evidence
from vuln_scanner_orchestrator import VulnScannerOrchestrator
from core.scope import require_authorized
from core.auth_policy import require_auth_policy, default_policy_path

# Config
OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).parent / "output")

# Local hosts that should default to HTTP
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def normalize_target(raw: str, scheme: str = None) -> str:
    """Normalize a target URL or host with a safe scheme default."""
    raw = raw.strip()

    if raw.startswith(("http://", "https://")):
        return raw

    host = raw.split("/")[0].split(":")[0].lower()
    chosen = scheme if scheme else ("http" if host in LOCAL_HOSTS else "https")
    return f"{chosen}://{raw}"


class SwarmOrchestrator:
    def __init__(self, target, profile="cautious", output_dir: str = OUTPUT_DIR, scheme=None):
        self.target = target
        self.raw_target = target
        self.target_url = normalize_target(target, scheme)
        self.scheme = self.target_url.split("://")[0]
        self.profile = profile
        self.output_dir = output_dir
        self.results = {
            "target": target,
            "target_url": self.target_url,
            "scheme": self.scheme,
            "timestamp": datetime.utcnow().isoformat(),
            "profile": profile,
            "recon": None,
            "crawl": None,
            "enrichment": None,
            "summary": {},
            "errors": [],
        }

        os.makedirs(self.output_dir, exist_ok=True)

    def run_full_swarm(self):
        """Run complete bug bounty workflow"""
        print("=" * 60)
        print("🐞 BUG BOUNTY SWARM - STARTING")
        print(f"   Target: {self.raw_target}")
        print(f"   URL: {self.target_url}")
        print("=" * 60)

        profiles = load_profiles(str(repo_root() / "configs" / "profiles.yaml"))
        profile_cfg = profiles.get("profiles", {}).get(self.profile, {})
        max_pages = int(profile_cfg.get("max_pages", 20))
        mcp_cfg = load_mcp(str(repo_root() / "configs" / "mcp.yaml"))
        mcp_endpoints = (mcp_cfg or {}).get("endpoints", {})
        mcp_enabled = bool((mcp_cfg or {}).get("enabled", True))

        recon_mcp = ReconMCPAdapter(mcp_endpoints.get("recon", "")) if mcp_enabled else None
        crawl_mcp = CrawlMCPAdapter(mcp_endpoints.get("crawl", "")) if mcp_enabled else None
        enrich_mcp = EnrichmentMCPAdapter(mcp_endpoints.get("enrichment", "")) if mcp_enabled else None

        if recon_mcp and recon_mcp.available() and not recon_mcp.health():
            print("⚠️ MCP recon endpoint not healthy, falling back to local.")
            recon_mcp = None
        if crawl_mcp and crawl_mcp.available() and not crawl_mcp.health():
            print("⚠️ MCP crawl endpoint not healthy, falling back to local.")
            crawl_mcp = None
        if enrich_mcp and enrich_mcp.available() and not enrich_mcp.health():
            print("⚠️ MCP enrichment endpoint not healthy, falling back to local.")
            enrich_mcp = None

        # Phase 1: Recon
        print("\n📡 PHASE 1: RECON")
        print("-" * 40)
        try:
            if recon_mcp and recon_mcp.available():
                mcp_data = recon_mcp.run(self.raw_target)
                if mcp_data:
                    self.results["recon"] = mcp_data
                else:
                    recon = ReconAgent(self.raw_target)
                    self.results["recon"] = recon.run()
            else:
                recon = ReconAgent(self.raw_target)
                self.results["recon"] = recon.run()
        except Exception as e:
            print(f"   ❌ Recon failed: {e}")
            self.results["errors"].append({"stage": "recon", "error": str(e)})

        # Phase 2: Crawl (graceful failure)
        print("\n🕷️ PHASE 2: CRAWL")
        print("-" * 40)
        try:
            if crawl_mcp and crawl_mcp.available():
                mcp_data = crawl_mcp.run(self.target_url, max_pages=max_pages)
                if mcp_data:
                    self.results["crawl"] = mcp_data
                else:
                    crawl = CrawlAgent(self.target_url, max_pages=max_pages)
                    self.results["crawl"] = crawl.run()
            else:
                crawl = CrawlAgent(self.target_url, max_pages=max_pages)
                self.results["crawl"] = crawl.run()
        except Exception as e:
            print(f"   ⚠️ Crawl failed: {e}")
            self.results["crawl"] = {"error": str(e), "skipped": True}
            self.results["errors"].append({"stage": "crawl", "error": str(e)})

        # Phase 3: Enrichment (graceful failure)
        print("\n🔍 PHASE 3: ENRICHMENT")
        print("-" * 40)
        try:
            if enrich_mcp and enrich_mcp.available():
                mcp_data = enrich_mcp.run(self.raw_target)
                if mcp_data:
                    self.results["enrichment"] = mcp_data
                else:
                    enrichment = EnrichmentAgent()
                    try:
                        enrichment.detect_tech(self.target_url)
                    except Exception as e:
                        print(f"   ⚠️ Tech detection failed: {e}")
                        self.results["errors"].append({"stage": "tech_detection", "error": str(e)})
                    if self.results.get("recon") and self.results["recon"].get("dns", {}).get("a"):
                        try:
                            for ip in self.results["recon"]["dns"]["a"]:
                                enrichment.lookup_ip_virustotal(ip)
                        except Exception as e:
                            print(f"   ⚠️ IP enrichment failed: {e}")
                    enrichment.save_results()
                    self.results["enrichment"] = enrichment.results
            else:
                enrichment = EnrichmentAgent()
                try:
                    enrichment.detect_tech(self.target_url)
                except Exception as e:
                    print(f"   ⚠️ Tech detection failed: {e}")
                    self.results["errors"].append({"stage": "tech_detection", "error": str(e)})
                if self.results.get("recon") and self.results["recon"].get("dns", {}).get("a"):
                    try:
                        for ip in self.results["recon"]["dns"]["a"]:
                            enrichment.lookup_ip_virustotal(ip)
                    except Exception as e:
                        print(f"   ⚠️ IP enrichment failed: {e}")
                enrichment.save_results()
                self.results["enrichment"] = enrichment.results
        except Exception as e:
            print(f"   ⚠️ Enrichment failed: {e}")
            self.results["enrichment"] = {"error": str(e)}
            self.results["errors"].append({"stage": "enrichment", "error": str(e)})

        # Generate summary
        self.generate_summary()

        print("\n" + "=" * 60)
        if self.results["errors"]:
            print("⚠️ SWARM COMPLETED WITH ERRORS")
        else:
            print("✅ SWARM COMPLETE")
        print("=" * 60)

        return self.results

    def generate_summary(self):
        """Generate summary of findings"""
        recon = self.results.get("recon") or {}
        crawl = self.results.get("crawl") or {}
        enrichment = self.results.get("enrichment") or {}

        summary = {
            "subdomains_found": len(recon.get("subdomains", [])),
            "pages_crawled": len(crawl.get("pages", [])) if isinstance(crawl, dict) else 0,
            "screenshots": len(crawl.get("screenshots", [])) if isinstance(crawl, dict) else 0,
            "forms_found": len(crawl.get("forms", [])) if isinstance(crawl, dict) else 0,
            "js_files": len(crawl.get("js_files", [])) if isinstance(crawl, dict) else 0,
            "tech_detected": [],
            "error_count": len(self.results.get("errors", [])),
        }

        if enrichment.get("tech_detection"):
            for td in enrichment["tech_detection"]:
                if isinstance(td, dict):
                    summary["tech_detected"].extend(td.get("tech", []))

        summary["tech_detected"] = list(set(summary["tech_detected"]))

        self.results["summary"] = summary

        print("\n📊 SUMMARY:")
        print(f"   Subdomains: {summary['subdomains_found']}")
        print(f"   Pages: {summary['pages_crawled']}")
        print(f"   Screenshots: {summary['screenshots']}")
        print(f"   Forms: {summary['forms_found']}")
        print(f"   Tech: {', '.join(summary['tech_detected'][:5]) or 'None'}")
        if summary["error_count"] > 0:
            print(f"   Errors: {summary['error_count']}")

    def save_report(self):
        """Save final JSON report"""
        slug = _safe_slug(self.raw_target)
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"swarm_report_{slug}_{stamp}"
        json_path = write_json(self.output_dir, base, self.results)
        print(f"\n💾 Report: {json_path}")
        md_path, html_path = self.save_markdown_report(base)
        print(f"📝 Markdown: {md_path}")
        print(f"🌐 HTML: {html_path}")
        return json_path, md_path, html_path

    def save_markdown_report(self, base_name):
        """Save human-readable markdown report"""
        summary = self.results.get("summary", {})
        recon = self.results.get("recon") or {}
        crawl = self.results.get("crawl") or {}

        md = f"""# SwarmReview Report - {self.raw_target}

**Generated:** {self.results['timestamp']}
**Target URL:** {self.target_url}
**Profile:** {self.profile}

## Summary

| Metric | Count |
|--------|-------|
| Subdomains | {summary.get('subdomains_found', 0)} |
| Pages Crawled | {summary.get('pages_crawled', 0)} |
| Screenshots | {summary.get('screenshots', 0)} |
| Forms | {summary.get('forms_found', 0)} |
| JS Files | {summary.get('js_files', 0)} |
| Errors | {summary.get('error_count', 0)} |

## Technologies Detected

{', '.join(summary.get('tech_detected', ['None detected']))}

## Recon Findings

"""

        if recon.get("subdomains"):
            md += "### Subdomains\n\n"
            for sub in recon["subdomains"][:20]:
                md += f"- {sub}\n"
            md += "\n"

        if crawl.get("pages"):
            md += "### Crawled Pages\n\n"
            for page in crawl["pages"][:10]:
                md += f"- [{page.get('title', 'No title')}]({page.get('url')}) - {page.get('forms_count')} forms\n"
            md += "\n"
        elif crawl.get("error"):
            md += f"_Crawl failed: {crawl['error']}_\n\n"

        if crawl.get("forms"):
            md += "### Forms Found\n\n"
            for form in crawl["forms"][:10]:
                md += f"- {form.get('method', 'GET').upper()} {form.get('action', '/')} ({len(form.get('inputs', []))} inputs)\n"
            md += "\n"

        if crawl.get("screenshots"):
            md += "### Screenshots\n\n"
            for ss in crawl["screenshots"]:
                md += f"- `{ss.get('name')}`: {ss.get('path')}\n"

        if self.results.get("errors"):
            md += "\n### Errors\n\n"
            for err in self.results["errors"]:
                md += f"- **{err.get('stage', 'unknown')}**: {err.get('error', 'Unknown error')}\n"

        md_path = write_markdown(self.output_dir, base_name, md)
        html_body = f"<h1>SwarmReview Report - {self.raw_target}</h1>" + md.replace("\n", "<br />")
        html_path = write_html(self.output_dir, base_name, f"SwarmReview Report - {self.raw_target}", html_body)
        return md_path, html_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SwarmReview Orchestrator")
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--scheme", choices=["http", "https"], help="Force HTTP or HTTPS scheme")
    parser.add_argument("--force-http", action="store_true", help="Equivalent to --scheme http")
    parser.add_argument("--profile", default="cautious", choices=["passive", "cautious", "active"])
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--openclaw", action="store_true", help="Emit OpenClaw-friendly summary")
    parser.add_argument("--artifact-dir", default="", help="Copy reports and evidence bundle here")
    parser.add_argument("--summary-json", default="", help="Write summary JSON to this path")
    parser.add_argument("--run-vuln", action="store_true", help="Run vuln scans after swarm")
    parser.add_argument("--authorized", action="store_true", help="Confirm explicit authorization for active tests")
    parser.add_argument("--schema-strict", action="store_true", help="Fail if OpenClaw schema validation fails")
    parser.add_argument("--schema-repair", action="store_true", help="Auto-repair OpenClaw summary fields")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and emit empty report without requests")
    parser.add_argument("--auth", default="", metavar="PATH",
                        help="Path to auth policy YAML (default: ./policy.yml)")
    parser.add_argument("--require-auth", default=True, action=argparse.BooleanOptionalAction,
                        help="Require valid auth policy before running (default: true)")
    args = parser.parse_args()

    if args.force_http:
        args.scheme = "http"

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
    focus = load_focus(str(repo_root() / "configs" / "focus.yaml"))
    require_focus_target(focus, args.target)
    focus_target = resolve_focus_target(focus)

    os.environ["SWARM_OUTPUT_DIR"] = args.output_dir
    orchestrator = SwarmOrchestrator(args.target, profile=args.profile, output_dir=args.output_dir, scheme=args.scheme)
    budget_cfg = load_budget(str(repo_root() / "configs" / "budget.yaml"))
    os.environ["EVIDENCE_LEVEL"] = str(budget_cfg.get("evidence_level", "standard"))
    reqs = budget_cfg.get("requests", {})
    os.environ["BUDGET_MAX_PER_MINUTE"] = str(reqs.get("max_per_minute", 120))
    if args.dry_run:
        results = {
            "target": args.target,
            "target_url": normalize_target(args.target, args.scheme),
            "scheme": (args.scheme or normalize_target(args.target, None).split("://")[0]),
            "timestamp": datetime.utcnow().isoformat(),
            "profile": args.profile,
            "note": "dry_run_no_requests",
            "recon": None,
            "crawl": None,
            "enrichment": None,
            "summary": {},
            "errors": [],
        }
        orchestrator.results = results
    else:
        results = orchestrator.run_full_swarm()
    json_path, md_path, html_path = orchestrator.save_report()

    evidence_zip = package_evidence(args.output_dir)
    if evidence_zip:
        print(f"📦 Evidence bundle: {evidence_zip}")

    vuln_summary = None
    if args.run_vuln and args.profile != "passive":
        require_authorized(args.authorized)
        tech_detected = []
        if results.get("enrichment", {}).get("tech_detection"):
            for td in results["enrichment"]["tech_detection"]:
                tech_detected.extend(td.get("tech", []))
        tech_detected = list(set(tech_detected))
        scanner = VulnScannerOrchestrator(
            args.target,
            output_dir=args.output_dir,
            tech_detected=tech_detected,
        )
        scanner.run_all_scanners(active_tests=True)
        vuln_reports = getattr(scanner, "report_paths", None) or (None, None, None)
        vuln_summary = {
            "reports": {
                "json": vuln_reports[0],
                "markdown": vuln_reports[1],
                "html": vuln_reports[2],
            },
            "total_findings": scanner.results.get("total_findings", 0),
        }
    elif args.run_vuln and args.profile == "passive":
        print("⚪ Passive profile: skipping vuln scans.")

    tech_detected = []
    if results.get("enrichment", {}).get("tech_detection"):
        for td in results["enrichment"]["tech_detection"]:
            tech_detected.extend(td.get("tech", []))
    summary = {
        "schema_version": "1.0",
        "target": args.target,
        "profile": args.profile,
        "reports": {
            "json": json_path,
            "markdown": md_path,
            "html": html_path,
        },
        "evidence_zip": evidence_zip,
        "tech_detected": list(set(tech_detected)),
        "vuln_scan": vuln_summary,
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
        for p in [json_path, md_path, html_path, evidence_zip]:
            if p and os.path.exists(p):
                shutil.copy2(p, args.artifact_dir)

    if args.openclaw:
        print(json.dumps(summary))
