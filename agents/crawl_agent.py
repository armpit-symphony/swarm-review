#!/usr/bin/env python3
"""
Crawl Agent - Web crawling, screenshots, and content extraction
Uses puppeteer for screenshots (free, no API key needed)
"""

import os
import sys
import json
import subprocess
import requests
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from core.rate_limit import from_env as budget_from_env
from core.http_utils import response_differs

# Config
OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[1] / "output")
SCREENSHOT_DIR = f"{OUTPUT_DIR}/screenshots"

class CrawlAgent:
    def __init__(self, target, max_pages=20):
        self.target = target
        self.max_pages = max_pages
        self.visited = set()
        self.results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "pages": [],
            "screenshots": [],
            "endpoints": [],
            "js_files": [],
            "forms": []
        }
        
        # Ensure output dirs exist
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    def run(self):
        """Run crawl based on target type"""
        print(f"🕷️ Starting crawl on: {self.target}")
        self._budget = budget_from_env()
        
        # Normalize URL
        if not self.target.startswith("http"):
            self.target = f"https://{self.target}"
        
        # Start crawling
        self.crawl_page(self.target)
        
        # Take screenshot of homepage
        self.screenshot(self.target, "homepage")
        
        # Extract JS files from all pages
        self.find_javascript()
        
        self.save_results()
        return self.results
    
    def crawl_page(self, url):
        """Crawl a single page"""
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        
        self.visited.add(url)
        print(f"   📄 Crawling: {url}")
        
        try:
            baseline = None
            self._budget.wait_for_budget()
            baseline = requests.get(url, timeout=10, headers={
                "User-Agent": "Mozilla/5.0 (SwarmReview Bot)"
            })
            self._budget.wait_for_budget()
            resp = requests.get(url, timeout=10, headers={
                "User-Agent": "Mozilla/5.0 (SwarmReview Bot)"
            })
            
            if not resp.ok:
                return
            if not response_differs(baseline, resp):
                return
            content = resp.text

            # Extract links
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, "html.parser")

            # Find all links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, href)

                # Same domain only
                if urlparse(full_url).netloc == urlparse(self.target).netloc:
                    if full_url not in self.visited:
                        self.results["endpoints"].append(full_url)

            # Find forms
            forms = soup.find_all("form")
            for form in forms:
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get"),
                    "inputs": [inp.get("name", "") for inp in form.find_all(["input", "textarea"])],
                }
                self.results["forms"].append(form_data)

            # Find JS files
            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                if js_url not in self.results["js_files"]:
                    self.results["js_files"].append(js_url)

            page_info = {
                "url": url,
                "status": resp.status_code,
                "title": soup.title.string if soup.title else "",
                "forms_count": len(forms),
                "links_count": len(soup.find_all("a")),
            }
            self.results["pages"].append(page_info)

            print(f"      ✅ {len(forms)} forms, {len(soup.find_all('a'))} links")
            print(f"      ✅ {len(forms)} forms, {len(soup.find_all('a'))} links")
                
        except Exception as e:
            print(f"      ❌ Failed: {e}")
    
    def screenshot(self, url, name):
        """Take screenshot using puppeteer"""
        print(f"   📸 Screenshot: {name}")
        
        # Create temp JS file for puppeteer
        screenshot_path = f"{SCREENSHOT_DIR}/{name}.png"
        
        safe_url = url.replace("'", "%27")
        puppeteer_script = f"""
const {{ chromium }} = require('puppeteer');

(async () => {{
    const browser = await chromium.launch();
    const page = await browser.newPage();
    await page.setViewport({{ width: 1280, height: 720 }});
    await page.goto('{safe_url}', {{ waitUntil: 'networkidle2' }});
    await page.screenshot({{ path: '{screenshot_path}' }});
    await browser.close();
}})();
"""
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "shot"
        script_path = f"{SCREENSHOT_DIR}/_script_{safe_name}.js"
        
        try:
            with open(script_path, "w") as f:
                f.write(puppeteer_script)
            
            result = subprocess.run(
                ["node", script_path],
                capture_output=True,
                timeout=30
            )
            
            if os.path.exists(screenshot_path):
                self.results["screenshots"].append({
                    "url": url,
                    "path": screenshot_path,
                    "name": name
                })
                print(f"      ✅ Saved: {screenshot_path}")
            else:
                print(f"      ⚠️ Screenshot failed")
                
        except FileNotFoundError:
            print(f"      ⚠️ Puppeteer not installed - install with: npm install puppeteer")
        except Exception as e:
            print(f"      ❌ Error: {e}")
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)
    
    def find_javascript(self):
        """Analyze JavaScript files for endpoints/secrets"""
        print(f"   🔍 Analyzing {len(self.results['js_files'])} JS files...")
        
        js_endpoints = []
        
        for js_url in self.results["js_files"][:10]:  # Limit to 10
            try:
                self._budget.wait_for_budget()
                resp = requests.get(js_url, timeout=5)
                if resp.ok:
                    content = resp.text
                    
                    # Simple pattern matching for APIs
                    import re
                    api_patterns = [
                        r'/api/[a-zA-Z0-9_/]+',
                        r'/v[0-9]/[a-zA-Z0-9_/]+',
                        r'endpoint["\']\\s*[:=]\\s*["\'][^"\']+["\']'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, content)
                        js_endpoints.extend(matches)
                        
            except:
                pass
        
        self.results["js_endpoints"] = list(set(js_endpoints))
        print(f"      ✅ Found {len(js_endpoints)} potential endpoints")
    
    def save_results(self):
        """Save results"""
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        filename = f"{OUTPUT_DIR}/crawl_{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Don't save full JS content
        save_data = self.results.copy()
        
        with open(filename, "w") as f:
            json.dump(save_data, f, indent=2)
        
        print(f"   💾 Saved: {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python crawl_agent.py <target_url> [max_pages]")
        sys.exit(1)
    
    target = sys.argv[1]
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    
    agent = CrawlAgent(target, max_pages)
    results = agent.run()
    
    print(f"\n✅ Crawl complete for {target}")
    print(f"   Pages: {len(results['pages'])}")
    print(f"   Screenshots: {len(results['screenshots'])}")
    print(f"   Forms: {len(results['forms'])}")
