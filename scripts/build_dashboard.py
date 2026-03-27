#!/usr/bin/env python3
"""Build an HTML dashboard across runs."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _load_reports(output_dir: str):
    reports = []
    for path in Path(output_dir).glob("**/*_report_*.json"):
        try:
            data = json.loads(path.read_text())
            reports.append(("swarm", path.name, data))
        except Exception:
            continue
    for path in Path(output_dir).glob("vuln_scan_*.json"):
        try:
            data = json.loads(path.read_text())
            reports.append(("vuln", path.name, data))
        except Exception:
            continue
    return reports


def main() -> int:
    output_dir = os.getenv("SWARM_OUTPUT_DIR") or "output"
    reports = _load_reports(output_dir)
    stats_by_target = {}
    rows = ""
    for rtype, name, data in reports:
        target = data.get("target", "")
        ts = data.get("timestamp", "")
        total = data.get("total_findings", "")
        stats = stats_by_target.setdefault(target, {"swarm": 0, "vuln": 0, "findings": 0})
        stats[rtype] += 1
        if isinstance(total, int):
            stats["findings"] += total
        rows += f"<tr><td>{rtype}</td><td>{name}</td><td>{target}</td><td>{ts}</td><td>{total}</td></tr>"

    summary_rows = ""
    for target, stats in stats_by_target.items():
        summary_rows += (
            f"<tr><td>{target}</td><td>{stats['swarm']}</td>"
            f"<td>{stats['vuln']}</td><td>{stats['findings']}</td></tr>"
        )

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>SwarmReview Dashboard</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f2f2f2; }}
.banner {{ padding: 12px; background: #f6f6f6; border: 1px solid #ddd; margin-bottom: 16px; }}
.filters {{ margin: 12px 0; }}
</style>
<script>
function filterTable() {{
  const q = document.getElementById('filterText').value.toLowerCase();
  const sev = document.getElementById('filterType').value;
  const rows = document.querySelectorAll('#reports tbody tr');
  rows.forEach(r => {{
    const text = r.innerText.toLowerCase();
    const type = r.children[0].innerText;
    const matchText = text.includes(q);
    const matchType = sev === '' || type === sev;
    r.style.display = (matchText && matchType) ? '' : 'none';
  }});
}}
</script>
</head><body>
<h1>SwarmReview Dashboard</h1>
<div class="banner">
  <strong>Total reports:</strong> {len(reports)} |
  <strong>Targets:</strong> {len(stats_by_target)}
</div>

<h2>Target Summary</h2>
<table>
  <tr><th>Target</th><th>Swarm Reports</th><th>Vuln Reports</th><th>Total Findings</th></tr>
  {summary_rows}
</table>

<div class="filters">
  <label>Search: <input id="filterText" onkeyup="filterTable()" /></label>
  <label>Type:
    <select id="filterType" onchange="filterTable()">
      <option value="">All</option>
      <option value="swarm">swarm</option>
      <option value="vuln">vuln</option>
    </select>
  </label>
</div>

<h2>Reports</h2>
<table>
<tbody id="reports">
<tr><th>Type</th><th>Report</th><th>Target</th><th>Timestamp</th><th>Total Findings</th></tr>
{rows}
</tbody>
</table>
</body></html>
"""
    out_path = Path(output_dir) / "dashboard.html"
    out_path.write_text(html)
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
