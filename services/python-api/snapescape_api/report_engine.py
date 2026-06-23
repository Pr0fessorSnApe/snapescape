"""Enterprise report generation engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SNAPESCAPE Report — {{ scan.target }}</title>
<style>
  :root { --cyan: #00f0ff; --purple: #7b2fff; --red: #ff0055; --bg: #0a0a12; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', sans-serif; background: var(--bg); color: #e0e0e0; padding: 40px; }
  .header { border-bottom: 2px solid var(--cyan); padding-bottom: 20px; margin-bottom: 30px; }
  .header h1 { color: var(--cyan); font-size: 2em; }
  .header .meta { color: #888; margin-top: 8px; }
  .severity-critical { color: var(--red); }
  .severity-high { color: #ff6644; }
  .severity-medium { color: #ffaa00; }
  .severity-low { color: #88cc00; }
  .finding { background: rgba(255,255,255,0.05); border: 1px solid rgba(0,240,255,0.2);
             border-radius: 12px; padding: 20px; margin: 16px 0; backdrop-filter: blur(10px); }
  .finding h3 { color: var(--purple); }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em;
           background: rgba(0,240,255,0.15); border: 1px solid var(--cyan); }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
  .stat { background: rgba(123,47,255,0.1); padding: 16px; border-radius: 8px; text-align: center; }
  .stat .num { font-size: 2em; color: var(--cyan); }
  pre { background: #111; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 0.85em; }
  .remediation { border-left: 3px solid var(--cyan); padding-left: 16px; margin-top: 12px; }
</style>
</head>
<body>
<div class="header">
  <h1>SNAPESCAPE Security Assessment</h1>
  <div class="meta">
    Target: <strong>{{ scan.target }}</strong> |
    Scan ID: {{ scan.id }} |
    Generated: {{ generated_at }}
  </div>
</div>

<h2>Executive Summary</h2>
<p>This report presents findings from an authorized security assessment of <strong>{{ scan.target }}</strong>.
A total of <strong>{{ findings|length }}</strong> validated findings were identified across
{{ severity_counts|length }} severity categories.</p>

<div class="stats">
  {% for sev, count in severity_counts.items() %}
  <div class="stat"><div class="num severity-{{ sev }}">{{ count }}</div><div>{{ sev|title }}</div></div>
  {% endfor %}
  <div class="stat"><div class="num">{{ assets|length }}</div><div>Assets</div></div>
</div>

<h2>Technical Findings</h2>
{% for f in findings %}
<div class="finding">
  <h3><span class="badge severity-{{ f.severity }}">{{ f.severity|upper }}</span> {{ f.title }}</h3>
  <p><strong>URL:</strong> {{ f.url }}</p>
  <p><strong>Confidence:</strong> {{ (f.confidence * 100)|int }}% |
     <strong>CWE:</strong> {{ f.cwe or 'N/A' }} |
     <strong>OWASP:</strong> {{ f.owasp or 'N/A' }} |
     <strong>MITRE ATT&CK:</strong> {{ f.mitre_attack or 'N/A' }}</p>
  {% if f.ai_analysis %}
  <p>{{ f.ai_analysis.summary }}</p>
  <div class="remediation">
    <strong>Remediation:</strong>
    <ul>{% for r in f.ai_analysis.remediation %}<li>{{ r }}</li>{% endfor %}</ul>
  </div>
  {% endif %}
  <pre>{{ f.evidence | tojson(indent=2) }}</pre>
</div>
{% endfor %}

<div style="margin-top:40px;color:#555;text-align:center;">
  SNAPESCAPE v0.1.0 — Created By Pr0Fessor_SnApe — Authorized Testing Only
</div>
</body>
</html>
"""


class ReportEngine:
    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(loader=BaseLoader())

    def generate(
        self,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        assets: list[dict[str, Any]] | None = None,
        ai_enriched: bool = False,
    ) -> dict[str, str]:
        assets = assets or []
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        context = {
            "scan": scan,
            "findings": findings,
            "assets": assets,
            "severity_counts": severity_counts,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }

        paths = {}
        scan_id = scan.get("id", "unknown")
        base = self.output_dir / scan_id
        base.mkdir(parents=True, exist_ok=True)

        # HTML
        template = self.env.from_string(REPORT_TEMPLATE)
        html = template.render(**context)
        html_path = base / "report.html"
        html_path.write_text(html, encoding="utf-8")
        paths["html"] = str(html_path)

        # JSON
        json_data = {"scan": scan, "findings": findings, "assets": assets, "generated_at": context["generated_at"]}
        json_path = base / "report.json"
        json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
        paths["json"] = str(json_path)

        # Markdown
        md = self._to_markdown(scan, findings, context["generated_at"])
        md_path = base / "report.md"
        md_path.write_text(md, encoding="utf-8")
        paths["markdown"] = str(md_path)

        # TXT
        txt_path = base / "report.txt"
        txt_path.write_text(self._to_text(scan, findings), encoding="utf-8")
        paths["txt"] = str(txt_path)

        # PDF
        try:
            from weasyprint import HTML
            pdf_path = base / "report.pdf"
            HTML(string=html).write_pdf(str(pdf_path))
            paths["pdf"] = str(pdf_path)
        except Exception:
            pass

        return paths

    def _to_markdown(self, scan: dict, findings: list, generated_at: str) -> str:
        lines = [
            f"# SNAPESCAPE Report: {scan.get('target')}",
            f"**Scan ID:** {scan.get('id')} | **Generated:** {generated_at}",
            "",
            "## Findings",
            "",
        ]
        for f in findings:
            lines.append(f"### [{f.get('severity', '').upper()}] {f.get('title')}")
            lines.append(f"- **URL:** {f.get('url')}")
            lines.append(f"- **Confidence:** {f.get('confidence', 0)*100:.0f}%")
            lines.append("")
        return "\n".join(lines)

    def _to_text(self, scan: dict, findings: list) -> str:
        lines = [f"SNAPESCAPE REPORT - {scan.get('target')}", "=" * 50, ""]
        for i, f in enumerate(findings, 1):
            lines.append(f"{i}. [{f.get('severity')}] {f.get('title')} - {f.get('url')}")
        return "\n".join(lines)
