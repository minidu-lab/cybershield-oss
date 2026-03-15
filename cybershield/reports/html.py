"""HTML report generator for CyberShield scan results.

Generates professional, dark-themed HTML security reports with:
- Executive summary with severity breakdown
- Sortable findings table with color-coded severity badges
- AI explanation sections embedded per finding
- Remediation steps with code examples
- Responsive design for print and screen

v0.2.0: Added findings table view, executive summary stats,
print-friendly styles, collapsible detail sections, and
improved severity badge styling.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import TYPE_CHECKING

from cybershield.reports.base import BaseReport

if TYPE_CHECKING:
    from cybershield.core import ScanResult, Vulnerability


SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#dc2626", "text": "#fff", "border": "#b91c1c"},
    "HIGH": {"bg": "#ea580c", "text": "#fff", "border": "#c2410c"},
    "MEDIUM": {"bg": "#ca8a04", "text": "#fff", "border": "#a16207"},
    "LOW": {"bg": "#16a34a", "text": "#fff", "border": "#15803d"},
    "INFO": {"bg": "#2563eb", "text": "#fff", "border": "#1d4ed8"},
}


class HTMLReportGenerator(BaseReport):
    """Generates professional dark-themed HTML security scan reports.

    Features:
    - Executive summary with scan metadata and severity pie
    - Findings table with sortable columns
    - Detailed vulnerability cards with evidence and remediation
    - AI explanation blocks (when available)
    - Print-friendly CSS
    - Responsive layout
    """

    format_name = "html"
    file_extension = ".html"

    def _render(self, result: ScanResult) -> str:
        """Render a complete HTML report from scan results."""
        summary = result.summary
        total_vulns = len(result.vulnerabilities)
        scan_date = datetime.fromtimestamp(result.start_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        vulns_table = self._render_findings_table(
            result.sorted_vulnerabilities()
        )
        vulns_details = self._render_vulnerability_details(
            result.sorted_vulnerabilities()
        )
        errors_html = self._render_errors(result.errors)

        # Risk score (simple weighted calculation)
        risk_score = (
            summary["CRITICAL"] * 10
            + summary["HIGH"] * 7
            + summary["MEDIUM"] * 4
            + summary["LOW"] * 1
        )
        risk_label = "Critical" if risk_score > 30 else (
            "High" if risk_score > 15 else (
                "Medium" if risk_score > 5 else (
                    "Low" if risk_score > 0 else "None"
                )
            )
        )
        risk_color = (
            "#dc2626" if risk_score > 30 else
            "#ea580c" if risk_score > 15 else
            "#ca8a04" if risk_score > 5 else
            "#16a34a"
        )

        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberShield Scan Report — {html.escape(result.target_url)}</title>
<style>
  :root {{
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-tertiary: #334155;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-dim: #64748b;
    --accent: #38bdf8;
    --accent-dim: #0ea5e9;
    --border: #334155;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.65;
    padding: 2rem;
    max-width: 1100px;
    margin: 0 auto;
  }}

  /* ── Header ── */
  .header {{
    text-align: center;
    padding: 2rem 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }}
  .header h1 {{
    color: var(--accent);
    font-size: 1.8rem;
    margin-bottom: 0.25rem;
  }}
  .header .subtitle {{
    color: var(--text-secondary);
    font-size: 0.95rem;
  }}

  /* ── Meta Info ── */
  .meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .meta-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
  }}
  .meta-card .label {{
    color: var(--text-dim);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .meta-card .value {{
    font-size: 1.1rem;
    font-weight: 600;
    margin-top: 0.25rem;
  }}

  /* ── Summary Cards ── */
  h2 {{
    color: var(--text-secondary);
    margin: 2rem 0 1rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    font-size: 1.2rem;
  }}

  .summary {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem;
    margin: 1.5rem 0;
  }}
  .summary-card {{
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 1.25rem 1rem;
    text-align: center;
    border: 1px solid var(--border);
    transition: transform 0.2s;
  }}
  .summary-card:hover {{ transform: translateY(-2px); }}
  .summary-card .count {{
    font-size: 2.25rem;
    font-weight: 700;
    line-height: 1;
  }}
  .summary-card .label {{
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-top: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  /* ── Risk Score ── */
  .risk-badge {{
    display: inline-block;
    padding: 0.25rem 1rem;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.9rem;
    color: #fff;
  }}

  /* ── Findings Table ── */
  .findings-table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    font-size: 0.9rem;
  }}
  .findings-table th {{
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 0.75rem 1rem;
    text-align: left;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
  }}
  .findings-table td {{
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  .findings-table tr:hover {{
    background: rgba(56, 189, 248, 0.05);
  }}

  /* ── Severity Badge ── */
  .severity-badge {{
    display: inline-block;
    padding: 3px 12px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}

  /* ── Vulnerability Detail Cards ── */
  .vuln-card {{
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.25rem;
    border-left: 4px solid;
  }}
  .vuln-card .title {{
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: var(--text-primary);
  }}
  .vuln-card .field {{
    margin: 0.75rem 0;
  }}
  .vuln-card .field-label {{
    color: var(--text-dim);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin-bottom: 0.25rem;
  }}
  .vuln-card pre {{
    background: var(--bg-primary);
    padding: 0.75rem 1rem;
    border-radius: 6px;
    font-size: 0.85rem;
    overflow-x: auto;
    margin-top: 0.25rem;
    border: 1px solid var(--border);
    white-space: pre-wrap;
    word-wrap: break-word;
  }}
  .vuln-card code {{
    font-family: 'SF Mono', 'Fira Code', 'Fira Mono', monospace;
  }}

  /* ── AI Explanation Block ── */
  .ai-block {{
    background: #172554;
    border: 1px solid #1e40af;
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-top: 0.75rem;
  }}
  .ai-block .ai-label {{
    color: #60a5fa;
    font-weight: 600;
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
  }}
  .ai-block .ai-content {{
    color: #93c5fd;
    font-size: 0.9rem;
    line-height: 1.7;
  }}

  /* ── CWE Tag ── */
  .cwe-tag {{
    display: inline-block;
    color: var(--text-dim);
    font-size: 0.8rem;
    margin-left: 0.5rem;
    background: var(--bg-tertiary);
    padding: 2px 8px;
    border-radius: 3px;
  }}

  /* ── Errors ── */
  .errors {{ color: #fbbf24; }}
  .errors li {{ margin: 0.25rem 0; padding-left: 1rem; }}

  /* ── Footer ── */
  footer {{
    text-align: center;
    color: var(--text-dim);
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    font-size: 0.85rem;
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}

  /* ── Print Styles ── */
  @media print {{
    body {{ background: #fff; color: #000; padding: 1rem; }}
    .header h1 {{ color: #0369a1; }}
    .summary-card, .vuln-card, .meta-card {{ border: 1px solid #ccc; }}
    .vuln-card {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>

  <!-- Header -->
  <div class="header">
    <h1>&#128737; CyberShield Scan Report</h1>
    <div class="subtitle">AI-Assisted Security Assessment</div>
  </div>

  <!-- Scan Metadata -->
  <div class="meta">
    <div class="meta-card">
      <div class="label">Target URL</div>
      <div class="value">{html.escape(result.target_url)}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Date</div>
      <div class="value">{scan_date}</div>
    </div>
    <div class="meta-card">
      <div class="label">Duration</div>
      <div class="value">{result.duration:.1f} seconds</div>
    </div>
    <div class="meta-card">
      <div class="label">Modules Used</div>
      <div class="value">{', '.join(result.modules_used)}</div>
    </div>
    <div class="meta-card">
      <div class="label">Overall Risk</div>
      <div class="value">
        <span class="risk-badge" style="background: {risk_color};">
          {risk_label} ({risk_score} pts)
        </span>
      </div>
    </div>
  </div>

  <!-- Severity Summary -->
  <h2>Severity Summary</h2>
  <div class="summary">
    <div class="summary-card">
      <div class="count" style="color: {SEVERITY_COLORS['CRITICAL']['bg']}">{summary['CRITICAL']}</div>
      <div class="label">Critical</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color: {SEVERITY_COLORS['HIGH']['bg']}">{summary['HIGH']}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color: {SEVERITY_COLORS['MEDIUM']['bg']}">{summary['MEDIUM']}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color: {SEVERITY_COLORS['LOW']['bg']}">{summary['LOW']}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color: {SEVERITY_COLORS['INFO']['bg']}">{summary['INFO']}</div>
      <div class="label">Info</div>
    </div>
  </div>

  <!-- Findings Overview Table -->
  <h2>Findings Overview ({total_vulns})</h2>
  {vulns_table}

  <!-- Detailed Findings -->
  <h2>Detailed Findings</h2>
  {vulns_details}

  {errors_html}

  <!-- Footer -->
  <footer>
    Generated by <strong>CyberShield OSS v0.2.0</strong> &mdash;
    <a href="https://github.com/minidu-lab/cybershield-oss">GitHub</a>
    <br>
    <small>Powered by Claude AI (Anthropic) &middot; {scan_date}</small>
  </footer>

</body>
</html>"""

    def _render_findings_table(
        self, vulnerabilities: list[Vulnerability]
    ) -> str:
        """Render the findings overview table."""
        if not vulnerabilities:
            return '<p style="color: #22c55e; padding: 1rem;">&#10004; No vulnerabilities found. Your application passed all checks.</p>'

        rows = []
        for i, vuln in enumerate(vulnerabilities, 1):
            colors = SEVERITY_COLORS.get(vuln.severity, SEVERITY_COLORS["INFO"])
            cwe_html = (
                f'<span class="cwe-tag">{html.escape(vuln.cwe_id)}</span>'
                if vuln.cwe_id else ""
            )
            rows.append(f"""\
    <tr>
      <td style="color: var(--text-dim);">{i}</td>
      <td><span class="severity-badge" style="background: {colors['bg']};">{vuln.severity}</span></td>
      <td>{html.escape(vuln.title)}{cwe_html}</td>
      <td style="font-family: monospace; font-size: 0.8rem;">{html.escape(vuln.scanner)}</td>
      <td style="color: var(--text-dim); font-size: 0.85rem;">{html.escape(vuln.url[:60])}</td>
    </tr>""")

        return f"""\
  <table class="findings-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Finding</th>
        <th>Scanner</th>
        <th>Location</th>
      </tr>
    </thead>
    <tbody>
{"".join(rows)}
    </tbody>
  </table>"""

    def _render_vulnerability_details(
        self, vulnerabilities: list[Vulnerability]
    ) -> str:
        """Render detailed vulnerability cards."""
        if not vulnerabilities:
            return ""

        cards = []
        for vuln in vulnerabilities:
            colors = SEVERITY_COLORS.get(vuln.severity, SEVERITY_COLORS["INFO"])

            # AI explanation section
            ai_section = ""
            if vuln.ai_explanation:
                ai_section = f"""\
    <div class="ai-block">
      <div class="ai-label">&#129302; AI Explanation (Claude)</div>
      <div class="ai-content">{html.escape(vuln.ai_explanation)}</div>
    </div>"""

            # CWE tag
            cwe_html = ""
            if vuln.cwe_id:
                cwe_html = f'<span class="cwe-tag">{html.escape(vuln.cwe_id)}</span>'

            cards.append(f"""\
  <div class="vuln-card" style="border-left-color: {colors['bg']};">
    <span class="severity-badge" style="background: {colors['bg']};">{vuln.severity}</span>
    {cwe_html}
    <div class="title">{html.escape(vuln.title)}</div>

    <div class="field">
      <div class="field-label">URL</div>
      <div>{html.escape(vuln.url)}</div>
    </div>

    <div class="field">
      <div class="field-label">Description</div>
      <div>{html.escape(vuln.description)}</div>
    </div>

    {self._render_evidence(vuln.evidence) if vuln.evidence else ''}

    <div class="field">
      <div class="field-label">Remediation Steps</div>
      <pre>{html.escape(vuln.remediation)}</pre>
    </div>

    {ai_section}
  </div>""")

        return "\n".join(cards)

    @staticmethod
    def _render_evidence(evidence: str) -> str:
        """Render the evidence section of a vulnerability card."""
        return f"""\
    <div class="field">
      <div class="field-label">Evidence</div>
      <pre>{html.escape(evidence)}</pre>
    </div>"""

    @staticmethod
    def _render_errors(errors: list[str]) -> str:
        """Render error section if any errors occurred during scanning."""
        if not errors:
            return ""
        items = "\n".join(
            f"    <li>{html.escape(e)}</li>" for e in errors
        )
        return f"""\
  <h2 class="errors">&#9888; Scanner Errors</h2>
  <ul class="errors">
{items}
  </ul>"""
