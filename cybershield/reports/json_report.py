"""JSON report generator for CyberShield scan results."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

from cybershield.reports.base import BaseReport

if TYPE_CHECKING:
    from cybershield.core import ScanResult


class JSONReportGenerator(BaseReport):
    """Generates structured JSON scan reports for programmatic consumption."""

    format_name = "json"
    file_extension = ".json"

    def _render(self, result: ScanResult) -> str:
        """Render a JSON report from scan results."""
        report = {
            "cybershield_version": "0.1.0",
            "scan": {
                "target_url": result.target_url,
                "start_time": datetime.fromtimestamp(
                    result.start_time
                ).isoformat(),
                "end_time": datetime.fromtimestamp(
                    result.end_time
                ).isoformat(),
                "duration_seconds": round(result.duration, 2),
                "modules_used": result.modules_used,
                "urls_scanned": result.urls_scanned,
            },
            "summary": result.summary,
            "total_findings": len(result.vulnerabilities),
            "vulnerabilities": [
                {
                    "scanner": v.scanner,
                    "title": v.title,
                    "severity": v.severity,
                    "url": v.url,
                    "description": v.description,
                    "evidence": v.evidence or None,
                    "remediation": v.remediation or None,
                    "cwe_id": v.cwe_id,
                    "ai_explanation": v.ai_explanation,
                }
                for v in result.sorted_vulnerabilities()
            ],
            "errors": result.errors,
        }

        return json.dumps(report, indent=2, ensure_ascii=False)
