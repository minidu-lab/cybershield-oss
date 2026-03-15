"""Core scanner orchestrator for CyberShield OSS."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from cybershield.config import Config
from cybershield.scanners.xss import XSSScanner
from cybershield.scanners.sqli import SQLiScanner
from cybershield.scanners.csrf import CSRFScanner
from cybershield.scanners.auth import AuthScanner
from cybershield.scanners.api_keys import APIKeyScanner
from cybershield.ai.explainer import VulnerabilityExplainer
from cybershield.reports.html import HTMLReportGenerator
from cybershield.reports.json_report import JSONReportGenerator
from cybershield.utils.logger import setup_logger

logger = logging.getLogger(__name__)

# Registry of available scanner modules
SCANNER_REGISTRY = {
    "xss": XSSScanner,
    "sqli": SQLiScanner,
    "csrf": CSRFScanner,
    "auth": AuthScanner,
    "api_keys": APIKeyScanner,
}

REPORT_GENERATORS = {
    "html": HTMLReportGenerator,
    "json": JSONReportGenerator,
}


@dataclass
class Vulnerability:
    """Represents a single detected vulnerability."""

    scanner: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    ai_explanation: Optional[str] = None

    @property
    def severity_rank(self) -> int:
        """Numeric severity for sorting (lower = more severe)."""
        ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return ranks.get(self.severity, 5)


@dataclass
class ScanResult:
    """Aggregated results from a full scan."""

    target_url: str
    start_time: float
    end_time: float = 0.0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    urls_scanned: int = 0
    modules_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Scan duration in seconds."""
        return self.end_time - self.start_time

    @property
    def summary(self) -> dict[str, int]:
        """Count of vulnerabilities by severity."""
        counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for vuln in self.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts

    def sorted_vulnerabilities(self) -> list[Vulnerability]:
        """Return vulnerabilities sorted by severity (most severe first)."""
        return sorted(self.vulnerabilities, key=lambda v: v.severity_rank)


class CyberShield:
    """Main scanner orchestrator.

    Coordinates multiple vulnerability scanners and optionally enriches
    findings with AI-powered explanations via Claude.

    Usage:
        scanner = CyberShield(api_key="sk-ant-...")
        results = scanner.scan("https://example.com", modules=["xss", "sqli"])
        for vuln in results.vulnerabilities:
            print(vuln.title, vuln.severity)
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        api_key: Optional[str] = None,
    ):
        if config is None:
            config = Config.from_env()
        if api_key:
            config.anthropic_api_key = api_key

        self.config = config
        self._logger = setup_logger(config.log_level)

        # Validate config
        warnings = config.validate()
        for w in warnings:
            self._logger.warning(w)

        # Initialize AI explainer if API key is available
        self._explainer: Optional[VulnerabilityExplainer] = None
        if config.anthropic_api_key:
            self._explainer = VulnerabilityExplainer(config)

    def scan(
        self,
        target_url: str,
        modules: Optional[list[str]] = None,
        ai_explain: bool = False,
        depth: Optional[int] = None,
    ) -> ScanResult:
        """Run a synchronous scan against the target URL.

        Args:
            target_url: The URL to scan.
            modules: List of scanner modules to use. Use ["all"] or None for all.
            ai_explain: Whether to generate AI explanations for findings.
            depth: Max crawl depth (overrides config).

        Returns:
            ScanResult with all findings.
        """
        return asyncio.run(
            self.scan_async(target_url, modules, ai_explain, depth)
        )

    async def scan_async(
        self,
        target_url: str,
        modules: Optional[list[str]] = None,
        ai_explain: bool = False,
        depth: Optional[int] = None,
    ) -> ScanResult:
        """Run an asynchronous scan against the target URL."""
        # Validate URL
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Invalid URL scheme '{parsed.scheme}'. Use http:// or https://"
            )

        # Determine which modules to run
        if modules is None or modules == ["all"]:
            active_modules = list(SCANNER_REGISTRY.keys())
        else:
            active_modules = []
            for mod in modules:
                if mod not in SCANNER_REGISTRY:
                    raise ValueError(
                        f"Unknown scanner module '{mod}'. "
                        f"Available: {list(SCANNER_REGISTRY.keys())}"
                    )
                active_modules.append(mod)

        self._logger.info(
            "Starting scan of %s with modules: %s",
            target_url,
            ", ".join(active_modules),
        )

        result = ScanResult(
            target_url=target_url,
            start_time=time.time(),
            modules_used=active_modules,
        )

        # Initialize and run scanners
        scanners = [
            SCANNER_REGISTRY[mod](self.config) for mod in active_modules
        ]

        tasks = [scanner.scan(target_url) for scanner in scanners]
        scanner_results = await asyncio.gather(*tasks, return_exceptions=True)

        for mod_name, scan_output in zip(active_modules, scanner_results):
            if isinstance(scan_output, Exception):
                error_msg = f"Scanner '{mod_name}' failed: {scan_output}"
                self._logger.error(error_msg)
                result.errors.append(error_msg)
            else:
                result.vulnerabilities.extend(scan_output)
                self._logger.info(
                    "Scanner '%s' found %d issue(s)",
                    mod_name,
                    len(scan_output),
                )

        # AI enrichment
        if ai_explain and self._explainer:
            self._logger.info("Generating AI explanations for %d findings...", len(result.vulnerabilities))
            for vuln in result.vulnerabilities:
                try:
                    vuln.ai_explanation = await self._explainer.explain(vuln)
                except Exception as e:
                    self._logger.warning(
                        "AI explanation failed for '%s': %s", vuln.title, e
                    )

        result.end_time = time.time()
        self._logger.info(
            "Scan complete in %.1fs — %d vulnerabilities found",
            result.duration,
            len(result.vulnerabilities),
        )
        return result

    def generate_report(
        self,
        result: ScanResult,
        format: str = "html",
        output_path: Optional[str] = None,
    ) -> str:
        """Generate a report from scan results.

        Args:
            result: The scan results to report on.
            format: Report format ('html' or 'json').
            output_path: Where to save the report. Auto-generated if None.

        Returns:
            Path to the generated report file.
        """
        if format not in REPORT_GENERATORS:
            raise ValueError(
                f"Unknown report format '{format}'. "
                f"Available: {list(REPORT_GENERATORS.keys())}"
            )
        generator = REPORT_GENERATORS[format](self.config)
        return generator.generate(result, output_path)
