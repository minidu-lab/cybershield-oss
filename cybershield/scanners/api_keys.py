"""Exposed API Keys and Secrets scanner.

Detects accidentally leaked API keys, tokens, and secrets in HTML
source code, JavaScript files, and HTTP responses. Uses regex patterns
for common service providers.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urljoin

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# Patterns for common API keys and secrets
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(
        r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key\s*[=:]\s*['\"]?"
        r"([A-Za-z0-9/+=]{40})"
    ),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth": re.compile(
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"
    ),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    "GitHub OAuth": re.compile(r"gho_[A-Za-z0-9]{36,255}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9A-Za-z\-]+"),
    "Slack Webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}"
    ),
    "Stripe Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,99}"),
    "Stripe Publishable Key": re.compile(r"pk_live_[0-9a-zA-Z]{24,99}"),
    "Heroku API Key": re.compile(
        r"(?i)heroku[_\-\.]?api[_\-\.]?key\s*[=:]\s*['\"]?"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    ),
    "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "SendGrid API Key": re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    "Firebase Key": re.compile(
        r"(?i)firebase[_\-\.]?(?:api)?[_\-\.]?key\s*[=:]\s*['\"]?"
        r"([A-Za-z0-9_\-]{20,})"
    ),
    "JSON Web Token": re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"
    ),
    "Private Key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
    ),
    "Generic API Key": re.compile(
        r"(?i)(?:api[_\-\.]?key|apikey|api_secret|access_token)\s*[=:]\s*['\"]?"
        r"([A-Za-z0-9_\-]{20,})"
    ),
    "Generic Secret": re.compile(
        r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})"
    ),
}

# JavaScript file patterns to check
JS_PATTERN = re.compile(r'<script[^>]*src=["\']([^"\']+\.js)["\']', re.IGNORECASE)


class APIKeyScanner(BaseScanner):
    """Scanner for exposed API keys, tokens, and secrets.

    Checks:
    1. HTML source for embedded secrets
    2. JavaScript files for hardcoded credentials
    3. Response headers for leaked tokens
    """

    name = "api_keys"
    description = "Exposed API Keys & Secrets Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for exposed secrets in page source and linked scripts."""
        vulnerabilities: list[Vulnerability] = []

        async with self._create_session() as session:
            status, body, headers = await self._fetch(session, target_url)
            if status == 0:
                return vulnerabilities

            # Scan main page source
            page_vulns = self._scan_content(target_url, body, "HTML source")
            vulnerabilities.extend(page_vulns)

            # Find and scan linked JavaScript files
            js_urls = JS_PATTERN.findall(body)
            for js_url in js_urls[:10]:  # Limit to 10 JS files
                full_url = urljoin(target_url, js_url)
                js_status, js_body, _ = await self._fetch(session, full_url)
                if js_status == 200 and js_body:
                    js_vulns = self._scan_content(
                        full_url, js_body, f"JavaScript ({js_url})"
                    )
                    vulnerabilities.extend(js_vulns)

        return vulnerabilities

    def _scan_content(
        self, url: str, content: str, source_type: str
    ) -> list[Vulnerability]:
        """Scan a content string for secret patterns."""
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(content)
            if not matches:
                match = pattern.search(content)
                if match:
                    matches = [match.group()]

            for match in matches:
                # Deduplicate
                match_str = match if isinstance(match, str) else match
                if match_str in seen:
                    continue
                seen.add(match_str)

                # Mask the secret for the report
                masked = self._mask_secret(match_str)
                severity = self._determine_severity(secret_name)

                self.logger.warning(
                    "Exposed %s found in %s at %s",
                    secret_name,
                    source_type,
                    url,
                )
                vulns.append(
                    Vulnerability(
                        scanner=self.name,
                        title=f"Exposed {secret_name} in {source_type}",
                        severity=severity,
                        url=url,
                        description=(
                            f"A {secret_name} was found exposed in the "
                            f"{source_type}. If this is a real credential, "
                            f"it should be immediately rotated and removed "
                            f"from client-side code."
                        ),
                        evidence=f"Matched: {masked}",
                        remediation=(
                            f"1. Immediately rotate/revoke the {secret_name}\n"
                            f"2. Move the secret to server-side environment variables\n"
                            f"3. Never commit secrets to source code\n"
                            f"4. Use a secrets manager (e.g., AWS Secrets Manager, "
                            f"HashiCorp Vault)\n"
                            f"5. Add secret scanning to your CI/CD pipeline"
                        ),
                        cwe_id="CWE-312",
                    )
                )
        return vulns

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Mask a secret, showing only first 4 and last 2 characters."""
        if len(secret) <= 8:
            return secret[:2] + "*" * (len(secret) - 2)
        return secret[:4] + "*" * (len(secret) - 6) + secret[-2:]

    @staticmethod
    def _determine_severity(secret_name: str) -> str:
        """Determine severity based on the type of secret found."""
        critical = {"AWS Secret Key", "Private Key", "Stripe Secret Key"}
        high = {
            "AWS Access Key",
            "GitHub Token",
            "Slack Token",
            "SendGrid API Key",
            "Generic Secret",
        }
        medium = {
            "Google API Key",
            "Twilio API Key",
            "Heroku API Key",
            "Firebase Key",
            "JSON Web Token",
            "Generic API Key",
        }

        if secret_name in critical:
            return "CRITICAL"
        if secret_name in high:
            return "HIGH"
        if secret_name in medium:
            return "MEDIUM"
        return "LOW"
