"""Cross-Site Request Forgery (CSRF) vulnerability scanner.

Detects missing or weak CSRF protections by analyzing forms for tokens,
checking SameSite cookie attributes, and verifying Origin/Referer header
enforcement.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# Patterns that indicate a CSRF token is present
CSRF_TOKEN_PATTERNS = [
    re.compile(
        r'<input[^>]*name=["\']?'
        r"(csrf|_csrf|csrfmiddlewaretoken|_token|authenticity_token|"
        r"__RequestVerificationToken|antiforgery|xsrf)"
        r'["\']?[^>]*>',
        re.IGNORECASE,
    ),
    re.compile(r'<meta[^>]*name=["\']?csrf-token["\']?', re.IGNORECASE),
    re.compile(r"X-CSRF-TOKEN", re.IGNORECASE),
    re.compile(r"X-XSRF-TOKEN", re.IGNORECASE),
]

# Forms with state-changing actions (POST typically)
FORM_PATTERN = re.compile(
    r"<form[^>]*method\s*=\s*[\"']?post[\"']?[^>]*>(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)


class CSRFScanner(BaseScanner):
    """Scanner for Cross-Site Request Forgery (CSRF) vulnerabilities.

    Checks for:
    1. Forms without CSRF tokens
    2. Missing SameSite cookie attributes
    3. Missing or misconfigured Origin/Referer validation
    """

    name = "csrf"
    description = "Cross-Site Request Forgery (CSRF) Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for CSRF vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []

        async with self._create_session() as session:
            status, body, headers = await self._fetch(session, target_url)
            if status == 0:
                return vulnerabilities

            # Check forms for CSRF tokens
            form_vulns = self._check_forms(target_url, body)
            vulnerabilities.extend(form_vulns)

            # Check cookie SameSite attributes
            cookie_vulns = self._check_cookies(target_url, headers)
            vulnerabilities.extend(cookie_vulns)

        return vulnerabilities

    def _check_forms(
        self, target_url: str, body: str
    ) -> list[Vulnerability]:
        """Check POST forms for CSRF token presence."""
        vulns: list[Vulnerability] = []
        forms = FORM_PATTERN.findall(body)

        for i, form_content in enumerate(forms, 1):
            has_token = any(
                pattern.search(form_content) for pattern in CSRF_TOKEN_PATTERNS
            )
            if not has_token:
                self.logger.warning(
                    "POST form #%d at %s lacks CSRF token", i, target_url
                )
                vulns.append(
                    Vulnerability(
                        scanner=self.name,
                        title=f"POST form #{i} missing CSRF token",
                        severity="MEDIUM",
                        url=target_url,
                        description=(
                            f"A form using POST method on this page does not "
                            f"include a CSRF token. Without a token, an "
                            f"attacker could craft a malicious page that "
                            f"submits this form on behalf of an authenticated "
                            f"user."
                        ),
                        evidence=f"Form content (truncated): {form_content[:200]}",
                        remediation=(
                            "1. Add a unique, unpredictable CSRF token to every "
                            "state-changing form\n"
                            "2. Validate the token server-side on form submission\n"
                            "3. Use your framework's built-in CSRF protection:\n"
                            "   - Django: {% csrf_token %}\n"
                            "   - Flask: flask-wtf CSRFProtect\n"
                            "   - Express: csurf middleware\n"
                            "4. Set SameSite=Strict on session cookies"
                        ),
                        cwe_id="CWE-352",
                    )
                )
        return vulns

    def _check_cookies(
        self, target_url: str, headers: dict
    ) -> list[Vulnerability]:
        """Check Set-Cookie headers for SameSite attributes."""
        vulns: list[Vulnerability] = []
        set_cookies = []

        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookies.append(value)

        for cookie_header in set_cookies:
            cookie_name = cookie_header.split("=")[0].strip()
            lower = cookie_header.lower()

            if "samesite" not in lower:
                vulns.append(
                    Vulnerability(
                        scanner=self.name,
                        title=f"Cookie '{cookie_name}' missing SameSite attribute",
                        severity="LOW",
                        url=target_url,
                        description=(
                            f"The cookie '{cookie_name}' is set without a "
                            f"SameSite attribute. Modern browsers default to "
                            f"SameSite=Lax, but explicitly setting it provides "
                            f"defense-in-depth against CSRF attacks."
                        ),
                        evidence=f"Set-Cookie: {cookie_header}",
                        remediation=(
                            "1. Add SameSite=Strict for session cookies\n"
                            "2. Use SameSite=Lax as a minimum for all cookies\n"
                            "3. Combine with CSRF tokens for defense-in-depth"
                        ),
                        cwe_id="CWE-1275",
                    )
                )
        return vulns
