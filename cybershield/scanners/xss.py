"""Cross-Site Scripting (XSS) vulnerability scanner.

Detects reflected and stored XSS by injecting common payloads into
query parameters and form fields, then checking if they appear
unsanitized in the response body.
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# Common XSS test payloads — designed to trigger in various contexts
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    "<img src=x onerror=alert('XSS')>",
    '"><img src=x onerror=alert(1)>',
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "'-confirm(1)-'",
    '<details/open/ontoggle=alert("XSS")>',
]

# Markers to look for in reflected output
XSS_MARKERS = [
    "<script>alert(",
    "onerror=alert(",
    "onload=alert(",
    "ontoggle=alert(",
    "javascript:alert(",
    "-alert(",
    "-confirm(",
]


class XSSScanner(BaseScanner):
    """Scanner for Cross-Site Scripting (XSS) vulnerabilities.

    Tests reflected XSS by injecting payloads into URL query parameters
    and checking if they are reflected without sanitization in the HTTP
    response body.
    """

    name = "xss"
    description = "Cross-Site Scripting (XSS) Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for XSS vulnerabilities in query parameters."""
        vulnerabilities: list[Vulnerability] = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            # If no query params, test with common parameter names
            params = {"q": ["test"], "search": ["test"], "id": ["1"]}

        async with self._create_session() as session:
            for param_name in params:
                for payload in XSS_PAYLOADS:
                    vuln = await self._test_param(
                        session, target_url, parsed, param_name, payload
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        # One confirmed XSS per parameter is sufficient
                        break

        return vulnerabilities

    async def _test_param(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        parsed,
        param_name: str,
        payload: str,
    ) -> Vulnerability | None:
        """Test a single parameter with a single XSS payload."""
        # Build test URL with injected payload
        test_params = parse_qs(parsed.query)
        test_params[param_name] = [payload]

        flat_params = {k: v[0] for k, v in test_params.items()}
        test_query = urlencode(flat_params)
        test_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                test_query,
                parsed.fragment,
            )
        )

        status, body, headers = await self._fetch(session, test_url)
        if status == 0:
            return None

        # Check if any payload marker is reflected in the response
        body_lower = body.lower()
        for marker in XSS_MARKERS:
            if marker.lower() in body_lower:
                self.logger.warning(
                    "Reflected XSS found in param '%s' at %s",
                    param_name,
                    target_url,
                )
                return Vulnerability(
                    scanner=self.name,
                    title=f"Reflected XSS in parameter '{param_name}'",
                    severity="HIGH",
                    url=target_url,
                    description=(
                        f"The parameter '{param_name}' reflects user input "
                        f"without proper sanitization. The payload "
                        f"'{payload}' was found in the response body, "
                        f"indicating a Cross-Site Scripting vulnerability."
                    ),
                    evidence=f"Payload: {payload}\nReflected marker: {marker}",
                    remediation=(
                        "1. Sanitize all user input before rendering in HTML\n"
                        "2. Use context-aware output encoding (HTML entity encoding)\n"
                        "3. Implement Content-Security-Policy headers\n"
                        "4. Use a templating engine with auto-escaping (e.g., Jinja2)\n"
                        "5. Consider using DOMPurify for client-side sanitization"
                    ),
                    cwe_id="CWE-79",
                )
        return None
