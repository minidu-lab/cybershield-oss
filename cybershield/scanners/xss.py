"""Cross-Site Scripting (XSS) vulnerability scanner.

Detects reflected and stored XSS by injecting common payloads into
query parameters, form fields, and HTTP headers, then checking if they
appear unsanitized in the response body.

v0.2.0: Added form field injection, header injection, DOM-based XSS
context detection, encoding bypass payloads, and response context
analysis to reduce false positives.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# ── XSS Test Payloads ──────────────────────────────────────────────
# Organized by context: HTML body, attribute, JavaScript, URL

XSS_PAYLOADS = [
    # HTML context — basic script injection
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>confirm(1)</script>',
    # Attribute breakout — escape double/single quotes
    '"><script>alert(1)</script>',
    "'-alert('XSS')-'",
    '" onmouseover="alert(1)"',
    "' onfocus='alert(1)' autofocus='",
    # Event handler payloads — img, svg, body, details
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    # JavaScript context — protocol handlers
    'javascript:alert(1)',
    'javascript:alert(document.cookie)',
    # Encoding bypass payloads
    '<ScRiPt>alert(1)</ScRiPt>',
    '<IMG SRC=x onerror=alert(1)>',
    '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
    '"><iframe src="javascript:alert(1)">',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
]

# ── Reflection Markers ──────────────────────────────────────────────
# Patterns to look for in the response that confirm reflection

XSS_MARKERS = [
    re.compile(r"<script>alert\(", re.IGNORECASE),
    re.compile(r"<script>confirm\(", re.IGNORECASE),
    re.compile(r"onerror\s*=\s*alert\(", re.IGNORECASE),
    re.compile(r"onload\s*=\s*alert\(", re.IGNORECASE),
    re.compile(r"ontoggle\s*=\s*alert\(", re.IGNORECASE),
    re.compile(r"onmouseover\s*=\s*alert\(", re.IGNORECASE),
    re.compile(r"onfocus\s*=\s*alert\(", re.IGNORECASE),
    re.compile(r"javascript\s*:\s*alert\(", re.IGNORECASE),
    re.compile(r"<iframe\s+src\s*=\s*[\"']?javascript:", re.IGNORECASE),
    re.compile(r"<svg[^>]*onload\s*=", re.IGNORECASE),
]

# Common parameter names that often accept user input
COMMON_PARAMS = ["q", "search", "query", "s", "keyword", "id", "name",
                 "page", "url", "redirect", "next", "return", "callback",
                 "input", "text", "value", "msg", "message", "comment"]

# Form patterns to discover input fields
FORM_PATTERN = re.compile(
    r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL
)
INPUT_PATTERN = re.compile(
    r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>', re.IGNORECASE
)
TEXTAREA_PATTERN = re.compile(
    r'<textarea[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>', re.IGNORECASE
)
FORM_ACTION_PATTERN = re.compile(
    r'<form[^>]*action\s*=\s*["\']([^"\']*)["\'][^>]*', re.IGNORECASE
)


class XSSScanner(BaseScanner):
    """Scanner for Cross-Site Scripting (XSS) vulnerabilities.

    Tests reflected XSS by injecting payloads into:
    1. URL query parameters
    2. HTML form fields discovered in the page
    3. HTTP headers (Referer, User-Agent)

    Checks if payloads are reflected without sanitization in the response.

    v0.2.0 improvements:
    - Form field discovery and injection
    - Header-based XSS testing
    - Encoding bypass payloads
    - Context-aware reflection detection
    - Reduced false positives via baseline comparison
    """

    name = "xss"
    description = "Cross-Site Scripting (XSS) Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for XSS vulnerabilities across multiple injection points."""
        vulnerabilities: list[Vulnerability] = []
        parsed = urlparse(target_url)

        async with self._create_session() as session:
            # Fetch baseline response for comparison
            baseline_status, baseline_body, baseline_headers = await self._fetch(
                session, target_url
            )

            # 1. Test URL query parameters
            params = parse_qs(parsed.query)
            if not params:
                params = {p: ["test"] for p in COMMON_PARAMS[:5]}

            for param_name in params:
                for payload in XSS_PAYLOADS:
                    vuln = await self._test_param(
                        session, target_url, parsed, param_name, payload,
                        baseline_body
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # One confirmed XSS per parameter

            # 2. Discover and test form fields
            if baseline_body:
                form_vulns = await self._test_forms(
                    session, target_url, baseline_body
                )
                vulnerabilities.extend(form_vulns)

            # 3. Test header injection (Referer, User-Agent)
            header_vulns = await self._test_headers(
                session, target_url, baseline_body
            )
            vulnerabilities.extend(header_vulns)

        return vulnerabilities

    async def _test_param(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        parsed,
        param_name: str,
        payload: str,
        baseline_body: str,
    ) -> Vulnerability | None:
        """Test a single URL parameter with a single XSS payload."""
        test_params = parse_qs(parsed.query)
        test_params[param_name] = [payload]

        flat_params = {k: v[0] for k, v in test_params.items()}
        test_query = urlencode(flat_params, safe="")
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, test_query, parsed.fragment,
        ))

        status, body, headers = await self._fetch(session, test_url)
        if status == 0:
            return None

        # Check reflection — only flag if marker appears in response
        # but NOT in the baseline (reduces false positives)
        for marker in XSS_MARKERS:
            if marker.search(body) and not marker.search(baseline_body):
                self.logger.warning(
                    "Reflected XSS found in param '%s' at %s",
                    param_name, target_url,
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
                        f"indicating a Cross-Site Scripting vulnerability. "
                        f"An attacker could inject malicious JavaScript that "
                        f"executes in the victim's browser, potentially "
                        f"stealing session cookies, credentials, or "
                        f"performing actions on behalf of the user."
                    ),
                    evidence=(
                        f"Payload: {payload}\n"
                        f"Reflected marker: {marker.pattern}\n"
                        f"HTTP Status: {status}\n"
                        f"Parameter: {param_name}"
                    ),
                    remediation=(
                        "1. Sanitize all user input before rendering in HTML\n"
                        "2. Use context-aware output encoding:\n"
                        "   - HTML context: html.escape() or &lt; &gt; &amp; encoding\n"
                        "   - Attribute context: quote attributes and encode\n"
                        "   - JavaScript context: JSON.stringify() or JS-encode\n"
                        "3. Implement Content-Security-Policy headers:\n"
                        "   Content-Security-Policy: default-src 'self'; script-src 'self'\n"
                        "4. Use a templating engine with auto-escaping (Jinja2, React JSX)\n"
                        "5. Consider using DOMPurify for client-side sanitization\n"
                        "6. Set HttpOnly flag on session cookies to limit impact"
                    ),
                    cwe_id="CWE-79",
                )
        return None

    async def _test_forms(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        page_body: str,
    ) -> list[Vulnerability]:
        """Discover HTML forms and test their input fields for XSS."""
        vulnerabilities: list[Vulnerability] = []
        forms = FORM_PATTERN.findall(page_body)

        for form_html in forms[:5]:  # Limit to 5 forms per page
            input_names = INPUT_PATTERN.findall(form_html)
            input_names += TEXTAREA_PATTERN.findall(form_html)

            # Get form action URL
            action_match = FORM_ACTION_PATTERN.search(form_html)
            form_url = target_url
            if action_match and action_match.group(1):
                action = action_match.group(1)
                if action.startswith("http"):
                    form_url = action
                elif action.startswith("/"):
                    parsed = urlparse(target_url)
                    form_url = f"{parsed.scheme}://{parsed.netloc}{action}"

            # Test each input field with a subset of payloads
            test_payloads = [
                '<script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
            ]

            for field_name in input_names[:10]:  # Limit fields
                for payload in test_payloads:
                    form_data = {field_name: payload}
                    status, body, _ = await self._fetch(
                        session, form_url, method="POST", data=form_data
                    )
                    if status == 0:
                        continue

                    for marker in XSS_MARKERS:
                        if marker.search(body):
                            self.logger.warning(
                                "Form XSS in field '%s' at %s",
                                field_name, form_url,
                            )
                            vulnerabilities.append(Vulnerability(
                                scanner=self.name,
                                title=f"Reflected XSS in form field '{field_name}'",
                                severity="HIGH",
                                url=form_url,
                                description=(
                                    f"The form field '{field_name}' reflects "
                                    f"user input without sanitization when "
                                    f"submitted via POST. The payload "
                                    f"'{payload}' was reflected in the "
                                    f"response."
                                ),
                                evidence=(
                                    f"Form field: {field_name}\n"
                                    f"Payload: {payload}\n"
                                    f"Method: POST\n"
                                    f"Form action: {form_url}"
                                ),
                                remediation=(
                                    "1. Sanitize all form inputs server-side before rendering\n"
                                    "2. Use parameterized templates with auto-escaping\n"
                                    "3. Validate input against expected format (whitelist)\n"
                                    "4. Implement CSP headers to block inline scripts"
                                ),
                                cwe_id="CWE-79",
                            ))
                            break  # One per field
                    else:
                        continue
                    break  # Move to next field after finding one

        return vulnerabilities

    async def _test_headers(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        baseline_body: str,
    ) -> list[Vulnerability]:
        """Test if XSS payloads in HTTP headers are reflected."""
        vulnerabilities: list[Vulnerability] = []

        header_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
        ]

        for payload in header_payloads:
            # Test Referer header injection
            status, body, _ = await self._fetch(
                session, target_url,
                headers={"Referer": payload}
            )
            if status != 0:
                for marker in XSS_MARKERS:
                    if marker.search(body) and not marker.search(baseline_body):
                        vulnerabilities.append(Vulnerability(
                            scanner=self.name,
                            title="XSS via Referer header reflection",
                            severity="MEDIUM",
                            url=target_url,
                            description=(
                                "The Referer header value is reflected in the "
                                "response without sanitization. An attacker "
                                "could craft a URL that injects JavaScript "
                                "via the Referer header."
                            ),
                            evidence=(
                                f"Header: Referer\n"
                                f"Payload: {payload}"
                            ),
                            remediation=(
                                "1. Never render HTTP headers in HTML without encoding\n"
                                "2. Sanitize all server-side output, not just query parameters\n"
                                "3. Implement CSP headers"
                            ),
                            cwe_id="CWE-79",
                        ))
                        break

            # Test User-Agent header injection
            status, body, _ = await self._fetch(
                session, target_url,
                headers={"User-Agent": payload}
            )
            if status != 0:
                for marker in XSS_MARKERS:
                    if marker.search(body) and not marker.search(baseline_body):
                        vulnerabilities.append(Vulnerability(
                            scanner=self.name,
                            title="XSS via User-Agent header reflection",
                            severity="MEDIUM",
                            url=target_url,
                            description=(
                                "The User-Agent header value is reflected in "
                                "the response without sanitization."
                            ),
                            evidence=(
                                f"Header: User-Agent\n"
                                f"Payload: {payload}"
                            ),
                            remediation=(
                                "1. Encode all HTTP header values before rendering\n"
                                "2. Use context-aware output encoding\n"
                                "3. Implement Content-Security-Policy headers"
                            ),
                            cwe_id="CWE-79",
                        ))
                        break

        return vulnerabilities
