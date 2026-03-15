"""Broken Authentication vulnerability scanner.

Detects common authentication weaknesses including missing security
headers, weak session management, exposed login endpoints, and
insecure transport configurations.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# Security headers that should be present
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS header missing — browser will allow HTTP downgrade",
        "remediation": (
            "Add header: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
        "cwe": "CWE-319",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "X-Content-Type-Options missing — browser may MIME-sniff responses",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options missing — page can be embedded in iframes (clickjacking)",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
        "cwe": "CWE-1021",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "Content-Security-Policy missing — no XSS mitigation at browser level",
        "remediation": (
            "Add a Content-Security-Policy header. Start with:\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'"
        ),
        "cwe": "CWE-693",
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "description": "X-XSS-Protection header missing (legacy, but still useful for older browsers)",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        "cwe": "CWE-79",
    },
}


class AuthScanner(BaseScanner):
    """Scanner for authentication and security header weaknesses.

    Checks for:
    1. Missing security-related HTTP headers
    2. Insecure cookie attributes (HttpOnly, Secure flags)
    3. HTTP to HTTPS redirect behavior
    4. Information disclosure via server headers
    """

    name = "auth"
    description = "Authentication & Security Headers Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for authentication and header vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []

        async with self._create_session() as session:
            status, body, headers = await self._fetch(session, target_url)
            if status == 0:
                return vulnerabilities

            # Check security headers
            header_vulns = self._check_security_headers(target_url, headers)
            vulnerabilities.extend(header_vulns)

            # Check cookie security
            cookie_vulns = self._check_cookie_security(target_url, headers)
            vulnerabilities.extend(cookie_vulns)

            # Check for server information disclosure
            info_vulns = self._check_info_disclosure(target_url, headers)
            vulnerabilities.extend(info_vulns)

            # Check HTTPS enforcement
            https_vulns = await self._check_https(session, target_url)
            vulnerabilities.extend(https_vulns)

        return vulnerabilities

    def _check_security_headers(
        self, target_url: str, headers: dict
    ) -> list[Vulnerability]:
        """Check for missing security headers."""
        vulns: list[Vulnerability] = []
        header_keys_lower = {k.lower(): k for k in headers}

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in header_keys_lower:
                vulns.append(
                    Vulnerability(
                        scanner=self.name,
                        title=f"Missing header: {header_name}",
                        severity=info["severity"],
                        url=target_url,
                        description=info["description"],
                        evidence=f"Header '{header_name}' not found in response",
                        remediation=info["remediation"],
                        cwe_id=info["cwe"],
                    )
                )
        return vulns

    def _check_cookie_security(
        self, target_url: str, headers: dict
    ) -> list[Vulnerability]:
        """Check cookies for HttpOnly and Secure flags."""
        vulns: list[Vulnerability] = []
        is_https = urlparse(target_url).scheme == "https"

        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue

            cookie_name = value.split("=")[0].strip()
            lower = value.lower()

            if "httponly" not in lower:
                vulns.append(
                    Vulnerability(
                        scanner=self.name,
                        title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                        severity="MEDIUM",
                        url=target_url,
                        description=(
                            f"The cookie '{cookie_name}' can be accessed by "
                            f"client-side JavaScript, making it vulnerable to "
                            f"XSS-based session hijacking."
                        ),
                        evidence=f"Set-Cookie: {value}",
                        remediation="Set the HttpOnly flag on all session cookies",
                        cwe_id="CWE-1004",
                    )
                )

            if is_https and "secure" not in lower:
                vulns.append(
                    Vulnerability(
                        scanner=self.name,
                        title=f"Cookie '{cookie_name}' missing Secure flag",
                        severity="MEDIUM",
                        url=target_url,
                        description=(
                            f"The cookie '{cookie_name}' on an HTTPS site "
                            f"does not have the Secure flag, meaning it could "
                            f"be transmitted over unencrypted HTTP."
                        ),
                        evidence=f"Set-Cookie: {value}",
                        remediation="Set the Secure flag on all cookies served over HTTPS",
                        cwe_id="CWE-614",
                    )
                )
        return vulns

    def _check_info_disclosure(
        self, target_url: str, headers: dict
    ) -> list[Vulnerability]:
        """Check for server version information disclosure."""
        vulns: list[Vulnerability] = []

        server = headers.get("Server", headers.get("server", ""))
        if server and re.search(r"\d+\.\d+", server):
            vulns.append(
                Vulnerability(
                    scanner=self.name,
                    title="Server version disclosed in headers",
                    severity="LOW",
                    url=target_url,
                    description=(
                        f"The server reveals its version ({server}), which "
                        f"helps attackers identify known vulnerabilities for "
                        f"that specific version."
                    ),
                    evidence=f"Server: {server}",
                    remediation=(
                        "Remove or obfuscate the Server header. In nginx: "
                        "server_tokens off; In Apache: ServerTokens Prod"
                    ),
                    cwe_id="CWE-200",
                )
            )

        x_powered = headers.get(
            "X-Powered-By", headers.get("x-powered-by", "")
        )
        if x_powered:
            vulns.append(
                Vulnerability(
                    scanner=self.name,
                    title="Technology stack disclosed via X-Powered-By",
                    severity="LOW",
                    url=target_url,
                    description=(
                        f"The X-Powered-By header reveals '{x_powered}', "
                        f"exposing the technology stack to potential attackers."
                    ),
                    evidence=f"X-Powered-By: {x_powered}",
                    remediation="Remove the X-Powered-By header from responses",
                    cwe_id="CWE-200",
                )
            )
        return vulns

    async def _check_https(
        self, session: aiohttp.ClientSession, target_url: str
    ) -> list[Vulnerability]:
        """Check if HTTP redirects to HTTPS."""
        vulns: list[Vulnerability] = []
        parsed = urlparse(target_url)

        if parsed.scheme == "https":
            # Test if HTTP version redirects
            http_url = target_url.replace("https://", "http://", 1)
            status, _, headers = await self._fetch(session, http_url)
            if status in (200, 0):
                # 200 means no redirect; 0 means connection issue
                if status == 200:
                    vulns.append(
                        Vulnerability(
                            scanner=self.name,
                            title="HTTP does not redirect to HTTPS",
                            severity="MEDIUM",
                            url=http_url,
                            description=(
                                "The HTTP version of this site serves content "
                                "instead of redirecting to HTTPS, allowing "
                                "potential man-in-the-middle attacks."
                            ),
                            evidence=f"HTTP {http_url} returned status 200",
                            remediation=(
                                "Configure your web server to redirect all "
                                "HTTP traffic to HTTPS (301 redirect)"
                            ),
                            cwe_id="CWE-319",
                        )
                    )
        return vulns
