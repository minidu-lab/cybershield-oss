#!/usr/bin/env python3
"""Example: create a custom scanner module.

Shows how to extend CyberShield with your own vulnerability scanner.
"""

from __future__ import annotations

import asyncio

from cybershield.config import Config
from cybershield.core import Vulnerability
from cybershield.scanners.base import BaseScanner


class DirectoryTraversalScanner(BaseScanner):
    """Custom scanner: checks for directory traversal vulnerabilities."""

    name = "dir_traversal"
    description = "Directory Traversal Scanner"

    # Common directory traversal payloads
    PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ]

    # Indicators of successful traversal
    INDICATORS = [
        "root:x:",  # Linux /etc/passwd
        "root:*:",
        "[boot loader]",  # Windows boot.ini
        "[operating systems]",
    ]

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for directory traversal vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []

        async with self._create_session() as session:
            for payload in self.PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/{payload}"
                status, body, _ = await self._fetch(session, test_url)

                if status == 200:
                    for indicator in self.INDICATORS:
                        if indicator in body:
                            vulnerabilities.append(
                                Vulnerability(
                                    scanner=self.name,
                                    title="Directory Traversal detected",
                                    severity="CRITICAL",
                                    url=test_url,
                                    description=(
                                        f"The server is vulnerable to path "
                                        f"traversal. The payload '{payload}' "
                                        f"successfully accessed a system file."
                                    ),
                                    evidence=f"Payload: {payload}, Indicator: {indicator}",
                                    remediation=(
                                        "1. Validate and sanitize all file path inputs\n"
                                        "2. Use a whitelist of allowed file paths\n"
                                        "3. Chroot the web application\n"
                                        "4. Never use user input directly in file operations"
                                    ),
                                    cwe_id="CWE-22",
                                )
                            )
                            return vulnerabilities  # One finding is enough

        return vulnerabilities


async def main():
    """Run the custom scanner."""
    config = Config.from_env()
    scanner = DirectoryTraversalScanner(config)

    results = await scanner.scan("https://example.com")
    print(f"Found {len(results)} vulnerabilities")
    for vuln in results:
        print(f"  [{vuln.severity}] {vuln.title}")


if __name__ == "__main__":
    asyncio.run(main())
