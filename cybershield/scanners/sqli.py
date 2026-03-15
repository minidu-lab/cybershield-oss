"""SQL Injection vulnerability scanner.

Detects SQL injection by injecting common payloads into query parameters
and analyzing the response for database error messages or behavioral
anomalies that indicate unsanitized query construction.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# SQL injection test payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "'; DROP TABLE users--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
]

# Database error patterns that indicate SQL injection
DB_ERROR_PATTERNS = [
    # MySQL
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:.*mysql", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"mysqli?[_\.]", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"pg_exec\(\)", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"unterminated quoted string", re.IGNORECASE),
    # SQLite
    re.compile(r"SQLite3?::Exception", re.IGNORECASE),
    re.compile(r"sqlite\.OperationalError", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR", re.IGNORECASE),
    # SQL Server
    re.compile(r"Microsoft.*ODBC.*SQL Server", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"mssql_query\(\)", re.IGNORECASE),
    # Oracle
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"oracle.*error", re.IGNORECASE),
    # Generic
    re.compile(r"SQL syntax.*?error", re.IGNORECASE),
    re.compile(r"valid SQL statement", re.IGNORECASE),
    re.compile(r"unexpected end of SQL command", re.IGNORECASE),
]


class SQLiScanner(BaseScanner):
    """Scanner for SQL Injection vulnerabilities.

    Tests for error-based and boolean-based blind SQL injection by
    injecting payloads into URL query parameters and analyzing responses.
    """

    name = "sqli"
    description = "SQL Injection Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for SQL injection vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            params = {"id": ["1"], "page": ["1"], "user": ["admin"]}

        async with self._create_session() as session:
            # First, get the baseline response
            baseline_status, baseline_body, _ = await self._fetch(
                session, target_url
            )

            for param_name in params:
                for payload in SQLI_PAYLOADS:
                    vuln = await self._test_param(
                        session,
                        target_url,
                        parsed,
                        param_name,
                        payload,
                        baseline_body,
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # One confirmed SQLi per parameter

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
        """Test a single parameter with a SQL injection payload."""
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

        # Check for database error messages
        for pattern in DB_ERROR_PATTERNS:
            match = pattern.search(body)
            if match and not pattern.search(baseline_body):
                self.logger.warning(
                    "SQL Injection found in param '%s' at %s",
                    param_name,
                    target_url,
                )
                return Vulnerability(
                    scanner=self.name,
                    title=f"SQL Injection in parameter '{param_name}'",
                    severity="CRITICAL",
                    url=target_url,
                    description=(
                        f"The parameter '{param_name}' appears vulnerable to "
                        f"SQL injection. The payload '{payload}' triggered a "
                        f"database error message in the response, indicating "
                        f"that user input is being inserted directly into SQL "
                        f"queries without proper parameterization."
                    ),
                    evidence=(
                        f"Payload: {payload}\n"
                        f"Error pattern matched: {match.group()}"
                    ),
                    remediation=(
                        "1. Use parameterized queries (prepared statements) for ALL "
                        "database operations\n"
                        "2. Use an ORM (e.g., SQLAlchemy) that handles parameterization\n"
                        "3. Validate and sanitize all user input\n"
                        "4. Apply the principle of least privilege to database accounts\n"
                        "5. Use a Web Application Firewall (WAF) as defense-in-depth"
                    ),
                    cwe_id="CWE-89",
                )

        return None
