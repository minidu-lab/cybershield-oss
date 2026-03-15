"""SQL Injection vulnerability scanner.

Detects SQL injection by injecting common payloads into query parameters
and analyzing the response for database error messages or behavioral
anomalies that indicate unsanitized query construction.

v0.2.0: Added time-based blind SQL injection detection, boolean-based
blind detection, enhanced error pattern matching, response time analysis,
and multi-database support (MySQL, PostgreSQL, SQLite, MSSQL, Oracle).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp

from cybershield.scanners.base import BaseScanner
from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

# ── SQL Injection Payloads ──────────────────────────────────────────
# Organized by technique: error-based, boolean-based, time-based

# Error-based: designed to trigger database error messages
ERROR_BASED_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "'; DROP TABLE users;--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    "1;SELECT@@version--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
]

# Boolean-based: two payloads that should produce different responses
BOOLEAN_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),          # Numeric context
    ("' AND '1'='1", "' AND '1'='2"),     # String context
    ("1) AND (1=1", "1) AND (1=2"),       # Parenthesized context
]

# Time-based blind: payloads that introduce measurable delays
TIME_BASED_PAYLOADS = {
    "MySQL": [
        "' AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "'; SELECT SLEEP(5);--",
    ],
    "PostgreSQL": [
        "'; SELECT pg_sleep(5);--",
        "' AND pg_sleep(5)--",
    ],
    "MSSQL": [
        "'; WAITFOR DELAY '0:0:5';--",
        "1; WAITFOR DELAY '0:0:5'--",
    ],
    "SQLite": [
        "' AND 1=randomblob(500000000)--",
    ],
}

# Time threshold (seconds) — if response takes longer, it's suspicious
TIME_THRESHOLD = 4.5

# ── Database Error Patterns ─────────────────────────────────────────
# Compiled regex patterns that indicate SQL errors from specific DBs

DB_ERROR_PATTERNS = [
    # MySQL / MariaDB
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:.*mysql", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"mysqli?[_\.]", re.IGNORECASE),
    re.compile(r"MariaDB server version", re.IGNORECASE),
    re.compile(r"mysql_num_rows\(\)", re.IGNORECASE),
    re.compile(r"MySQL result index", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"pg_exec\(\)", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"unterminated quoted string", re.IGNORECASE),
    re.compile(r"psycopg2\.", re.IGNORECASE),
    re.compile(r"PG::SyntaxError", re.IGNORECASE),
    # SQLite
    re.compile(r"SQLite3?::Exception", re.IGNORECASE),
    re.compile(r"sqlite\.OperationalError", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"near \".*\": syntax error", re.IGNORECASE),
    # Microsoft SQL Server
    re.compile(r"Microsoft.*ODBC.*SQL Server", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"mssql_query\(\)", re.IGNORECASE),
    re.compile(r"Microsoft SQL Native Client", re.IGNORECASE),
    re.compile(r"SQL Server.*Driver", re.IGNORECASE),
    re.compile(r"Incorrect syntax near", re.IGNORECASE),
    # Oracle
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"oracle.*error", re.IGNORECASE),
    re.compile(r"Oracle.*Driver", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    # Generic SQL errors
    re.compile(r"SQL syntax.*?error", re.IGNORECASE),
    re.compile(r"valid SQL statement", re.IGNORECASE),
    re.compile(r"unexpected end of SQL command", re.IGNORECASE),
    re.compile(r"Dynamic SQL Error", re.IGNORECASE),
    re.compile(r"supplied argument is not a valid", re.IGNORECASE),
]


class SQLiScanner(BaseScanner):
    """Scanner for SQL Injection vulnerabilities.

    Tests for three categories of SQL injection:
    1. Error-based: triggers database error messages in responses
    2. Boolean-based blind: detects different responses for true/false conditions
    3. Time-based blind: measures response time with SLEEP/WAITFOR payloads

    v0.2.0 improvements:
    - Time-based blind SQL injection detection
    - Boolean-based blind detection with response diffing
    - Multi-database payload support (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
    - Enhanced error pattern matching
    - Baseline comparison to reduce false positives
    """

    name = "sqli"
    description = "SQL Injection Scanner"

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan for SQL injection vulnerabilities using multiple techniques."""
        vulnerabilities: list[Vulnerability] = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            params = {"id": ["1"], "page": ["1"], "user": ["admin"]}

        async with self._create_session() as session:
            # Fetch baseline response for comparison
            baseline_start = time.time()
            baseline_status, baseline_body, _ = await self._fetch(
                session, target_url
            )
            baseline_time = time.time() - baseline_start

            for param_name in params:
                # 1. Error-based SQL injection
                for payload in ERROR_BASED_PAYLOADS:
                    vuln = await self._test_error_based(
                        session, target_url, parsed, param_name,
                        payload, baseline_body
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        break

                # 2. Boolean-based blind SQL injection
                vuln = await self._test_boolean_based(
                    session, target_url, parsed, param_name, baseline_body
                )
                if vuln:
                    vulnerabilities.append(vuln)

                # 3. Time-based blind SQL injection
                vuln = await self._test_time_based(
                    session, target_url, parsed, param_name, baseline_time
                )
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_error_based(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        parsed,
        param_name: str,
        payload: str,
        baseline_body: str,
    ) -> Vulnerability | None:
        """Test for error-based SQL injection."""
        test_url = self._build_test_url(parsed, param_name, payload)
        status, body, headers = await self._fetch(session, test_url)
        if status == 0:
            return None

        for pattern in DB_ERROR_PATTERNS:
            match = pattern.search(body)
            if match and not pattern.search(baseline_body):
                db_type = self._identify_database(match.group())
                self.logger.warning(
                    "SQL Injection (error-based) in param '%s' at %s [%s]",
                    param_name, target_url, db_type,
                )
                return Vulnerability(
                    scanner=self.name,
                    title=f"SQL Injection in parameter '{param_name}'",
                    severity="CRITICAL",
                    url=target_url,
                    description=(
                        f"The parameter '{param_name}' is vulnerable to "
                        f"error-based SQL injection. The payload "
                        f"'{payload}' triggered a {db_type} database error "
                        f"in the response, confirming that user input is "
                        f"inserted directly into SQL queries without "
                        f"parameterization. An attacker could extract the "
                        f"entire database, modify data, or in some cases "
                        f"execute operating system commands."
                    ),
                    evidence=(
                        f"Technique: Error-based\n"
                        f"Payload: {payload}\n"
                        f"Database: {db_type}\n"
                        f"Error matched: {match.group()}\n"
                        f"HTTP Status: {status}"
                    ),
                    remediation=(
                        "1. Use parameterized queries (prepared statements) for ALL "
                        "database operations — this is the primary fix:\n"
                        "   Python: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                        "   Node.js: db.query('SELECT * FROM users WHERE id = $1', [userId])\n"
                        "2. Use an ORM (SQLAlchemy, Prisma, Sequelize) that handles parameterization\n"
                        "3. Validate input types (e.g., ensure IDs are integers)\n"
                        "4. Apply the principle of least privilege to database accounts\n"
                        "5. Use a Web Application Firewall (WAF) as defense-in-depth\n"
                        "6. Disable detailed database error messages in production"
                    ),
                    cwe_id="CWE-89",
                )

        return None

    async def _test_boolean_based(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        parsed,
        param_name: str,
        baseline_body: str,
    ) -> Vulnerability | None:
        """Test for boolean-based blind SQL injection.

        Sends a TRUE and FALSE condition — if responses differ
        significantly, the parameter is likely injectable.
        """
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_url = self._build_test_url(parsed, param_name, true_payload)
            false_url = self._build_test_url(parsed, param_name, false_payload)

            _, true_body, _ = await self._fetch(session, true_url)
            _, false_body, _ = await self._fetch(session, false_url)

            if not true_body or not false_body:
                continue

            # Check if TRUE condition returns baseline-like content
            # and FALSE condition returns different content
            true_diff = abs(len(true_body) - len(baseline_body))
            false_diff = abs(len(false_body) - len(baseline_body))

            # Heuristic: TRUE response similar to baseline, FALSE very different
            if true_diff < 100 and false_diff > 500:
                self.logger.warning(
                    "Boolean-based blind SQLi in param '%s' at %s",
                    param_name, target_url,
                )
                return Vulnerability(
                    scanner=self.name,
                    title=f"Blind SQL Injection (boolean-based) in '{param_name}'",
                    severity="CRITICAL",
                    url=target_url,
                    description=(
                        f"The parameter '{param_name}' appears vulnerable to "
                        f"boolean-based blind SQL injection. Sending a TRUE "
                        f"condition ({true_payload}) returns a normal response "
                        f"(~{len(true_body)} bytes), while a FALSE condition "
                        f"({false_payload}) returns a significantly different "
                        f"response (~{len(false_body)} bytes). This allows an "
                        f"attacker to extract data one bit at a time."
                    ),
                    evidence=(
                        f"Technique: Boolean-based blind\n"
                        f"TRUE payload: {true_payload} → {len(true_body)} bytes\n"
                        f"FALSE payload: {false_payload} → {len(false_body)} bytes\n"
                        f"Baseline: {len(baseline_body)} bytes\n"
                        f"Difference: {abs(len(true_body) - len(false_body))} bytes"
                    ),
                    remediation=(
                        "1. Use parameterized queries — never concatenate user input into SQL\n"
                        "2. Use an ORM with built-in parameterization\n"
                        "3. Validate and whitelist expected input values\n"
                        "4. Implement rate limiting to slow down extraction attempts\n"
                        "5. Use a WAF with SQL injection rule sets"
                    ),
                    cwe_id="CWE-89",
                )

        return None

    async def _test_time_based(
        self,
        session: aiohttp.ClientSession,
        target_url: str,
        parsed,
        param_name: str,
        baseline_time: float,
    ) -> Vulnerability | None:
        """Test for time-based blind SQL injection.

        Injects SLEEP/WAITFOR payloads and measures if the response
        is delayed beyond the normal baseline response time.
        """
        for db_name, payloads in TIME_BASED_PAYLOADS.items():
            for payload in payloads[:1]:  # Test one payload per DB type
                test_url = self._build_test_url(parsed, param_name, payload)

                start_time = time.time()
                status, body, _ = await self._fetch(session, test_url)
                elapsed = time.time() - start_time

                if status == 0:
                    continue

                # If response took significantly longer than baseline,
                # the SLEEP/WAITFOR payload likely executed
                if elapsed > TIME_THRESHOLD and elapsed > (baseline_time + 4):
                    self.logger.warning(
                        "Time-based blind SQLi in param '%s' at %s [%s, %.1fs]",
                        param_name, target_url, db_name, elapsed,
                    )
                    return Vulnerability(
                        scanner=self.name,
                        title=f"Blind SQL Injection (time-based) in '{param_name}'",
                        severity="CRITICAL",
                        url=target_url,
                        description=(
                            f"The parameter '{param_name}' is vulnerable to "
                            f"time-based blind SQL injection. The payload "
                            f"'{payload}' caused the server to delay its "
                            f"response by {elapsed:.1f}s (baseline: "
                            f"{baseline_time:.1f}s), indicating that the "
                            f"SLEEP/WAITFOR command executed successfully. "
                            f"This confirms {db_name} database injection. "
                            f"An attacker can extract the entire database "
                            f"contents by timing responses."
                        ),
                        evidence=(
                            f"Technique: Time-based blind\n"
                            f"Payload: {payload}\n"
                            f"Database: {db_name}\n"
                            f"Response time: {elapsed:.2f}s\n"
                            f"Baseline time: {baseline_time:.2f}s\n"
                            f"Delay detected: {elapsed - baseline_time:.2f}s"
                        ),
                        remediation=(
                            "1. Use parameterized queries (prepared statements)\n"
                            "2. Use an ORM with automatic parameterization\n"
                            "3. Never concatenate user input into SQL strings\n"
                            "4. Restrict database user permissions\n"
                            "5. Implement query timeouts to limit damage\n"
                            "6. Use a WAF to detect and block SQLi patterns"
                        ),
                        cwe_id="CWE-89",
                    )

        return None

    def _build_test_url(self, parsed, param_name: str, payload: str) -> str:
        """Build a test URL with the payload injected into the parameter."""
        test_params = parse_qs(parsed.query)
        test_params[param_name] = [payload]
        flat_params = {k: v[0] for k, v in test_params.items()}
        test_query = urlencode(flat_params, safe="")
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, test_query, parsed.fragment,
        ))

    @staticmethod
    def _identify_database(error_text: str) -> str:
        """Identify the database type from an error message."""
        error_lower = error_text.lower()
        if any(kw in error_lower for kw in ["mysql", "mariadb"]):
            return "MySQL/MariaDB"
        if any(kw in error_lower for kw in ["pg_", "postgresql", "psycopg"]):
            return "PostgreSQL"
        if any(kw in error_lower for kw in ["sqlite"]):
            return "SQLite"
        if any(kw in error_lower for kw in ["microsoft", "mssql", "sql server"]):
            return "Microsoft SQL Server"
        if any(kw in error_lower for kw in ["ora-", "oracle"]):
            return "Oracle"
        return "Unknown"
