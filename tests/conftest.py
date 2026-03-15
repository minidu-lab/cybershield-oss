"""Shared test fixtures for CyberShield OSS tests."""

from __future__ import annotations

import pytest

from cybershield.config import Config
from cybershield.core import Vulnerability


@pytest.fixture
def config():
    """Return a test configuration (no real API key)."""
    return Config(
        anthropic_api_key="test-key-not-real",
        log_level="DEBUG",
        max_concurrent=2,
        request_timeout=10,
    )


@pytest.fixture
def sample_vulnerability():
    """Return a sample vulnerability for testing."""
    return Vulnerability(
        scanner="xss",
        title="Reflected XSS in parameter 'q'",
        severity="HIGH",
        url="https://example.com/search?q=test",
        description=(
            "The parameter 'q' reflects user input without sanitization."
        ),
        evidence='<script>alert("XSS")</script>',
        remediation="Sanitize all user input before rendering in HTML.",
        cwe_id="CWE-79",
    )


@pytest.fixture
def sample_vulnerabilities():
    """Return a list of sample vulnerabilities across severities."""
    return [
        Vulnerability(
            scanner="sqli",
            title="SQL Injection in 'id' parameter",
            severity="CRITICAL",
            url="https://example.com/user?id=1",
            description="SQL injection via unsanitized parameter.",
            cwe_id="CWE-89",
        ),
        Vulnerability(
            scanner="xss",
            title="Reflected XSS in search",
            severity="HIGH",
            url="https://example.com/search",
            description="XSS via reflected input.",
            cwe_id="CWE-79",
        ),
        Vulnerability(
            scanner="csrf",
            title="Missing CSRF token on login form",
            severity="MEDIUM",
            url="https://example.com/login",
            description="Login form lacks CSRF protection.",
            cwe_id="CWE-352",
        ),
        Vulnerability(
            scanner="auth",
            title="Missing X-Content-Type-Options header",
            severity="LOW",
            url="https://example.com",
            description="Browser may MIME-sniff responses.",
            cwe_id="CWE-693",
        ),
    ]
