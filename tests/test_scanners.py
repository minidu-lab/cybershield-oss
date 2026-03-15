"""Unit tests for CyberShield vulnerability scanners."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from cybershield.config import Config
from cybershield.scanners.xss import XSSScanner
from cybershield.scanners.sqli import SQLiScanner
from cybershield.scanners.csrf import CSRFScanner
from cybershield.scanners.auth import AuthScanner
from cybershield.scanners.api_keys import APIKeyScanner


@pytest.fixture
def test_config():
    return Config(log_level="DEBUG", request_timeout=5)


class TestXSSScanner:
    """Tests for the XSS scanner module."""

    @pytest.mark.asyncio
    async def test_detects_reflected_xss(self, test_config):
        scanner = XSSScanner(test_config)

        with aioresponses() as mocked:
            # Mock a page that reflects the XSS payload
            mocked.get(
                "https://example.com/search",
                status=200,
                body='<html><body>Results for: <script>alert("XSS")</script></body></html>',
                repeat=True,
            )

            results = await scanner.scan(
                "https://example.com/search?q=test"
            )

        assert len(results) > 0
        assert results[0].severity == "HIGH"
        assert results[0].cwe_id == "CWE-79"
        assert "XSS" in results[0].title

    @pytest.mark.asyncio
    async def test_no_false_positive_on_clean_page(self, test_config):
        scanner = XSSScanner(test_config)

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com/search",
                status=200,
                body="<html><body>Clean results page</body></html>",
                repeat=True,
            )

            results = await scanner.scan(
                "https://example.com/search?q=test"
            )

        assert len(results) == 0


class TestSQLiScanner:
    """Tests for the SQL injection scanner module."""

    @pytest.mark.asyncio
    async def test_detects_mysql_error(self, test_config):
        scanner = SQLiScanner(test_config)

        with aioresponses() as mocked:
            # Baseline — clean response
            mocked.get(
                "https://example.com/user",
                status=200,
                body="<html><body>User profile</body></html>",
            )
            # Injected — triggers MySQL error
            mocked.get(
                "https://example.com/user",
                status=500,
                body="You have an error in your SQL syntax near ''1'' at line 1",
                repeat=True,
            )

            results = await scanner.scan(
                "https://example.com/user?id=1"
            )

        assert len(results) > 0
        assert results[0].severity == "CRITICAL"
        assert results[0].cwe_id == "CWE-89"


class TestCSRFScanner:
    """Tests for the CSRF scanner module."""

    @pytest.mark.asyncio
    async def test_detects_missing_csrf_token(self, test_config):
        scanner = CSRFScanner(test_config)
        html_body = """
        <html><body>
            <form method="post" action="/login">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body></html>
        """

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com/login",
                status=200,
                body=html_body,
            )

            results = await scanner.scan("https://example.com/login")

        csrf_vulns = [v for v in results if "CSRF" in v.title or "csrf" in v.title.lower()]
        assert len(csrf_vulns) > 0

    @pytest.mark.asyncio
    async def test_no_alert_when_csrf_token_present(self, test_config):
        scanner = CSRFScanner(test_config)
        html_body = """
        <html><body>
            <form method="post" action="/login">
                <input type="hidden" name="csrf_token" value="abc123">
                <input type="text" name="username">
                <button type="submit">Login</button>
            </form>
        </body></html>
        """

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com/login",
                status=200,
                body=html_body,
            )

            results = await scanner.scan("https://example.com/login")

        # No CSRF form token warnings (cookie warnings may still appear)
        form_vulns = [v for v in results if "form" in v.title.lower()]
        assert len(form_vulns) == 0


class TestAuthScanner:
    """Tests for the authentication/headers scanner module."""

    @pytest.mark.asyncio
    async def test_detects_missing_security_headers(self, test_config):
        scanner = AuthScanner(test_config)

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com",
                status=200,
                body="<html></html>",
                headers={"Content-Type": "text/html"},
            )

            results = await scanner.scan("https://example.com")

        # Should detect multiple missing headers
        assert len(results) >= 3
        titles = [v.title for v in results]
        assert any("Strict-Transport-Security" in t for t in titles)
        assert any("Content-Security-Policy" in t for t in titles)

    @pytest.mark.asyncio
    async def test_detects_server_version_disclosure(self, test_config):
        scanner = AuthScanner(test_config)

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com",
                status=200,
                body="<html></html>",
                headers={
                    "Server": "nginx/1.24.0",
                    "Strict-Transport-Security": "max-age=31536000",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                },
            )

            results = await scanner.scan("https://example.com")

        version_vulns = [v for v in results if "version" in v.title.lower()]
        assert len(version_vulns) > 0


class TestAPIKeyScanner:
    """Tests for the API key/secrets scanner module."""

    @pytest.mark.asyncio
    async def test_detects_aws_access_key(self, test_config):
        scanner = APIKeyScanner(test_config)
        html_body = """
        <html><script>
            const config = {
                aws_key: "AKIAIOSFODNN7EXAMPLE"
            };
        </script></html>
        """

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com",
                status=200,
                body=html_body,
            )

            results = await scanner.scan("https://example.com")

        assert len(results) > 0
        assert any("AWS" in v.title for v in results)

    @pytest.mark.asyncio
    async def test_detects_github_token(self, test_config):
        scanner = APIKeyScanner(test_config)
        html_body = f"""
        <html><script>
            const token = "ghp_{'A' * 36}";
        </script></html>
        """

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com",
                status=200,
                body=html_body,
            )

            results = await scanner.scan("https://example.com")

        assert len(results) > 0
        assert any("GitHub" in v.title for v in results)

    @pytest.mark.asyncio
    async def test_no_secrets_on_clean_page(self, test_config):
        scanner = APIKeyScanner(test_config)

        with aioresponses() as mocked:
            mocked.get(
                "https://example.com",
                status=200,
                body="<html><body>Clean page with no secrets</body></html>",
            )

            results = await scanner.scan("https://example.com")

        assert len(results) == 0
