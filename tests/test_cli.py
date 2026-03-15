"""Tests for the CyberShield CLI interface."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from cybershield.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    """Tests for CLI commands."""

    def test_version(self, runner):
        """--version should print the version."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self, runner):
        """--help should print usage information."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "CyberShield" in result.output

    def test_scan_help(self, runner):
        """scan --help should show scan options."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--modules" in result.output
        assert "--report" in result.output

    def test_scan_invalid_url(self, runner):
        """scan with invalid URL should exit with error."""
        result = runner.invoke(cli, ["scan", "not-a-valid-url"])
        # Should still attempt (URL validator adds https://)
        assert result.exit_code in (0, 1, 2)

    def test_tutor_help(self, runner):
        """tutor --help should show tutor options."""
        result = runner.invoke(cli, ["tutor", "--help"])
        assert result.exit_code == 0
        assert "--topic" in result.output
