"""Tests for the AI integration modules."""

from __future__ import annotations

import pytest

from cybershield.config import Config
from cybershield.core import Vulnerability


class TestVulnerabilityExplainer:
    """Tests for the AI vulnerability explainer."""

    def test_config_without_api_key_raises(self):
        """Explainer should raise if no API key is configured."""
        from cybershield.ai.client import ClaudeClient

        config = Config(anthropic_api_key=None)
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            ClaudeClient(config)

    def test_config_with_api_key_initializes(self):
        """Explainer should initialize with a valid API key."""
        from cybershield.ai.explainer import VulnerabilityExplainer

        config = Config(anthropic_api_key="test-key")
        explainer = VulnerabilityExplainer(config)
        assert explainer is not None


class TestSecurityTutor:
    """Tests for the security tutor."""

    def test_tutor_initializes_with_topic(self):
        """Tutor should pre-load a topic into conversation history."""
        from cybershield.ai.tutor import SecurityTutor

        config = Config(anthropic_api_key="test-key")
        tutor = SecurityTutor(config, topic="SQL injection")
        assert len(tutor.history) == 1
        assert "SQL injection" in tutor.history[0]["content"]

    def test_tutor_initializes_without_topic(self):
        """Tutor should start with empty history when no topic given."""
        from cybershield.ai.tutor import SecurityTutor

        config = Config(anthropic_api_key="test-key")
        tutor = SecurityTutor(config)
        assert len(tutor.history) == 0

    def test_tutor_clear_history(self):
        """Tutor should be able to clear conversation history."""
        from cybershield.ai.tutor import SecurityTutor

        config = Config(anthropic_api_key="test-key")
        tutor = SecurityTutor(config, topic="XSS")
        assert len(tutor.history) == 1
        tutor.clear_history()
        assert len(tutor.history) == 0
