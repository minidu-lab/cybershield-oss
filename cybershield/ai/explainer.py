"""AI-powered vulnerability explanation pipeline.

Takes raw scanner output and uses Claude to generate developer-friendly,
context-aware explanations with clear remediation guidance.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cybershield.ai.client import ClaudeClient
from cybershield.config import Config

if TYPE_CHECKING:
    from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are CyberShield's security analysis assistant. Your role is to explain \
web application vulnerabilities in clear, plain English that any developer \
can understand — even those without security expertise.

Guidelines:
1. Explain WHAT the vulnerability is in one sentence
2. Explain WHY it's dangerous with a concrete attack scenario
3. Show HOW to fix it with specific code examples when possible
4. Rate the real-world risk (not just theoretical severity)
5. Use analogies to make complex concepts accessible
6. Be concise — aim for 150-250 words per explanation
7. Always suggest the most secure fix first, then practical alternatives
8. If the vulnerability is in a specific framework, give framework-specific advice

Format your response as:
## What's happening
[1-2 sentence explanation]

## Why it matters
[Attack scenario in plain English]

## How to fix it
[Step-by-step remediation with code snippets]

## Risk level
[Contextual risk assessment]
"""


class VulnerabilityExplainer:
    """Generates AI-powered explanations for detected vulnerabilities.

    Uses the Claude API to transform raw scanner output into clear,
    actionable security reports that developers can understand.

    Usage:
        explainer = VulnerabilityExplainer(config)
        explanation = await explainer.explain(vulnerability)
    """

    def __init__(self, config: Config):
        self.config = config
        self._client = ClaudeClient(config)

    async def explain(self, vulnerability) -> str:
        """Generate a plain-English explanation for a vulnerability.

        Args:
            vulnerability: A Vulnerability object from a scanner.

        Returns:
            A formatted string with the AI-generated explanation.
        """
        prompt = self._build_prompt(vulnerability)
        logger.debug("Requesting AI explanation for: %s", vulnerability.title)

        explanation = await self._client.complete(
            system_prompt=SYSTEM_PROMPT,
            user_message=prompt,
            max_tokens=1024,
            temperature=0.3,
        )

        return explanation

    async def explain_batch(
        self, vulnerabilities: list
    ) -> dict[str, str]:
        """Generate explanations for multiple vulnerabilities.

        Args:
            vulnerabilities: List of Vulnerability objects.

        Returns:
            Dict mapping vulnerability title to explanation.
        """
        explanations = {}
        for vuln in vulnerabilities:
            try:
                explanation = await self.explain(vuln)
                explanations[vuln.title] = explanation
            except Exception as e:
                logger.warning(
                    "Failed to explain '%s': %s", vuln.title, e
                )
                explanations[vuln.title] = (
                    f"AI explanation unavailable: {e}\n\n"
                    f"Scanner description: {vuln.description}"
                )
        return explanations

    def _build_prompt(self, vulnerability) -> str:
        """Build the user prompt from a Vulnerability object."""
        parts = [
            f"Vulnerability: {vulnerability.title}",
            f"Severity: {vulnerability.severity}",
            f"URL: {vulnerability.url}",
            f"Scanner: {vulnerability.scanner}",
            f"Description: {vulnerability.description}",
        ]
        if vulnerability.evidence:
            parts.append(f"Evidence: {vulnerability.evidence}")
        if vulnerability.cwe_id:
            parts.append(f"CWE: {vulnerability.cwe_id}")
        if vulnerability.remediation:
            parts.append(
                f"Scanner suggested fix: {vulnerability.remediation}"
            )

        return "\n".join(parts)

    async def close(self):
        """Close the underlying API client."""
        await self._client.close()
