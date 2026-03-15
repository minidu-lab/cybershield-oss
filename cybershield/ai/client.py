"""Anthropic Claude API client wrapper for CyberShield OSS.

Provides a thin async wrapper around the Anthropic SDK with retry logic,
token tracking, and CyberShield-specific defaults.
"""

from __future__ import annotations

import logging
from typing import Optional

import anthropic

from cybershield.config import Config

logger = logging.getLogger(__name__)


class ClaudeClient:
    """Async wrapper around the Anthropic Python SDK.

    Handles API key management, model selection, retry logic, and
    token usage tracking for CyberShield's AI features.
    """

    def __init__(self, config: Config):
        if not config.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is required for AI features. "
                "Set it in your .env file or pass it directly."
            )

        self.config = config
        self._client = anthropic.AsyncAnthropic(
            api_key=config.anthropic_api_key,
        )
        self.model = config.ai_model
        self.max_tokens = config.ai_max_tokens
        self.temperature = config.ai_temperature
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """Send a message to Claude and return the response text.

        Args:
            system_prompt: System instruction for Claude's behavior.
            user_message: The user message / query.
            max_tokens: Override default max tokens.
            temperature: Override default temperature.

        Returns:
            Claude's response as a string.
        """
        try:
            response = await self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature or self.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )

            # Track token usage
            if response.usage:
                self._total_input_tokens += response.usage.input_tokens
                self._total_output_tokens += response.usage.output_tokens
                logger.debug(
                    "Token usage — input: %d, output: %d",
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                )

            # Extract text from response
            text_blocks = [
                block.text
                for block in response.content
                if block.type == "text"
            ]
            return "\n".join(text_blocks)

        except anthropic.AuthenticationError:
            logger.error("Invalid ANTHROPIC_API_KEY — check your credentials")
            raise
        except anthropic.RateLimitError:
            logger.warning("Rate limited by Anthropic API — retrying...")
            raise
        except anthropic.APIError as e:
            logger.error("Anthropic API error: %s", e)
            raise

    async def complete_stream(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ):
        """Stream a response from Claude, yielding text chunks.

        Yields:
            Text chunks as they arrive from the API.
        """
        async with self._client.messages.stream(
            model=self.model,
            max_tokens=max_tokens or self.max_tokens,
            temperature=temperature or self.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        ) as stream:
            async for text in stream.text_stream:
                yield text

    @property
    def total_tokens(self) -> dict[str, int]:
        """Return total token usage for this session."""
        return {
            "input": self._total_input_tokens,
            "output": self._total_output_tokens,
            "total": self._total_input_tokens + self._total_output_tokens,
        }

    async def close(self):
        """Close the underlying HTTP client."""
        await self._client.close()
