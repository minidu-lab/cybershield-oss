"""Interactive Security Tutor powered by Claude.

An educational chat interface where cybersecurity students can ask
questions about vulnerabilities, attack techniques, and defense
strategies. Designed for learning, not for offensive use.
"""

from __future__ import annotations

import logging
from typing import Optional

from cybershield.ai.client import ClaudeClient
from cybershield.config import Config

logger = logging.getLogger(__name__)

TUTOR_SYSTEM_PROMPT = """\
You are CyberShield's Security Tutor — an expert cybersecurity educator \
focused on web application security. You help students understand \
vulnerabilities, attack vectors, and defensive techniques.

Your teaching philosophy:
1. EXPLAIN concepts with real-world analogies
2. SHOW with safe, educational examples (never provide weaponizable exploits)
3. CONNECT theory to practice — always relate to actual development scenarios
4. ENCOURAGE curiosity — no question is too basic
5. GUIDE toward secure coding habits, not just fixing bugs

Important rules:
- Never provide working exploit code that could be used maliciously
- Always emphasize ethical hacking and responsible disclosure
- When explaining attacks, focus on the "why" and "how to defend"
- Use the OWASP Top 10 as a reference framework
- Adapt your explanations to the student's apparent skill level
- If asked about offensive techniques, redirect to defensive strategies

Topics you cover:
- OWASP Top 10 vulnerabilities
- Secure coding practices
- Authentication and authorization
- Cryptography fundamentals
- Network security basics
- Web application architecture security
- Security testing methodologies
- Bug bounty and responsible disclosure
"""


class SecurityTutor:
    """Interactive security education chat powered by Claude.

    Provides a conversational interface for students to learn about
    cybersecurity concepts with contextual, educational responses.

    Usage:
        tutor = SecurityTutor(config)
        response = await tutor.ask("What is SQL injection?")

        # With conversation history
        tutor.start_session()
        r1 = await tutor.ask("What is XSS?")
        r2 = await tutor.ask("How do I prevent it in React?")  # Remembers context
    """

    def __init__(self, config: Config, topic: Optional[str] = None):
        self.config = config
        self._client = ClaudeClient(config)
        self._history: list[dict[str, str]] = []
        self._topic = topic

        if topic:
            self._history.append(
                {
                    "role": "user",
                    "content": (
                        f"I want to learn about {topic} in the context of "
                        f"web application security. Start with an overview."
                    ),
                }
            )

    async def ask(self, question: str) -> str:
        """Ask the security tutor a question.

        Args:
            question: The student's question.

        Returns:
            The tutor's educational response.
        """
        self._history.append({"role": "user", "content": question})

        response = await self._client.complete(
            system_prompt=TUTOR_SYSTEM_PROMPT,
            user_message=self._format_history(),
            max_tokens=1500,
            temperature=0.5,
        )

        self._history.append({"role": "assistant", "content": response})
        return response

    async def ask_stream(self, question: str):
        """Ask a question and stream the response.

        Yields:
            Text chunks of the tutor's response.
        """
        self._history.append({"role": "user", "content": question})

        full_response = ""
        async for chunk in self._client.complete_stream(
            system_prompt=TUTOR_SYSTEM_PROMPT,
            user_message=self._format_history(),
            max_tokens=1500,
            temperature=0.5,
        ):
            full_response += chunk
            yield chunk

        self._history.append(
            {"role": "assistant", "content": full_response}
        )

    def _format_history(self) -> str:
        """Format conversation history for the API request."""
        parts = []
        for msg in self._history:
            role = "Student" if msg["role"] == "user" else "Tutor"
            parts.append(f"{role}: {msg['content']}")
        return "\n\n".join(parts)

    def clear_history(self):
        """Clear the conversation history."""
        self._history.clear()

    @property
    def history(self) -> list[dict[str, str]]:
        """Return the conversation history."""
        return list(self._history)

    async def close(self):
        """Close the underlying API client."""
        await self._client.close()
