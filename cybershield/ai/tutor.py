"""Interactive Security Tutor powered by Claude.

An educational chat interface where cybersecurity students can ask
questions about vulnerabilities, attack techniques, and defense
strategies. Designed for learning, not for offensive use.

v0.2.0: Enhanced with severity-aware color coding, structured responses,
proper multi-turn conversation via the Messages API, session management,
and quiz mode for self-assessment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cybershield.ai.client import ClaudeClient
from cybershield.config import Config

logger = logging.getLogger(__name__)

TUTOR_SYSTEM_PROMPT = """\
You are CyberShield Tutor, an expert cybersecurity educator. Explain \
vulnerabilities in plain English. Always include:
1) what the vulnerability is
2) how attackers exploit it
3) a concrete code example of the fix

Your teaching philosophy:
- EXPLAIN concepts with real-world analogies
- SHOW with safe, educational examples (never provide weaponizable exploits)
- CONNECT theory to practice — always relate to actual development scenarios
- ENCOURAGE curiosity — no question is too basic
- GUIDE toward secure coding habits, not just fixing bugs

When explaining a vulnerability, use this structure:

## Vulnerability Overview
Brief description of what it is.

## How Attackers Exploit It
Step-by-step explanation of the attack vector.

## Severity Assessment
Rate as CRITICAL / HIGH / MEDIUM / LOW with justification.

## Code Example — Vulnerable vs Fixed
Show the vulnerable code, then the secure version with comments.

## Key Takeaways
2-3 bullet points for quick recall.

Important rules:
- Never provide working exploit code for malicious use
- Always emphasize ethical hacking and responsible disclosure
- When explaining attacks, focus on defense
- Use the OWASP Top 10 as a reference framework
- Adapt complexity to the student's apparent skill level
- Reference CWE IDs when applicable

Topics you cover:
- OWASP Top 10 vulnerabilities (XSS, SQLi, CSRF, SSRF, etc.)
- Secure coding practices (input validation, output encoding, parameterized queries)
- Authentication and authorization (OAuth, JWT, session management)
- Cryptography fundamentals (hashing, encryption, TLS)
- Network security basics (firewalls, TLS, DNS security)
- Web application architecture security (headers, CSP, CORS)
- Security testing methodologies (SAST, DAST, penetration testing)
- Bug bounty and responsible disclosure
"""

# Severity color codes for terminal output
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Bright red
    "HIGH": "\033[93m",      # Yellow/orange
    "MEDIUM": "\033[33m",    # Dark yellow
    "LOW": "\033[92m",       # Green
    "INFO": "\033[94m",      # Blue
    "RESET": "\033[0m",      # Reset
    "BOLD": "\033[1m",       # Bold
    "DIM": "\033[2m",        # Dim
}


@dataclass
class TutorSession:
    """Tracks a tutor session's metadata."""

    session_id: str = ""
    started_at: str = ""
    topic: Optional[str] = None
    questions_asked: int = 0
    topics_covered: list[str] = field(default_factory=list)


class SecurityTutor:
    """Interactive security education chat powered by Claude.

    Provides a conversational interface for students to learn about
    cybersecurity concepts with contextual, educational responses.
    Maintains full multi-turn conversation history for context-aware
    follow-up questions.

    Usage:
        tutor = SecurityTutor(config)
        response = await tutor.ask("What is SQL injection?")

        # Multi-turn conversations remember context
        r1 = await tutor.ask("What is XSS?")
        r2 = await tutor.ask("How do I prevent it in React?")  # Remembers context

        # Topic-focused sessions
        tutor = SecurityTutor(config, topic="CSRF attacks")

        # Quiz mode
        quiz = await tutor.quiz("XSS")
    """

    def __init__(self, config: Config, topic: Optional[str] = None):
        self.config = config
        self._client = ClaudeClient(config)
        self._history: list[dict[str, str]] = []
        self._topic = topic
        self._session = TutorSession(
            session_id=datetime.now().strftime("%Y%m%d_%H%M%S"),
            started_at=datetime.now().isoformat(),
            topic=topic,
        )

        if topic:
            self._history.append(
                {
                    "role": "user",
                    "content": (
                        f"I want to learn about {topic} in the context of "
                        f"web application security. Start with a structured "
                        f"overview following your response format."
                    ),
                }
            )

    async def ask(self, question: str) -> str:
        """Ask the security tutor a question.

        Sends the question along with the full conversation history to
        Claude for context-aware multi-turn responses.

        Args:
            question: The student's question.

        Returns:
            The tutor's educational response with severity-aware formatting.
        """
        self._history.append({"role": "user", "content": question})
        self._session.questions_asked += 1

        response = await self._client.complete(
            system_prompt=TUTOR_SYSTEM_PROMPT,
            user_message=self._format_history(),
            max_tokens=2048,
            temperature=0.4,
        )

        self._history.append({"role": "assistant", "content": response})

        # Track topics discussed
        self._extract_topics(question)

        return self._apply_severity_colors(response)

    async def ask_stream(self, question: str):
        """Ask a question and stream the response.

        Yields:
            Text chunks of the tutor's response as they arrive.
        """
        self._history.append({"role": "user", "content": question})
        self._session.questions_asked += 1

        full_response = ""
        async for chunk in self._client.complete_stream(
            system_prompt=TUTOR_SYSTEM_PROMPT,
            user_message=self._format_history(),
            max_tokens=2048,
            temperature=0.4,
        ):
            full_response += chunk
            yield chunk

        self._history.append(
            {"role": "assistant", "content": full_response}
        )
        self._extract_topics(question)

    async def quiz(self, topic: str) -> str:
        """Generate a quiz question on a security topic.

        Args:
            topic: The security topic to quiz on.

        Returns:
            A formatted quiz question with multiple-choice answers.
        """
        quiz_prompt = (
            f"Create a multiple-choice quiz question about '{topic}' in "
            f"cybersecurity. Format it as:\n\n"
            f"**Question:** [question text]\n\n"
            f"A) [option]\nB) [option]\nC) [option]\nD) [option]\n\n"
            f"**Correct Answer:** [letter]\n\n"
            f"**Explanation:** [why this is correct and others are wrong]"
        )

        response = await self._client.complete(
            system_prompt=TUTOR_SYSTEM_PROMPT,
            user_message=quiz_prompt,
            max_tokens=1024,
            temperature=0.7,
        )
        return response

    async def explain_vulnerability(self, vuln_type: str) -> str:
        """Get a structured explanation of a specific vulnerability type.

        Args:
            vuln_type: e.g., "XSS", "SQL Injection", "CSRF"

        Returns:
            Structured vulnerability explanation with code examples.
        """
        prompt = (
            f"Explain the {vuln_type} vulnerability in detail. Follow "
            f"your standard response format with Overview, How Attackers "
            f"Exploit It, Severity Assessment, Code Example (vulnerable "
            f"vs fixed), and Key Takeaways."
        )
        return await self.ask(prompt)

    def _format_history(self) -> str:
        """Format conversation history for the API request.

        Sends the full multi-turn history so Claude can maintain
        context across the conversation.
        """
        parts = []
        for msg in self._history:
            role = "Student" if msg["role"] == "user" else "Tutor"
            parts.append(f"{role}: {msg['content']}")
        return "\n\n".join(parts)

    def _extract_topics(self, question: str):
        """Extract and track security topics from the question."""
        topic_keywords = {
            "XSS": ["xss", "cross-site scripting", "script injection"],
            "SQL Injection": ["sql injection", "sqli", "sql inject"],
            "CSRF": ["csrf", "cross-site request forgery"],
            "Authentication": ["auth", "login", "password", "session", "jwt"],
            "SSRF": ["ssrf", "server-side request"],
            "Cryptography": ["crypto", "encryption", "hashing", "tls", "ssl"],
            "API Security": ["api key", "api security", "oauth", "token"],
            "Network Security": ["firewall", "dns", "network", "port scan"],
        }
        q_lower = question.lower()
        for topic, keywords in topic_keywords.items():
            if any(kw in q_lower for kw in keywords):
                if topic not in self._session.topics_covered:
                    self._session.topics_covered.append(topic)

    @staticmethod
    def _apply_severity_colors(text: str) -> str:
        """Apply ANSI color codes to severity keywords in the response.

        Makes CRITICAL appear in red, HIGH in orange/yellow, etc.
        """
        replacements = {
            "CRITICAL": (
                f"{SEVERITY_COLORS['BOLD']}{SEVERITY_COLORS['CRITICAL']}"
                f"CRITICAL{SEVERITY_COLORS['RESET']}"
            ),
            "HIGH": (
                f"{SEVERITY_COLORS['BOLD']}{SEVERITY_COLORS['HIGH']}"
                f"HIGH{SEVERITY_COLORS['RESET']}"
            ),
            "MEDIUM": (
                f"{SEVERITY_COLORS['MEDIUM']}"
                f"MEDIUM{SEVERITY_COLORS['RESET']}"
            ),
            "LOW": (
                f"{SEVERITY_COLORS['LOW']}"
                f"LOW{SEVERITY_COLORS['RESET']}"
            ),
        }
        for keyword, colored in replacements.items():
            # Only replace standalone severity words (not inside other words)
            text = text.replace(
                f"**{keyword}**", f"**{colored}**"
            )
            text = text.replace(
                f"Severity: {keyword}", f"Severity: {colored}"
            )
        return text

    def clear_history(self):
        """Clear the conversation history and start fresh."""
        self._history.clear()
        self._session.questions_asked = 0
        self._session.topics_covered.clear()

    @property
    def history(self) -> list[dict[str, str]]:
        """Return the conversation history."""
        return list(self._history)

    @property
    def session_info(self) -> TutorSession:
        """Return current session metadata."""
        return self._session

    async def close(self):
        """Close the underlying API client."""
        await self._client.close()
