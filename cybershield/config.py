"""Configuration management for CyberShield OSS."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass
class Config:
    """Application configuration loaded from environment variables or .env file."""

    anthropic_api_key: Optional[str] = None
    log_level: str = "INFO"
    max_concurrent: int = 5
    request_timeout: int = 30
    user_agent: str = (
        "CyberShield-OSS/0.1.0 "
        "(+https://github.com/minidu-lab/cybershield-oss)"
    )
    report_output_dir: str = "./reports"
    max_depth: int = 3
    max_urls: int = 50
    follow_redirects: bool = True
    verify_ssl: bool = True

    # Scanner-specific settings
    xss_payloads_file: Optional[str] = None
    sqli_payloads_file: Optional[str] = None
    api_key_patterns_file: Optional[str] = None

    # AI settings
    ai_model: str = "claude-sonnet-4-20250514"
    ai_max_tokens: int = 1024
    ai_temperature: float = 0.3

    @classmethod
    def from_env(cls, env_path: Optional[str] = None) -> Config:
        """Load configuration from environment variables and optional .env file."""
        if env_path:
            load_dotenv(env_path)
        else:
            # Try loading from project root
            for candidate in [".env", "../.env"]:
                if Path(candidate).exists():
                    load_dotenv(candidate)
                    break

        return cls(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            log_level=os.getenv("CYBERSHIELD_LOG_LEVEL", "INFO"),
            max_concurrent=int(os.getenv("CYBERSHIELD_MAX_CONCURRENT", "5")),
            request_timeout=int(os.getenv("CYBERSHIELD_TIMEOUT", "30")),
            report_output_dir=os.getenv("CYBERSHIELD_REPORT_DIR", "./reports"),
            max_depth=int(os.getenv("CYBERSHIELD_MAX_DEPTH", "3")),
            max_urls=int(os.getenv("CYBERSHIELD_MAX_URLS", "50")),
            ai_model=os.getenv(
                "CYBERSHIELD_AI_MODEL", "claude-sonnet-4-20250514"
            ),
            ai_max_tokens=int(os.getenv("CYBERSHIELD_AI_MAX_TOKENS", "1024")),
            ai_temperature=float(
                os.getenv("CYBERSHIELD_AI_TEMPERATURE", "0.3")
            ),
        )

    def validate(self) -> list[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        if not self.anthropic_api_key:
            warnings.append(
                "ANTHROPIC_API_KEY not set — AI features will be disabled"
            )
        if self.max_concurrent < 1:
            warnings.append("max_concurrent must be >= 1, defaulting to 1")
            self.max_concurrent = 1
        if self.request_timeout < 5:
            warnings.append("request_timeout too low, defaulting to 5s")
            self.request_timeout = 5
        return warnings
