"""Base scanner class that all vulnerability scanners inherit from."""

from __future__ import annotations

import abc
import asyncio
import logging
from typing import TYPE_CHECKING

import aiohttp

if TYPE_CHECKING:
    from cybershield.config import Config
    from cybershield.core import Vulnerability

logger = logging.getLogger(__name__)


class BaseScanner(abc.ABC):
    """Abstract base class for all vulnerability scanners.

    Each scanner module must implement the `scan` method, which takes a
    target URL and returns a list of discovered `Vulnerability` objects.
    """

    name: str = "base"
    description: str = "Base scanner"

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(f"cybershield.scanners.{self.name}")

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        data: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, str, dict]:
        """Fetch a URL and return (status_code, body, response_headers).

        Returns (0, "", {}) on connection errors instead of raising.
        """
        default_headers = {"User-Agent": self.config.user_agent}
        if headers:
            default_headers.update(headers)

        try:
            async with session.request(
                method,
                url,
                data=data,
                headers=default_headers,
                timeout=aiohttp.ClientTimeout(
                    total=self.config.request_timeout
                ),
                ssl=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects,
            ) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.logger.debug("Request to %s failed: %s", url, exc)
            return 0, "", {}

    def _create_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session with project defaults."""
        return aiohttp.ClientSession(
            headers={"User-Agent": self.config.user_agent},
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
        )

    @abc.abstractmethod
    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Scan the target URL and return discovered vulnerabilities.

        Args:
            target_url: The URL to scan.

        Returns:
            List of Vulnerability objects found during the scan.
        """
        ...
