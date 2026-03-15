"""HTTP request helper utilities for CyberShield OSS."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp

logger = logging.getLogger(__name__)


async def fetch_page(
    url: str,
    timeout: int = 30,
    user_agent: str = "CyberShield-OSS/0.1.0",
    verify_ssl: bool = True,
) -> tuple[int, str, dict]:
    """Fetch a web page and return (status, body, headers).

    Args:
        url: URL to fetch.
        timeout: Request timeout in seconds.
        user_agent: User-Agent header value.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Tuple of (status_code, response_body, response_headers).
        Returns (0, "", {}) on connection failure.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"User-Agent": user_agent},
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=verify_ssl,
            ) as resp:
                body = await resp.text()
                return resp.status, body, dict(resp.headers)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
        return 0, "", {}


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    """Normalize a URL, resolving relative paths against a base URL.

    Args:
        url: URL to normalize.
        base_url: Base URL for resolving relative paths.

    Returns:
        Normalized absolute URL.
    """
    if base_url:
        url = urljoin(base_url, url)

    parsed = urlparse(url)
    # Remove fragment
    return parsed._replace(fragment="").geturl()


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain."""
    return urlparse(url1).netloc == urlparse(url2).netloc
