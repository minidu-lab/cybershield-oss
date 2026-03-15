"""Input validation utilities for CyberShield OSS."""

from __future__ import annotations

from urllib.parse import urlparse

VALID_MODULES = {"xss", "sqli", "csrf", "auth", "api_keys", "all"}


def validate_url(url: str) -> str:
    """Validate and normalize a target URL.

    Args:
        url: The URL to validate.

    Returns:
        Normalized URL string.

    Raises:
        ValueError: If the URL is invalid.
    """
    if not url:
        raise ValueError("URL cannot be empty")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        raise ValueError(f"Invalid URL: missing hostname in '{url}'")

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Use http:// or https://"
        )

    # Basic hostname validation
    hostname = parsed.hostname or ""
    if not hostname or "." not in hostname and hostname != "localhost":
        raise ValueError(f"Invalid hostname: '{hostname}'")

    return url


def validate_modules(modules: list[str]) -> list[str]:
    """Validate scanner module names.

    Args:
        modules: List of module names to validate.

    Returns:
        Validated list of module names.

    Raises:
        ValueError: If any module name is invalid.
    """
    if not modules:
        return ["all"]

    for mod in modules:
        if mod not in VALID_MODULES:
            raise ValueError(
                f"Unknown module '{mod}'. "
                f"Available modules: {sorted(VALID_MODULES)}"
            )

    return modules
