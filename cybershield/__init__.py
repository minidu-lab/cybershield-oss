"""
CyberShield OSS — AI-Assisted Cybersecurity Scanner & Education Platform.

An open-source tool that scans web applications for common vulnerabilities
and uses Claude by Anthropic to generate clear, developer-friendly explanations
with actionable remediation guidance.
"""

__version__ = "0.1.0"
__author__ = "Minidu Pasan"
__license__ = "MIT"

from cybershield.core import CyberShield
from cybershield.config import Config

__all__ = ["CyberShield", "Config", "__version__"]
