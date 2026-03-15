"""Base report generator class."""

from __future__ import annotations

import abc
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from cybershield.config import Config
    from cybershield.core import ScanResult


class BaseReport(abc.ABC):
    """Abstract base class for report generators."""

    format_name: str = "base"
    file_extension: str = ".txt"

    def __init__(self, config: Config):
        self.config = config

    def generate(
        self, result: ScanResult, output_path: Optional[str] = None
    ) -> str:
        """Generate a report and save it to a file.

        Args:
            result: Scan results to report.
            output_path: Output file path. Auto-generated if None.

        Returns:
            Path to the generated report file.
        """
        if output_path is None:
            os.makedirs(self.config.report_output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                self.config.report_output_dir,
                f"cybershield_{timestamp}{self.file_extension}",
            )

        content = self._render(result)
        Path(output_path).write_text(content, encoding="utf-8")
        return output_path

    @abc.abstractmethod
    def _render(self, result: ScanResult) -> str:
        """Render the report content as a string."""
        ...
