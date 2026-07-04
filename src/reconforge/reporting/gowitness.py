"""Gowitness screenshot provider for ReconForge.

Responsibilities:
- Capture screenshots via gowitness CLI
- Save screenshots to artifacts/screenshots/

Design:
- Calls gowitness via subprocess.run
- Provider abstraction enables multiple screenshot backends
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from reconforge.reporting.screenshot_provider import ScreenshotProvider


class GowitnessProvider(ScreenshotProvider):
    """Screenshot provider using gowitness.

    Uses gowitness (https://github.com/sensepost/gowitness) to
    capture screenshots of web pages.
    """

    output_dir = Path("artifacts/screenshots")

    def available(self) -> bool:
        """Return True if gowitness is installed."""
        return shutil.which("gowitness") is not None

    def capture(self, target_url: str) -> str | None:
        """Capture a screenshot using gowitness.

        Args:
            target_url: URL to screenshot.

        Returns:
            Absolute path to created screenshot, or None on failure.
        """
        if not self.available():
            return None

        output_path = self._build_output_path(target_url)
        try:
            proc = subprocess.run(
                [
                    "gowitness",
                    "single",
                    "--url",
                    target_url,
                    "--destination",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                return None

            if not output_path.exists():
                return None
            return str(output_path)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
