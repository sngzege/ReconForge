"""Screenshot provider abstraction for ReconForge.

Responsibilities:
- Define a common interface for screenshot providers
- Provide built-in gowitness implementation

Design:
- ABC allows multiple providers (gowitness, cutycapt, custom)
- Providers write artifacts under artifacts/screenshots/
- Provider calls are mocked in unit tests
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar


class ScreenshotProvider(abc.ABC):
    """Abstract base class for screenshot providers.

    All screenshot providers must implement:
    - capture(target_url) -> screenshot_path
    - available() -> bool
    """

    output_dir: ClassVar[Path]

    @abc.abstractmethod
    def capture(self, target_url: str) -> str | None:
        """Capture a screenshot of the given URL.

        Args:
            target_url: URL to screenshot.

        Returns:
            Path to saved screenshot, or None on failure.
        """

    @abc.abstractmethod
    def available(self) -> bool:
        """Return True if this provider is available to use.

        Returns:
            True if underlying tool is installed and provider is ready.
        """

    def _build_output_path(self, target_url: str) -> Path:
        """Build the output file path for a screenshot.

        Args:
            target_url: Target URL.

        Returns:
            Path under artifacts/screenshots/.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_url = target_url.replace("://", "_").replace("/", "_").replace("?", "_")
        filename = f"{ts}_{safe_url}.png"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir / filename
