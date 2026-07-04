"""Screenshot plugin for ReconForge.

Responsibilities:
- Capture screenshots of alive web hosts
- Store screenshot artifacts under artifacts/screenshots/

Design:
- Uses ScreenshotProvider abstraction with gowitness backend
- Writes ScreenshotResult referencing created artifacts
- Reporter consumes PipelineResult and references artifacts
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result
from reconforge.reporting.gowitness import GowitnessProvider


class ScreenshotPlugin(BasePlugin):
    """Capture screenshots of alive web hosts.

    Uses a provider-based architecture to allow multiple screenshot
    backends. Defaults to gowitness.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "screenshot"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Capture screenshots of alive web hosts"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Capture screenshots for alive URLs.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of screenshot dicts in data field.
        """
        start = time.perf_counter()

        httpx_result = upstream_results["httpx_alive"]
        if not httpx_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"httpx_alive failed: {httpx_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        urls = httpx_result.data
        if not urls:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        provider = GowitnessProvider()
        if not provider.available():
            return create_failure_result(
                module=self.name,
                error="No screenshot provider available. Install gowitness.",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        screenshots: list[dict[str, Any]] = []
        for url in urls:
            path = provider.capture(url)
            if path is not None:
                screenshots.append({"url": url, "path": path})

        return create_success_result(
            module=self.name,
            data=screenshots,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"count": len(screenshots)},
        )
