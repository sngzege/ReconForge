"""Katana web crawler plugin for ReconForge.

Responsibilities:
- Crawl alive web hosts to discover endpoints and links
- Extract paths from HTML responses

Design:
- Calls katana via subprocess.run with stdin input
- Katana reads URLs from stdin natively
- Consumes httpx_alive upstream results (alive URLs)
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result
from reconforge.core.tool_resolver import ToolResolver


class KatanaPlugin(BasePlugin):
    """Crawl alive web hosts using katana to discover endpoints.

    Katana is a fast web crawler written in Go. This plugin feeds
    alive URLs into katana via stdin and collects discovered paths/links.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "katana"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Crawl web hosts to discover endpoints with katana"

    def setup(self, **kwargs: object) -> None:
        """Check if katana is installed.

        Raises:
            RuntimeError: If katana is not found in PATH.
        """
        ToolResolver().resolve("katana")

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run katana to crawl alive hosts.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of endpoint URL strings in data field.
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

        try:
            input_data = "\n".join(urls)
            proc = subprocess.run(
                ["katana"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0 and not proc.stdout:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"katana failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            endpoints = [
                line.strip() for line in proc.stdout.splitlines() if line.strip()
            ]

            return create_success_result(
                module=self.name,
                data=endpoints,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(endpoints)},
            )
        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="katana is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="katana timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
