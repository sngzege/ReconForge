"""HTTP fingerprint plugin for ReconForge.

Responsibilities:
- Fingerprint HTTP responses (server, status, title)
- Parse httpx JSON output for detailed info

Design:
- Calls httpx via subprocess.run with -json flag
- Parses JSON lines output
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result
from reconforge.core.tool_resolver import ToolResolver


class HttpFingerprintPlugin(BasePlugin):
    """Fingerprint HTTP responses using httpx.

    Extracts server headers, status codes, page titles,
    and other HTTP response metadata.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "http_fingerprint"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Fingerprint HTTP responses (server, status, title)"

    def setup(self, **kwargs: object) -> None:
        """Check if httpx is installed.

        Raises:
            RuntimeError: If httpx is not found in PATH.
        """
        ToolResolver().resolve("httpx")

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Fingerprint HTTP responses.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of fingerprint dicts in data field.
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
                ["httpx", "-json"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0 and not proc.stdout:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"httpx failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            fingerprints: list[dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    fingerprints.append(
                        {
                            "url": data.get("url", ""),
                            "status_code": data.get("status_code", 0),
                            "server": data.get("webserver", ""),
                            "title": data.get("title", ""),
                        }
                    )
                except json.JSONDecodeError:
                    continue

            return create_success_result(
                module=self.name,
                data=fingerprints,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(fingerprints)},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="httpx is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="httpx timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
