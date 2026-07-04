"""httpx alive check plugin for ReconForge.

Responsibilities:
- Check which hosts respond to HTTP/HTTPS
- Parse httpx JSON output for alive URLs

Design:
- Calls httpx via subprocess.run with stdin input
- Uses -json flag for structured output
- Falls back to plain text parsing for backward compatibility
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class HttpxAlivePlugin(BasePlugin):
    """Check which hosts are alive using httpx.

    httpx is a fast and multi-purpose HTTP toolkit that
    probes hosts for HTTP/HTTPS responses.
    """

    requires: ClassVar[list[str]] = ["dns_resolver"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "httpx_alive"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Check which hosts are alive via HTTP/HTTPS"

    def setup(self, **kwargs: object) -> None:
        """Check if httpx is installed.

        Raises:
            RuntimeError: If httpx is not found in PATH.
        """
        if shutil.which("httpx") is None:
            raise RuntimeError(
                "httpx is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/httpx"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run httpx to check which hosts are alive.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "dns_resolver" result.

        Returns:
            Result with list of alive URLs in data field.
        """
        start = time.perf_counter()

        dns_result = upstream_results["dns_resolver"]
        if not dns_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"dns_resolver failed: {dns_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        ips = dns_result.data
        if not ips:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        try:
            input_data = "\n".join(ips)
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

            alive_urls: list[str] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    if url:
                        alive_urls.append(url)
                except json.JSONDecodeError:
                    alive_urls.append(line)

            return create_success_result(
                module=self.name,
                data=alive_urls,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(alive_urls)},
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
