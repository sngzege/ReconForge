"""httpx alive check plugin for ReconForge.

Responsibilities:
- Check which hosts respond to HTTP/HTTPS
- Parse httpx JSON output for alive URLs

Design:
- Calls httpx via subprocess.run with stdin input
- Uses -json flag for structured output
- Falls back to plain text parsing for backward compatibility
- Optional degraded urllib fallback when RECONFORGE_HTTPX_FALLBACK is set
  and the correct projectdiscovery httpx binary is unavailable
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import (
    Result,
    create_failure_result,
    create_partial_result,
    create_success_result,
)
from reconforge.core.tool_resolver import ToolResolver, ToolUnavailableError


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

    @staticmethod
    def _fallback_enabled() -> bool:
        """Return True if the degraded urllib fallback is enabled.

        Controlled by the RECONFORGE_HTTPX_FALLBACK environment variable.
        When set to a truthy value (1, true, yes), the plugin falls back
        to a limited stdlib urllib probe when the correct projectdiscovery
        httpx binary is unavailable.
        """
        return os.environ.get("RECONFORGE_HTTPX_FALLBACK", "").lower() in (
            "1",
            "true",
            "yes",
        )

    def setup(self, **kwargs: object) -> None:
        """Check if the correct httpx binary is installed.

        Uses ToolResolver to verify the binary is the genuine
        projectdiscovery httpx (not a name-shadowing imposter).

        When RECONFORGE_HTTPX_FALLBACK is set, setup() does not raise even
        if httpx is missing or wrong — the plugin will operate in degraded
        urllib mode at runtime.

        Raises:
            ToolUnavailableError: If httpx is not installed or is the wrong
                binary and the fallback flag is not set.
        """
        try:
            ToolResolver().resolve("httpx")
        except ToolUnavailableError:
            if not self._fallback_enabled():
                raise

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run httpx to check which hosts are alive.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "dns_resolver" result.

        Returns:
            Result with list of alive URLs in data field. When operating
            in degraded urllib fallback mode, returns a PARTIAL result.
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
                if self._fallback_enabled():
                    return self._probe_with_urllib(ips, start)
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
            if self._fallback_enabled():
                return self._probe_with_urllib(ips, start)
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

    def _probe_with_urllib(self, ips: list[str], start: float) -> Result:
        """Probe IPs via stdlib urllib as a degraded fallback.

        This is a limited replacement for httpx: it only checks whether a
        host responds on HTTP/HTTPS. It cannot fingerprint servers, detect
        technologies, or provide status-code/title metadata. The result is
        PARTIAL to signal the degraded capabilities.

        Args:
            ips: List of IP addresses to probe.
            start: Pipeline start time for duration tracking.

        Returns:
            PARTIAL Result with alive URLs and a degraded-mode note.
        """
        alive_urls: list[str] = []
        for ip in ips:
            url = self._probe_ip(ip)
            if url:
                alive_urls.append(url)

        return create_partial_result(
            module=self.name,
            data=alive_urls,
            error="httpx unavailable - degraded urllib fallback "
            "(no fingerprinting/tech-detect)",
            duration=timedelta(seconds=time.perf_counter() - start),
        )

    @staticmethod
    def _probe_ip(ip: str) -> str | None:
        """Probe a single IP for HTTP/HTTPS responsiveness.

        Tries HTTPS first, then HTTP. Any HTTP response (including error
        status codes) counts as alive — only connection failures are skipped.

        Args:
            ip: IP address to probe.

        Returns:
            Alive URL string, or None if the host did not respond.
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{ip}"
            try:
                request = urllib.request.Request(
                    url, headers={"User-Agent": "ReconForge/1.0"}, method="GET"
                )
                with urllib.request.urlopen(request, timeout=10):
                    return url
            except urllib.error.HTTPError:
                # HTTP error response still means the host is alive
                return url
            except (urllib.error.URLError, TimeoutError, OSError):
                continue
        return None
