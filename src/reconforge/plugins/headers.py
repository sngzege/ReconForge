"""HTTP headers plugin for ReconForge.

Responsibilities:
- Fetch HTTP response headers for alive hosts
- Parse headers into structured per-URL records

Design:
- Uses stdlib urllib.request (zero external tool dependency)
- Consumes httpx_alive upstream results (alive URLs)
- Mocked in unit tests via urllib.request.urlopen patches
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class HeadersPlugin(BasePlugin):
    """Fetch HTTP response headers for alive hosts.

    Uses stdlib urllib to retrieve response headers for each
    alive URL discovered by the httpx_alive plugin.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "headers"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Fetch HTTP response headers for alive hosts"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Fetch HTTP headers for each alive URL.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of {url, status, headers} dicts in data field.
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

        results: list[dict[str, Any]] = []
        for url in urls:
            record = self._fetch_headers(url)
            if record is not None:
                results.append(record)

        return create_success_result(
            module=self.name,
            data=results,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"count": len(results)},
        )

    def _fetch_headers(self, url: str) -> dict[str, Any] | None:
        """Fetch headers for a single URL.

        Args:
            url: URL to fetch headers for.

        Returns:
            Dict with url, status, headers, or None on error.
        """
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "ReconForge/1.0"}, method="GET"
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                headers = dict(response.headers.items())
                return {
                    "url": url,
                    "status": response.status,
                    "headers": headers,
                }
        except urllib.error.HTTPError as e:
            # HTTP error still provides useful headers
            return {
                "url": url,
                "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
            }
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
