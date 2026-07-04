"""robots.txt plugin for ReconForge.

Responsibilities:
- Fetch /robots.txt for each alive host
- Parse directives (Allow, Disallow, Sitemap, User-agent)

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
from urllib.parse import urlparse

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class RobotsTxtPlugin(BasePlugin):
    """Fetch and parse robots.txt for alive hosts.

    Retrieves the robots.txt file from each alive host and
    extracts its directives into a structured form.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "robots_txt"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Fetch and parse robots.txt for alive hosts"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Fetch robots.txt for each alive URL.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of robots.txt dicts in data field.
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
            record = self._fetch_robots(url)
            if record is not None:
                results.append(record)

        return create_success_result(
            module=self.name,
            data=results,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"count": len(results)},
        )

    def _fetch_robots(self, url: str) -> dict[str, Any] | None:
        """Fetch and parse robots.txt for a single URL.

        Args:
            url: Base URL to fetch robots.txt from.

        Returns:
            Dict with url, status, content, disallowed, sitemaps, or None.
        """
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            request = urllib.request.Request(
                robots_url, headers={"User-Agent": "ReconForge/1.0"}
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                content = response.read().decode("utf-8", errors="replace")
                return self._parse_robots(robots_url, response.status, content)
        except urllib.error.HTTPError as e:
            return {
                "url": robots_url,
                "status": e.code,
                "content": "",
                "disallowed": [],
                "sitemaps": [],
            }
        except (urllib.error.URLError, TimeoutError, OSError):
            return None

    def _parse_robots(self, url: str, status: int, content: str) -> dict[str, Any]:
        """Parse robots.txt content into directives.

        Args:
            url: robots.txt URL.
            status: HTTP status code.
            content: robots.txt raw content.

        Returns:
            Dict with parsed directives.
        """
        disallowed: list[str] = []
        sitemaps: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "disallow" and value:
                disallowed.append(value)
            elif key == "sitemap" and value:
                sitemaps.append(value)
        return {
            "url": url,
            "status": status,
            "content": content,
            "disallowed": disallowed,
            "sitemaps": sitemaps,
        }
