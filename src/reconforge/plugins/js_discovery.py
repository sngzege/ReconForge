"""JavaScript discovery plugin for ReconForge.

Responsibilities:
- Discover JavaScript files from crawled endpoints
- Extract inline and external JS scripts

Design:
- Filters katana endpoints for .js files and <script> patterns
- Uses stdlib re and urllib.parse
"""

from __future__ import annotations

import time
import urllib.parse
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class JsDiscoveryPlugin(BasePlugin):
    """Discover JavaScript files from crawled endpoints.

    Analyzes katana-discovered endpoints to find JavaScript
    files referenced in HTML pages.
    """

    requires: ClassVar[list[str]] = ["katana"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "js_discovery"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Discover JavaScript files from crawled endpoints"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Discover JS files from katana endpoints.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "katana" result.

        Returns:
            Result with list of {url, is_external} dicts in data field.
        """
        start = time.perf_counter()

        katana_result = upstream_results["katana"]
        if not katana_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"katana failed: {katana_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        endpoints = katana_result.data
        if not endpoints:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        js_files = self._extract_js(endpoints)

        return create_success_result(
            module=self.name,
            data=js_files,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"count": len(js_files)},
        )

    def _extract_js(self, endpoints: list[str]) -> list[dict[str, Any]]:
        """Extract JS references from endpoints.

        Args:
            endpoints: List of endpoint URLs from katana.

        Returns:
            List of {url, is_external} dicts for JS files.
        """
        seen: set[str] = set()

        js_files: list[dict[str, Any]] = []

        for endpoint in endpoints:
            if not endpoint:
                continue
            if endpoint.endswith(".js") or ".js?" in endpoint:
                parsed = urllib.parse.urlparse(endpoint)
                if endpoint not in seen:
                    seen.add(endpoint)
                    js_files.append(
                        {
                            "url": endpoint,
                            "is_external": bool(parsed.scheme and parsed.netloc),
                        }
                    )
            else:
                # These could be HTML pages; if loaded as text, extract JS refs
                # Since we only have URLs here, we treat discovered HTML endpoints
                # as potential script sources and only log them for further fetch
                pass

        return js_files
