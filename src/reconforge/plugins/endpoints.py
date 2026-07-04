"""Endpoint extraction plugin for ReconForge.

Responsibilities:
- Extract API endpoints from discovered paths
- Identify high-value endpoints (admin, API, sensitive)

Design:
- Parses katana-discovered endpoint paths
- Classifies endpoints by sensitivity pattern
- Consumes katana upstream results
"""

from __future__ import annotations

import re
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result

SENSITIVE_PATTERNS = [
    r"/admin",
    r"/login",
    r"/api",
    r"/auth",
    r"/token",
    r"/config",
    r"/backup",
    r"/debug",
    r"/graphql",
    r"/.well-known",
]


class EndpointsPlugin(BasePlugin):
    """Extract and classify API endpoints from discovered paths.

    Analyzes katana-discovered endpoints to identify interesting
    API paths and potentially sensitive endpoints.
    """

    requires: ClassVar[list[str]] = ["katana"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "endpoints"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Extract and classify API endpoints from discovered paths"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Extract endpoints from katana results.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "katana" result.

        Returns:
            Result with list of endpoint dicts in data field.
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

        extracted = self._classify_endpoints(endpoints)

        return create_success_result(
            module=self.name,
            data=extracted,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"count": len(extracted)},
        )

    def _classify_endpoints(self, endpoints: list[str]) -> list[dict[str, Any]]:
        """Classify endpoints by sensitivity.

        Args:
            endpoints: List of endpoint URLs from katana.

        Returns:
            List of {url, category, is_sensitive} dicts.
        """
        results: list[dict[str, Any]] = []
        for url in endpoints:
            if not url:
                continue
            category = self._categorize(url)
            is_sensitive = bool(category in ("admin", "api", "sensitive"))
            results.append(
                {"url": url, "category": category, "is_sensitive": is_sensitive}
            )
        return results

    def _categorize(self, url: str) -> str:
        """Categorize an endpoint URL.

        Args:
            url: Endpoint URL.

        Returns:
            Category string.
        """
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                if pattern in (r"/api", r"/graphql"):
                    return "api"
                return "sensitive"
        if any(path in url.lower() for path in [".js", ".css", "static", "assets"]):
            return "static"
        return "page"
