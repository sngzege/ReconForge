"""Wayback Machine plugin for ReconForge.

Responsibilities:
- Query the Wayback Machine CDX API for archived URLs
- Deduplicate and return historical URL records

Design:
- Uses stdlib urllib.request (zero external tool dependency)
- Queries https://web.archive.org/cdx/search/cdx
- Consumes normalize_url upstream results (domain)
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result

# Wayback CDX API endpoint
CDX_API = "https://web.archive.org/cdx/search/cdx"


class WaybackPlugin(BasePlugin):
    """Query the Wayback Machine for archived URLs.

    Uses the Wayback CDX API to discover historical URLs
    associated with the target domain.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "wayback"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Query Wayback Machine for archived URLs"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Query Wayback Machine for archived URLs.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of archived URL strings in data field.
        """
        start = time.perf_counter()

        normalize_result = upstream_results["normalize_url"]
        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        url = self._build_query(domain)

        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "ReconForge/1.0"}
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read().decode("utf-8", errors="replace")

            urls = self._parse_cdx_response(raw)
            return create_success_result(
                module=self.name,
                data=urls,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(urls)},
            )
        except urllib.error.HTTPError as e:
            return create_failure_result(
                module=self.name,
                error=f"Wayback HTTP error: {e.code} {e.reason}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return create_failure_result(
                module=self.name,
                error=f"Wayback request failed: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _build_query(self, domain: str) -> str:
        """Build the Wayback CDX API query URL.

        Args:
            domain: Domain to query (e.g. example.com).

        Returns:
            Full CDX API URL string.
        """
        params = urllib.parse.urlencode(
            {
                "url": f"*.{domain}/*",
                "output": "json",
                "collapse": "urlkey",
                "fl": "original",
            }
        )
        return f"{CDX_API}?{params}"

    def _parse_cdx_response(self, raw: str) -> list[str]:
        """Parse the CDX JSON response into a URL list.

        The CDX API returns a JSON array where the first row is the
        header and subsequent rows are values for the 'original' field.

        Args:
            raw: Raw JSON response text.

        Returns:
            Deduplicated list of archived URLs.
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list) or len(data) < 2:
            return []
        # First row is header; remaining rows are values
        urls: list[str] = []
        seen: set[str] = set()
        for row in data[1:]:
            if row and isinstance(row, list) and row[0] not in seen:
                seen.add(row[0])
                urls.append(row[0])
        return urls
