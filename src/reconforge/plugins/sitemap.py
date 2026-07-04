"""Sitemap plugin for ReconForge.

Responsibilities:
- Fetch /sitemap.xml for each alive host
- Extract URLs listed in the sitemap

Design:
- Uses stdlib urllib.request (zero external tool dependency)
- Parses XML with stdlib xml.etree.ElementTree
- Consumes httpx_alive upstream results (alive URLs)
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import timedelta
from typing import Any, ClassVar
from urllib.parse import urlparse

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class SitemapPlugin(BasePlugin):
    """Fetch and parse sitemap.xml for alive hosts.

    Retrieves the sitemap.xml file from each alive host and
    extracts the listed URLs.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "sitemap"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Fetch and parse sitemap.xml for alive hosts"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Fetch sitemap.xml for each alive URL.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of sitemap dicts in data field.
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
            record = self._fetch_sitemap(url)
            if record is not None:
                results.append(record)

        return create_success_result(
            module=self.name,
            data=results,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"count": len(results)},
        )

    def _fetch_sitemap(self, url: str) -> dict[str, Any] | None:
        """Fetch and parse sitemap.xml for a single URL.

        Args:
            url: Base URL to fetch sitemap.xml from.

        Returns:
            Dict with url, status, urls, or None on connection error.
        """
        parsed = urlparse(url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        try:
            request = urllib.request.Request(
                sitemap_url, headers={"User-Agent": "ReconForge/1.0"}
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                content = response.read()
                urls = self._parse_sitemap_xml(content)
                return {
                    "url": sitemap_url,
                    "status": response.status,
                    "urls": urls,
                    "count": len(urls),
                }
        except urllib.error.HTTPError as e:
            return {"url": sitemap_url, "status": e.code, "urls": [], "count": 0}
        except (urllib.error.URLError, TimeoutError, OSError):
            return None

    def _parse_sitemap_xml(self, content: bytes) -> list[str]:
        """Parse sitemap XML content into URL list.

        Handles both sitemapindex and urlset formats. Extracts <loc>
        elements which appear in both.

        Args:
            content: Raw sitemap XML bytes.

        Returns:
            List of URLs found in the sitemap.
        """
        urls: list[str] = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return urls
        # Strip XML namespaces for simpler matching
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "loc" and elem.text:
                urls.append(elem.text.strip())
        return urls
