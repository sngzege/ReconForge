"""Merge Engine plugin for ReconForge.

Responsibilities:
- Deduplicate subdomains from multiple sources
- Track source attribution for each subdomain
- Produce unified subdomain list

Design:
- Pure Python implementation (no external tools)
- Reads results from subfinder, assetfinder, crtsh
- Returns list of dicts with subdomain and sources
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_success_result


class MergeEnginePlugin(BasePlugin):
    """Merge and deduplicate subdomain results from multiple sources.

    Combines results from subfinder, assetfinder, and crtsh into
    a unified list with source attribution.
    """

    requires: ClassVar[list[str]] = ["subfinder", "assetfinder", "crtsh"]
    allow_partial: ClassVar[bool] = True

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "merge_engine"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Merge and deduplicate subdomain results"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Merge subdomain results from all sources.

        Args:
            target: Original target (unused).
            upstream_results: Must contain subfinder, assetfinder, crtsh results.

        Returns:
            Result with deduplicated subdomain list in data field.
            Each item is a dict: {"subdomain": str, "sources": list[str]}
        """
        start = time.perf_counter()

        # Collect subdomains with source attribution
        subdomain_sources: dict[str, list[str]] = {}

        for source_name in self.requires:
            source_result = upstream_results.get(source_name)
            if not source_result or not source_result.is_success:
                continue

            subdomains = source_result.data
            if not isinstance(subdomains, list):
                continue

            for subdomain in subdomains:
                if subdomain not in subdomain_sources:
                    subdomain_sources[subdomain] = []
                subdomain_sources[subdomain].append(source_name)

        # Build result list
        merged_data: list[dict[str, Any]] = [
            {"subdomain": subdomain, "sources": sources}
            for subdomain, sources in sorted(subdomain_sources.items())
        ]

        return create_success_result(
            module=self.name,
            data=merged_data,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={
                "total_unique": len(merged_data),
                "sources_processed": len(self.requires),
            },
        )
