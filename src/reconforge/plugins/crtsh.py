"""crt.sh plugin for ReconForge.

Responsibilities:
- Discover subdomains via crt.sh certificate transparency logs
- Parse JSON response from crt.sh API

Design:
- Uses urllib.request for HTTP (no external dependencies)
- Queries https://crt.sh/?q=<domain>&output=json
- Deduplicates results
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class CrtshPlugin(BasePlugin):
    """Discover subdomains via crt.sh certificate transparency.

    Queries the crt.sh API for certificate transparency logs
    associated with the target domain.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "crtsh"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Discover subdomains via crt.sh certificate transparency"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Query crt.sh for subdomains.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of subdomains in data field.
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
        url = f"https://crt.sh/?q={domain}&output=json"

        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ReconForge/1.0"},
            )

            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode())

            # Extract and deduplicate subdomains
            subdomains: set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip()
                    if name:
                        subdomains.add(name)

            result_list = sorted(subdomains)

            return create_success_result(
                module=self.name,
                data=result_list,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(result_list)},
            )

        except urllib.error.HTTPError as e:
            return create_failure_result(
                module=self.name,
                error=f"crt.sh HTTP error: {e.code} {e.reason}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except urllib.error.URLError as e:
            return create_failure_result(
                module=self.name,
                error=f"crt.sh connection error: {e.reason}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except (json.JSONDecodeError, KeyError) as e:
            return create_failure_result(
                module=self.name,
                error=f"crt.sh response parsing error: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )