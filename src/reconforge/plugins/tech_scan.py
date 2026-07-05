"""Technology detection plugin using whatweb.

Responsibilities:
- Detect technologies, frameworks, servers using whatweb
- Extract titles, headers, server info
- Provide technology stack overview

Design:
- Uses whatweb with JSON output
- Depends on http_alive for target URLs
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class TechScanPlugin(BasePlugin):
    """Detect technologies using whatweb."""

    requires: ClassVar[list[str]] = ["http_alive"]

    @property
    def name(self) -> str:
        return "tech_scan"

    @property
    def description(self) -> str:
        return "Detect technologies using whatweb"

    def setup(self, **kwargs: object) -> None:
        if shutil.which("whatweb") is None:
            raise RuntimeError(
                "whatweb is not installed. Install with: apt install whatweb"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        start = time.perf_counter()

        http_alive_result = upstream_results.get("http_alive")
        if not http_alive_result or not http_alive_result.is_success:
            return create_failure_result(
                module=self.name,
                error="http_alive result not available or failed",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        alive_urls = http_alive_result.data
        if not alive_urls:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        # Use first alive URL (usually main domain HTTPS)
        urls = [alive_urls[0]["url"]]

        all_techs: list[dict[str, Any]] = []

        for url in urls:
            try:
                proc = subprocess.run(
                    ["whatweb", url, "--log-json=-", "--no-errors"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                # Parse JSON from stdout (whatweb may return non-zero
                # due to Ruby stream close errors, but JSON is still valid)
                stdout = proc.stdout.strip()
                if not stdout:
                    continue

                try:
                    data = json.loads(stdout)
                    for entry in data:
                        if isinstance(entry, dict) and "plugins" in entry:
                            techs = self._extract_techs(entry)
                            all_techs.extend(techs)
                except json.JSONDecodeError:
                    continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Deduplicate
        seen = set()
        unique_techs = []
        for tech in all_techs:
            key = (tech.get("type"), tech.get("value"))
            if key not in seen:
                seen.add(key)
                unique_techs.append(tech)

        return create_success_result(
            module=self.name,
            data=unique_techs,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"url": urls[0], "count": len(unique_techs)},
        )

    def _extract_techs(self, entry: dict) -> list[dict[str, Any]]:
        """Extract technologies from whatweb entry."""
        techs = []
        plugins = entry.get("plugins", {})
        
        for plugin_name, plugin_data in plugins.items():
            if plugin_name in ["IP", "Country"]:
                continue
            
            # Extract string values
            if "string" in plugin_data:
                for val in plugin_data["string"]:
                    techs.append({
                        "type": plugin_name,
                        "value": val,
                    })
            
            # Extract module values
            if "module" in plugin_data:
                for val in plugin_data["module"]:
                    techs.append({
                        "type": plugin_name,
                        "value": val,
                    })
            
            # If no string/module, just record the plugin name
            if not plugin_data:
                techs.append({
                    "type": plugin_name,
                    "value": "detected",
                })
        
        return techs
