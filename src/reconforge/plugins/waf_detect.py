"""WAF detection plugin for ReconForge.

Responsibilities:
- Detect Web Application Firewalls using wafw00f
- Identify WAF vendor and product

Design:
- Uses wafw00f tool
- Depends on http_alive for target URLs
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class WafDetectPlugin(BasePlugin):
    """Detect WAF using wafw00f."""

    requires: ClassVar[list[str]] = ["http_alive"]

    @property
    def name(self) -> str:
        return "waf_detect"

    @property
    def description(self) -> str:
        return "Detect Web Application Firewalls using wafw00f"

    def setup(self, **kwargs: object) -> None:
        if shutil.which("wafw00f") is None:
            raise RuntimeError(
                "wafw00f is not installed. Install with: apt install wafw00f"
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

        # Check first alive URL (usually main domain)
        url_to_check = alive_urls[0]["url"]
        waf_info = self._detect_waf(url_to_check)

        results = []
        if waf_info:
            results.append(waf_info)

        return create_success_result(
            module=self.name,
            data=results,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={"checked_url": url_to_check, "waf_found": len(results) > 0},
        )

    def _detect_waf(self, url: str) -> dict | None:
        """Run wafw00f and parse output."""
        try:
            proc = subprocess.run(
                ["wafw00f", url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = proc.stdout + proc.stderr

            # Parse output for WAF detection
            # Example: "[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
            if "is behind" in output:
                # Extract WAF name
                for line in output.splitlines():
                    if "is behind" in line:
                        # Extract between "behind" and "WAF"
                        parts = line.split("behind")
                        if len(parts) > 1:
                            waf_part = parts[1].split("WAF")[0].strip()
                            # Clean up ANSI codes
                            import re
                            waf_clean = re.sub(r'\x1b\[[0-9;]*m', '', waf_part)
                            return {
                                "url": url,
                                "waf_detected": True,
                                "waf_name": waf_clean.strip(" ."),
                            }
            elif "No WAF detected" in output or "is not behind" in output:
                return {
                    "url": url,
                    "waf_detected": False,
                    "waf_name": None,
                }
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
