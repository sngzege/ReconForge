"""Subfinder plugin for ReconForge.

Responsibilities:
- Discover subdomains using the subfinder tool
- Parse subfinder output into structured data

Design:
- Calls subfinder via subprocess.run
- Uses -silent flag for clean output (one subdomain per line)
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class SubfinderPlugin(BasePlugin):
    """Discover subdomains using the subfinder tool.

    Subfinder is a passive subdomain enumeration tool that queries
    multiple online sources for subdomains.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "subfinder"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Discover subdomains using subfinder"

    def setup(self, **kwargs: object) -> None:
        """Check if subfinder is installed.

        Raises:
            RuntimeError: If subfinder is not found in PATH.
        """
        if shutil.which("subfinder") is None:
            raise RuntimeError(
                "subfinder is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/subfinder"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run subfinder on the target domain.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of subdomains in data field.
        """
        start = time.perf_counter()

        # Get normalized domain from upstream
        normalize_result = upstream_results["normalize_url"]
        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data

        try:
            proc = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0:
                return create_failure_result(
                    module=self.name,
                    error=f"subfinder failed (exit {proc.returncode}): {proc.stderr.strip()}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            # Parse output: one subdomain per line
            subdomains = [
                line.strip()
                for line in proc.stdout.splitlines()
                if line.strip()
            ]

            return create_success_result(
                module=self.name,
                data=subdomains,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(subdomains)},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="subfinder is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="subfinder timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )