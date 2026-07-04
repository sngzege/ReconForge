"""Technology detection plugin for ReconForge.

Responsibilities:
- Detect web technologies (frameworks, CMS, servers) on alive hosts
- Parse httpx -tech-detect JSON output

Design:
- Calls httpx via subprocess.run with -tech-detect -json flags
- Consumes http_fingerprint upstream results (alive URLs)
- Mocked in unit tests, real tool in integration tests
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


class TechDetectPlugin(BasePlugin):
    """Detect web technologies using httpx tech-detect.

    Identifies frameworks, CMS platforms, and other technologies
    running on the target's web services.
    """

    requires: ClassVar[list[str]] = ["http_fingerprint"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "tech_detect"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Detect web technologies (frameworks, CMS, servers)"

    def setup(self, **kwargs: object) -> None:
        """Check if httpx is installed.

        Raises:
            RuntimeError: If httpx is not found in PATH.
        """
        if shutil.which("httpx") is None:
            raise RuntimeError(
                "httpx is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/httpx"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Detect technologies on alive hosts.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "http_fingerprint" result.

        Returns:
            Result with list of {url, technologies} dicts in data field.
        """
        start = time.perf_counter()

        fingerprint_result = upstream_results["http_fingerprint"]
        if not fingerprint_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"http_fingerprint failed: {fingerprint_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        fingerprints = fingerprint_result.data
        if not fingerprints:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        urls = [fp.get("url", "") for fp in fingerprints if fp.get("url")]
        if not urls:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        try:
            input_data = "\n".join(urls)
            proc = subprocess.run(
                ["httpx", "-tech-detect", "-json"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode != 0 and not proc.stdout:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"httpx failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            results: list[dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    techs = data.get("technologies", [])
                    results.append(
                        {
                            "url": data.get("url", ""),
                            "technologies": techs if isinstance(techs, list) else [],
                        }
                    )
                except json.JSONDecodeError:
                    continue

            return create_success_result(
                module=self.name,
                data=results,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(results)},
            )
        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="httpx is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="httpx timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
