"""Naabu port scanner plugin for ReconForge.

Responsibilities:
- Scan open ports on resolved hosts using naabu
- Parse naabu JSON output into structured host:port records

Design:
- Calls naabu via subprocess.run with stdin input of IPs
- Uses -silent -json flags for clean JSON-lines output
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


class NaabuPlugin(BasePlugin):
    """Scan open ports on hosts using naabu.

    naabu is a fast port scanner written in Go. This plugin
    feeds resolved IP addresses into naabu and parses the results.
    """

    requires: ClassVar[list[str]] = ["dns_resolver"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "naabu"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Scan open ports using naabu"

    def setup(self, **kwargs: object) -> None:
        """Check if naabu is installed.

        Raises:
            RuntimeError: If naabu is not found in PATH.
        """
        if shutil.which("naabu") is None:
            raise RuntimeError(
                "naabu is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/naabu"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run naabu to scan open ports.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "dns_resolver" result.

        Returns:
            Result with list of {ip, port} dicts in data field.
        """
        start = time.perf_counter()

        dns_result = upstream_results["dns_resolver"]
        if not dns_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"dns_resolver failed: {dns_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        ips = dns_result.data
        if not ips:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        try:
            input_data = "\n".join(ips)
            proc = subprocess.run(
                ["naabu", "-silent", "-json"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0 and not proc.stdout:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"naabu failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            results: list[dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    results.append(
                        {
                            "ip": entry.get("ip", ""),
                            "port": entry.get("port", 0),
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
                error="naabu is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="naabu timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
