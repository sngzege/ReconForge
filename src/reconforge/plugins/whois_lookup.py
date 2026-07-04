"""WHOIS lookup plugin for ReconForge.

Responsibilities:
- Retrieve WHOIS information for domains
- Parse whois command output into structured data

Design:
- Calls whois via subprocess.run
- Parses key-value pairs from output
- Skips lookup for IP addresses
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class WhoisLookupPlugin(BasePlugin):
    """Retrieve WHOIS information for domains.

    Uses the whois command-line tool to query domain
    registration information.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "whois_lookup"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Retrieve WHOIS information for domains"

    def setup(self, **kwargs: object) -> None:
        """Check if whois is installed.

        Raises:
            RuntimeError: If whois is not found in PATH.
        """
        if shutil.which("whois") is None:
            raise RuntimeError(
                "whois is not installed or not in PATH. "
                "Install with: apt install whois (Kali/Debian)"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Perform WHOIS lookup.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with WHOIS data dict in data field.
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
        is_ip = normalize_result.metadata.get("is_ip", False)

        # Skip WHOIS for IP addresses
        if is_ip:
            note = "WHOIS skipped for IP address"
            return create_success_result(
                module=self.name,
                data={"domain": domain, "is_ip": True, "note": note},
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        try:
            proc = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if proc.returncode != 0:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"whois failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            # Parse WHOIS output
            whois_data = self._parse_whois(proc.stdout, domain)

            return create_success_result(
                module=self.name,
                data=whois_data,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="whois is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="whois timed out after 30 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _parse_whois(self, output: str, domain: str) -> dict[str, Any]:
        """Parse WHOIS output into structured data.

        Args:
            output: Raw WHOIS command output.
            domain: The domain being queried.

        Returns:
            Dict with parsed WHOIS fields.
        """
        data: dict[str, Any] = {"domain": domain, "is_ip": False, "raw": output}

        # Common WHOIS fields to extract
        field_mappings = {
            "Domain Name": "domain_name",
            "Registrar": "registrar",
            "Creation Date": "creation_date",
            "Registry Expiry Date": "expiration_date",
            "Updated Date": "updated_date",
            "Name Server": "name_servers",
        }

        name_servers: list[str] = []

        for line in output.splitlines():
            line = line.strip()
            if ":" not in line:
                continue

            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key in field_mappings:
                field_name = field_mappings[key]
                if field_name == "name_servers":
                    name_servers.append(value)
                else:
                    data[field_name] = value

        if "domain_name" in data:
            data["domain"] = data["domain_name"]

        if name_servers:
            data["name_servers"] = name_servers

        return data
