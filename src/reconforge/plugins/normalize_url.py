"""Normalize URL plugin for ReconForge.

Responsibilities:
- Standardize user input (domain, URL, IP) to canonical form
- Detect whether input is an IP address or domain
- Strip protocol, path, port, and trailing whitespace

Design:
- Pure Python implementation using stdlib (urllib.parse, ipaddress)
- Returns normalized string in Result.data
- Sets metadata["is_ip"] for downstream plugins
"""

from __future__ import annotations

import ipaddress
import time
from datetime import timedelta
from typing import ClassVar
from urllib.parse import urlparse

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class NormalizeUrlPlugin(BasePlugin):
    """Normalize user input to standard domain/IP format.

    Handles various input formats:
    - Plain domain: example.com → example.com
    - URL with protocol: https://example.com/path → example.com
    - URL with port: http://example.com:8080 → example.com
    - IPv4 address: 192.168.1.1 → 192.168.1.1
    - IPv6 address: ::1 → ::1
    - Uppercase: EXAMPLE.COM → example.com
    """

    requires: ClassVar[list[str]] = []

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "normalize_url"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Normalize input to standard domain/IP format"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Normalize the target input.

        Args:
            target: Raw user input (domain, URL, or IP address).
            upstream_results: Empty dict (no upstream dependencies).

        Returns:
            Result with normalized domain/IP in data field.
        """
        start = time.perf_counter()

        try:
            # Strip whitespace
            target = target.strip()

            if not target:
                return create_failure_result(
                    module=self.name,
                    error="Input cannot be empty",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            # Check if it's an IP address
            if self._is_ip(target):
                return create_success_result(
                    module=self.name,
                    data=target,
                    duration=timedelta(seconds=time.perf_counter() - start),
                    metadata={"original": target, "is_ip": True},
                )

            # Extract hostname from URL if protocol present
            normalized = self._extract_hostname(target)

            # Lowercase
            normalized = normalized.lower()

            return create_success_result(
                module=self.name,
                data=normalized,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"original": target, "is_ip": False},
            )

        except Exception as e:
            return create_failure_result(
                module=self.name,
                error=f"Normalization failed: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _is_ip(self, value: str) -> bool:
        """Check if value is a valid IP address (IPv4 or IPv6).

        Args:
            value: String to check.

        Returns:
            True if value is a valid IP address.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _extract_hostname(self, value: str) -> str:
        """Extract hostname from URL or return value as-is.

        Args:
            value: URL string or plain domain.

        Returns:
            Hostname extracted from URL, or original value.
        """
        if "://" in value:
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname
        return value