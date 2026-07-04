"""DNS Resolver plugin for ReconForge.

Responsibilities:
- Resolve domain names to IP addresses
- Support both IPv4 and IPv6 resolution
- Pass through IP addresses without DNS lookup

Design:
- Uses stdlib socket.getaddrinfo() for resolution
- Reads is_ip from normalize_url metadata to skip DNS for IPs
- Returns list of IP addresses in Result.data
"""

from __future__ import annotations

import socket
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class DnsResolverPlugin(BasePlugin):
    """Resolve domain to IP addresses using stdlib socket.

    Uses socket.getaddrinfo() for DNS resolution, supporting
    both IPv4 and IPv6 addresses.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "dns_resolver"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Resolve domain to IP addresses"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Resolve domain to IP addresses.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of IP addresses in data field.
        """
        start = time.perf_counter()

        # Get normalized result from upstream
        if "normalize_url" not in upstream_results:
            return create_failure_result(
                module=self.name,
                error="normalize_url result not available in upstream_results",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        normalize_result = upstream_results["normalize_url"]

        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        is_ip = normalize_result.metadata.get("is_ip", False)

        # If input was already an IP, return as-is
        if is_ip:
            return create_success_result(
                module=self.name,
                data=[domain],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "source": "input_was_ip"},
            )

        # Resolve domain
        try:
            ips = self._resolve(domain)
            if not ips:
                return create_failure_result(
                    module=self.name,
                    error=f"No DNS records found for {domain}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            return create_success_result(
                module=self.name,
                data=sorted(ips),
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(ips)},
            )

        except socket.gaierror as e:
            return create_failure_result(
                module=self.name,
                error=f"DNS resolution failed for {domain}: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _resolve(self, domain: str) -> list[str]:
        """Resolve domain to list of IP addresses.

        Args:
            domain: Domain name to resolve.

        Returns:
            List of IP addresses (IPv4 and IPv6).
        """
        ips: set[str] = set()

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                results = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                for result in results:
                    ips.add(result[4][0])
            except socket.gaierror:
                continue

        return list(ips)
