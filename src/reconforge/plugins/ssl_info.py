"""SSL/TLS certificate analysis plugin for ReconForge.

Responsibilities:
- Extract SSL certificate information
- Find Subject Alternative Names (SANs) for additional subdomains
- Check certificate validity

Design:
- Uses stdlib ssl module (no external tool needed)
- Depends on dns_resolver for target IPs
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class SslInfoPlugin(BasePlugin):
    """Analyze SSL certificates."""

    requires: ClassVar[list[str]] = ["normalize_url", "dns_resolver"]

    @property
    def name(self) -> str:
        return "ssl_info"

    @property
    def description(self) -> str:
        return "SSL/TLS certificate analysis"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        start = time.perf_counter()

        normalize_result = upstream_results.get("normalize_url")
        if not normalize_result or not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error="normalize_url result not available or failed",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        is_ip = normalize_result.metadata.get("is_ip", False)

        # Skip SSL check for IP addresses
        if is_ip:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"skipped": "ip_address"},
            )

        cert_info = self._get_cert_info(domain)

        if cert_info:
            return create_success_result(
                module=self.name,
                data=[cert_info],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "sans_count": len(cert_info.get("sans", []))},
            )
        else:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "error": "no_ssl"},
            )

    def _get_cert_info(self, domain: str) -> dict[str, Any] | None:
        """Get SSL certificate info for domain."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return None

                    # Extract certificate fields
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    
                    # Get SANs
                    sans = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        if san_type == "DNS":
                            sans.append(san_value)

                    return {
                        "domain": domain,
                        "subject": subject.get("commonName", ""),
                        "issuer": issuer.get("organizationName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                        "sans": sans,
                    }
        except Exception:
            return None
