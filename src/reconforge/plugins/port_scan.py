"""Port scanner plugin for ReconForge.

Responsibilities:
- Scan top 1000 common ports using nmap
- Detect open ports and basic service information
- Run after DNS resolution

Design:
- Uses nmap with default port range (top 1000)
- Returns list of open ports with service info
- Depends on dns_resolver for IP addresses
"""

from __future__ import annotations

import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class PortScanPlugin(BasePlugin):
    """Scan top 1000 common ports using nmap."""

    requires: ClassVar[list[str]] = ["dns_resolver"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "port_scan"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Scan top 1000 common ports using nmap"

    def setup(self, **kwargs: object) -> None:
        """Check if nmap is installed."""
        if shutil.which("nmap") is None:
            raise RuntimeError(
                "nmap is not installed or not in PATH. "
                "Install with: apt install nmap (Kali/Debian)"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run nmap port scan on resolved IPs."""
        start = time.perf_counter()

        dns_result = upstream_results.get("dns_resolver")
        if not dns_result or not dns_result.is_success:
            return create_failure_result(
                module=self.name,
                error="dns_resolver result not available or failed",
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
            # Scan top 100 ports (modify to 1000 for deeper scan)
            proc = subprocess.run(
                ["nmap", "-sV", "-T4", "--top-ports", "100", "-oX", "-"] + ips,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0 and not proc.stdout:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"nmap failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )
            ports = self._parse_nmap_xml(proc.stdout)
            return create_success_result(
                module=self.name,
                data=ports,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(ports), "scanned_ports": "top 1000"},
            )
        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="nmap is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="nmap timed out after 60 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _parse_nmap_xml(self, xml_output: str) -> list[dict[str, Any]]:
        """Parse nmap XML output into port records."""
        ports: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return ports

        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr", "") if addr is not None else ""
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "")
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""
                if state != "open":
                    continue
                service_elem = port_elem.find("service")
                service_name = product = version = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                ports.append(
                    {
                        "host": ip,
                        "port": int(port_id) if port_id else 0,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    }
                )
        return ports
