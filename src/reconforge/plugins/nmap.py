"""Nmap service detection plugin for ReconForge.

Detect services and versions on open ports using nmap. Consumes naabu
results and runs nmap service version detection (-sV, XML to stdout).
Mocked in unit tests, real tool in integration tests.
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


class NmapPlugin(BasePlugin):
    """Detect services and versions on open ports using nmap."""

    requires: ClassVar[list[str]] = ["naabu"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "nmap"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Detect services and versions using nmap"

    def setup(self, **kwargs: object) -> None:
        """Check if nmap is installed.

        Raises:
            RuntimeError: If nmap is not found in PATH.
        """
        if shutil.which("nmap") is None:
            raise RuntimeError(
                "nmap is not installed or not in PATH. "
                "Install with: apt install nmap (Kali/Debian)"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run nmap service detection on open ports from naabu.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "naabu" result.

        Returns:
            Result with list of service dicts in data field.
        """
        start = time.perf_counter()

        naabu_result = upstream_results["naabu"]
        if not naabu_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"naabu failed: {naabu_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        ports = naabu_result.data
        if not ports:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        targets = self._build_targets(ports)
        if not targets:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        try:
            proc = subprocess.run(
                ["nmap", "-sV", "-oX", "-"] + targets,
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode != 0 and not proc.stdout:
                stderr = proc.stderr.strip()
                return create_failure_result(
                    module=self.name,
                    error=f"nmap failed (exit {proc.returncode}): {stderr}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )
            services = self._parse_nmap_xml(proc.stdout)
            return create_success_result(
                module=self.name,
                data=services,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(services)},
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
                error="nmap timed out after 600 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _build_targets(self, ports: list[dict[str, Any]]) -> list[str]:
        """Build nmap target arguments grouping ports by IP.

        Args:
            ports: List of {ip, port} dicts from naabu.

        Returns:
            List of nmap target spec strings (e.g. "ip -p ports").
        """
        by_ip: dict[str, list[int]] = {}
        for entry in ports:
            ip = entry.get("ip", "")
            port = entry.get("port", 0)
            if ip and port:
                by_ip.setdefault(ip, []).append(int(port))
        targets: list[str] = []
        for ip, ip_ports in by_ip.items():
            port_list = ",".join(str(p) for p in sorted(set(ip_ports)))
            targets.append(f"{ip} -p {port_list}")
        return targets

    def _parse_nmap_xml(self, xml_output: str) -> list[dict[str, Any]]:
        """Parse nmap XML output into service records.

        Args:
            xml_output: Raw nmap XML string.

        Returns:
            List of {host, port, protocol, service, product, version} dicts.
        """
        services: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return services
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
                services.append(
                    {
                        "host": ip,
                        "port": int(port_id) if port_id else 0,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    }
                )
        return services
