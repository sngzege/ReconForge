"""Tests for the nmap plugin."""

from __future__ import annotations

import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.nmap import NmapPlugin


def _make_naabu_result(ports: list[dict]) -> Result:
    """Helper to create a mock naabu result."""
    return create_success_result(
        module="naabu",
        data=ports,
        duration=timedelta(seconds=0),
        metadata={"count": len(ports)},
    )


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestNmapPlugin:
    """Test NmapPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = NmapPlugin()
        assert plugin.name == "nmap"

    def test_requires(self) -> None:
        """Plugin should require naabu."""
        assert NmapPlugin.requires == ["naabu"]

    def test_successful_run(self) -> None:
        """Should parse nmap XML output into service records."""
        plugin = NmapPlugin()
        upstream = {"naabu": _make_naabu_result([{"ip": "93.184.216.34", "port": 80}])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = NMAP_XML
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 1
        assert result.data[0]["port"] == 80
        assert result.data[0]["service"] == "http"
        assert result.data[0]["product"] == "nginx"

    def test_closed_ports_filtered(self) -> None:
        """Closed ports should be excluded from results."""
        plugin = NmapPlugin()
        upstream = {"naabu": _make_naabu_result([{"ip": "93.184.216.34", "port": 22}])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = NMAP_XML

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        ports = [s["port"] for s in result.data]
        assert 22 not in ports

    def test_tool_not_found(self) -> None:
        """Should return failure if nmap is not installed."""
        plugin = NmapPlugin()
        upstream = {"naabu": _make_naabu_result([{"ip": "93.184.216.34", "port": 80}])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_ports(self) -> None:
        """Should return success with empty list if no ports to scan."""
        plugin = NmapPlugin()
        upstream = {"naabu": _make_naabu_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        """Should return failure if nmap times out."""
        plugin = NmapPlugin()
        upstream = {"naabu": _make_naabu_result([{"ip": "93.184.216.34", "port": 80}])}

        timeout = subprocess.TimeoutExpired("nmap", 600)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_build_targets_groups_ports(self) -> None:
        """_build_targets should group ports by IP."""
        plugin = NmapPlugin()
        ports = [
            {"ip": "1.1.1.1", "port": 80},
            {"ip": "1.1.1.1", "port": 443},
            {"ip": "2.2.2.2", "port": 22},
        ]
        targets = plugin._build_targets(ports)
        assert len(targets) == 2
        assert any("1.1.1.1" in t and "80" in t and "443" in t for t in targets)
