"""Tests for the naabu plugin."""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.naabu import NaabuPlugin


def _make_dns_result(ips: list[str]) -> Result:
    """Helper to create a mock dns_resolver result."""
    return create_success_result(
        module="dns_resolver",
        data=ips,
        duration=timedelta(seconds=0),
        metadata={"domain": "example.com", "count": len(ips)},
    )


class TestNaabuPlugin:
    """Test NaabuPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = NaabuPlugin()
        assert plugin.name == "naabu"

    def test_requires(self) -> None:
        """Plugin should require dns_resolver."""
        assert NaabuPlugin.requires == ["dns_resolver"]

    def test_successful_run(self) -> None:
        """Should parse naabu JSON output into port records."""
        plugin = NaabuPlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        json_lines = "\n".join(
            [
                json.dumps({"ip": "93.184.216.34", "port": 80}),
                json.dumps({"ip": "93.184.216.34", "port": 443}),
            ]
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_lines + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2
        assert result.data[0]["port"] in (80, 443)

    def test_tool_not_found(self) -> None:
        """Should return failure if naabu is not installed."""
        plugin = NaabuPlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_output(self) -> None:
        """Should return success with empty list if no open ports."""
        plugin = NaabuPlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_empty_ip_list(self) -> None:
        """Should return success with empty list if no IPs to scan."""
        plugin = NaabuPlugin()
        upstream = {"dns_resolver": _make_dns_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        """Should return failure if naabu times out."""
        plugin = NaabuPlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        timeout = subprocess.TimeoutExpired("naabu", 300)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_dedup_duplicate_ports(self) -> None:
        """Should deduplicate naabu records by (ip, port)."""
        plugin = NaabuPlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        # naabu emits duplicate (ip, port) records (e.g. one per protocol pass)
        json_lines = "\n".join(
            [
                json.dumps({"ip": "93.184.216.34", "port": 443}),
                json.dumps({"ip": "93.184.216.34", "port": 443}),
                json.dumps({"ip": "93.184.216.34", "port": 80}),
                json.dumps({"ip": "93.184.216.34", "port": 80}),
                json.dumps({"ip": "93.184.216.34", "port": 81}),
            ]
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_lines + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 3
        pairs = {(d["ip"], d["port"]) for d in result.data}
        assert pairs == {
            ("93.184.216.34", 443),
            ("93.184.216.34", 80),
            ("93.184.216.34", 81),
        }

