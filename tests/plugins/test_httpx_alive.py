"""Tests for the httpx_alive plugin."""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.httpx_alive import HttpxAlivePlugin


def _make_dns_result(ips: list[str]) -> Result:
    """Helper to create a mock dns_resolver result."""
    return create_success_result(
        module="dns_resolver",
        data=ips,
        duration=timedelta(seconds=0),
        metadata={"domain": "example.com", "count": len(ips)},
    )


class TestHttpxAlivePlugin:
    """Test HttpxAlivePlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = HttpxAlivePlugin()
        assert plugin.name == "httpx_alive"

    def test_requires(self) -> None:
        """Plugin should require dns_resolver."""
        assert HttpxAlivePlugin.requires == ["dns_resolver"]

    def test_successful_run(self) -> None:
        """Should parse httpx output into alive URL list."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "https://example.com\nhttp://example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "https://example.com" in result.data
        assert "http://example.com" in result.data

    def test_json_output(self) -> None:
        """Should parse httpx JSON output into alive URL list."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        json_lines = "\n".join(
            [
                json.dumps({"url": "https://example.com", "status_code": 200}),
                json.dumps({"url": "http://example.com", "status_code": 301}),
            ]
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_lines + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "https://example.com" in result.data
        assert "http://example.com" in result.data

    def test_tool_not_found(self) -> None:
        """Should return failure if httpx is not installed."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_output(self) -> None:
        """Should return success with empty list if no alive hosts."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        """Should return failure if httpx times out."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        timeout = subprocess.TimeoutExpired("httpx", 300)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
