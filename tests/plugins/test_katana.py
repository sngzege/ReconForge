"""Tests for the katana plugin."""

from __future__ import annotations

import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.katana import KatanaPlugin


def _make_httpx_result(urls: list[str]) -> Result:
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


class TestKatanaPlugin:
    """Test KatanaPlugin."""

    def test_name(self) -> None:
        plugin = KatanaPlugin()
        assert plugin.name == "katana"

    def test_requires(self) -> None:
        assert KatanaPlugin.requires == ["httpx_alive"]

    def test_successful_run(self) -> None:
        plugin = KatanaPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "https://example.com/\nhttps://example.com/about\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "https://example.com/about" in result.data

    def test_tool_not_found(self) -> None:
        plugin = KatanaPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_input(self) -> None:
        plugin = KatanaPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        plugin = KatanaPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        timeout = subprocess.TimeoutExpired("katana", 300)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
