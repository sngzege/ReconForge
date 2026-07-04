"""Tests for the assetfinder plugin."""

import subprocess
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.assetfinder import AssetfinderPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestAssetfinderPlugin:
    """Test AssetfinderPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = AssetfinderPlugin()
        assert plugin.name == "assetfinder"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert AssetfinderPlugin.requires == ["normalize_url"]

    def test_successful_run(self) -> None:
        """Should parse assetfinder output into subdomain list."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\nsub2.example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == ["sub1.example.com", "sub2.example.com"]

    def test_tool_not_found(self) -> None:
        """Should return failure if assetfinder is not installed."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_tool_error(self) -> None:
        """Should return failure if assetfinder returns non-zero exit code."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error"

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_timeout(self) -> None:
        """Should return failure if assetfinder times out."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("assetfinder", 300)):
            result = plugin.run("example.com", upstream)

        assert result.is_failure