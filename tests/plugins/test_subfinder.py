"""Tests for the subfinder plugin."""

import subprocess
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.subfinder import SubfinderPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestSubfinderPlugin:
    """Test SubfinderPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = SubfinderPlugin()
        assert plugin.name == "subfinder"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert SubfinderPlugin.requires == ["normalize_url"]

    def test_successful_run(self) -> None:
        """Should parse subfinder output into subdomain list."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\nsub2.example.com\napi.example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == [
            "sub1.example.com",
            "sub2.example.com",
            "api.example.com",
        ]
        mock_run.assert_called_once()

    def test_tool_not_found(self) -> None:
        """Should return failure if subfinder is not installed."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch(
            "subprocess.run", side_effect=FileNotFoundError("subfinder not found")
        ):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
        assert (
            "not found" in result.errors[0].lower()
            or "not installed" in result.errors[0].lower()
        )

    def test_tool_error(self) -> None:
        """Should return failure if subfinder returns non-zero exit code."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error: invalid target"

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_timeout(self) -> None:
        """Should return failure if subfinder times out."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("subfinder", 300)
        ):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
        assert (
            "timed out" in result.errors[0].lower()
            or "timeout" in result.errors[0].lower()
        )

    def test_empty_output(self) -> None:
        """Should return success with empty list if no subdomains found."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_whitespace_lines_filtered(self) -> None:
        """Should filter out empty and whitespace-only lines."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\n\n  \nsub2.example.com\n"

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == ["sub1.example.com", "sub2.example.com"]
