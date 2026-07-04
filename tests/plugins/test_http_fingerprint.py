"""Tests for the http_fingerprint plugin."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.http_fingerprint import HttpFingerprintPlugin


def _make_httpx_result(urls: list[str]) -> Result:
    """Helper to create a mock httpx_alive result."""
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


class TestHttpFingerprintPlugin:
    """Test HttpFingerprintPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = HttpFingerprintPlugin()
        assert plugin.name == "http_fingerprint"

    def test_requires(self) -> None:
        """Plugin should require httpx_alive."""
        assert HttpFingerprintPlugin.requires == ["httpx_alive"]

    def test_successful_run(self) -> None:
        """Should parse httpx JSON output into fingerprint list."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        json_output = json.dumps({
            "url": "https://example.com",
            "status_code": 200,
            "webserver": "nginx",
            "title": "Example Domain",
        })

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_output + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 1
        assert result.data[0]["url"] == "https://example.com"
        assert result.data[0]["status_code"] == 200

    def test_tool_not_found(self) -> None:
        """Should return failure if httpx is not installed."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_input(self) -> None:
        """Should return success with empty list if no URLs to fingerprint."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_multiple_urls(self) -> None:
        """Should fingerprint multiple URLs."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive":
                    _make_httpx_result(["https://example.com", "https://api.example.com"])}

        json_lines = "\n".join([
            json.dumps({"url": "https://example.com", "status_code": 200}),
            json.dumps({"url": "https://api.example.com", "status_code": 301}),
        ])

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_lines + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2
        assert result.data[0]["url"] == "https://example.com"
        assert result.data[1]["url"] == "https://api.example.com"
