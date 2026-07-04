"""Tests for the headers plugin."""

from __future__ import annotations

import urllib.error
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.headers import HeadersPlugin


def _make_httpx_result(urls: list[str]) -> Result:
    """Helper to create a mock httpx_alive result."""
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


class TestHeadersPlugin:
    """Test HeadersPlugin."""

    def test_name(self) -> None:
        plugin = HeadersPlugin()
        assert plugin.name == "headers"

    def test_requires(self) -> None:
        assert HeadersPlugin.requires == ["httpx_alive"]

    def test_successful_fetch(self) -> None:
        plugin = HeadersPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers.items.return_value = [
            ("Server", "nginx"),
            ("Content-Type", "text/html"),
        ]

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["status"] == 200
        assert result.data[0]["headers"]["Server"] == "nginx"

    def test_http_error_still_returns_headers(self) -> None:
        plugin = HeadersPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        err = urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", MagicMock(), None
        )

        with patch("urllib.request.urlopen", side_effect=err):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["status"] == 404

    def test_url_error_skipped(self) -> None:
        plugin = HeadersPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://bad.invalid"])}

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("fail")):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_empty_input(self) -> None:
        plugin = HeadersPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []
