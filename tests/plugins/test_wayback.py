"""Tests for the wayback plugin."""

from __future__ import annotations

import json
import urllib.error
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.wayback import WaybackPlugin


def _make_normalize_result(domain: str) -> Result:
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestWaybackPlugin:
    """Test WaybackPlugin."""

    def test_name(self) -> None:
        plugin = WaybackPlugin()
        assert plugin.name == "wayback"

    def test_requires(self) -> None:
        assert WaybackPlugin.requires == ["normalize_url"]

    def test_successful_query(self) -> None:
        plugin = WaybackPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        cdx_response = json.dumps(
            [
                ["original"],
                ["https://example.com/"],
                ["https://example.com/about"],
                ["https://example.com/"],
            ]
        )

        mock_response = MagicMock()
        mock_response.read.return_value = cdx_response.encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2
        assert "https://example.com/about" in result.data

    def test_http_error(self) -> None:
        plugin = WaybackPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        err = urllib.error.HTTPError(
            "https://web.archive.org", 500, "Server Error", MagicMock(), None
        )
        with patch("urllib.request.urlopen", side_effect=err):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_url_error(self) -> None:
        plugin = WaybackPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_response(self) -> None:
        plugin = WaybackPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps([]).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_build_query(self) -> None:
        plugin = WaybackPlugin()
        url = plugin._build_query("example.com")
        assert "web.archive.org" in url
        assert "example.com" in url
