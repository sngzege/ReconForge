"""Tests for the robots_txt plugin."""

from __future__ import annotations

import urllib.error
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.robots_txt import RobotsTxtPlugin


def _make_httpx_result(urls: list[str]) -> Result:
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


ROBOTS_CONTENT = """User-agent: *
Disallow: /admin/
Disallow: /private
Sitemap: https://example.com/sitemap.xml

# comment line"""


class TestRobotsTxtPlugin:
    """Test RobotsTxtPlugin."""

    def test_name(self) -> None:
        plugin = RobotsTxtPlugin()
        assert plugin.name == "robots_txt"

    def test_requires(self) -> None:
        assert RobotsTxtPlugin.requires == ["httpx_alive"]

    def test_successful_fetch(self) -> None:
        plugin = RobotsTxtPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = ROBOTS_CONTENT.encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["status"] == 200
        assert "/admin/" in result.data[0]["disallowed"]
        assert "https://example.com/sitemap.xml" in result.data[0]["sitemaps"]

    def test_http_error_returns_empty(self) -> None:
        plugin = RobotsTxtPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        err = urllib.error.HTTPError(
            "https://example.com/robots.txt", 404, "Not Found", MagicMock(), None
        )
        with patch("urllib.request.urlopen", side_effect=err):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["status"] == 404
        assert result.data[0]["disallowed"] == []

    def test_url_error_skipped(self) -> None:
        plugin = RobotsTxtPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://bad.invalid"])}

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("fail")):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_empty_input(self) -> None:
        plugin = RobotsTxtPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_parse_directives(self) -> None:
        plugin = RobotsTxtPlugin()
        record = plugin._parse_robots(
            "https://example.com/robots.txt", 200, ROBOTS_CONTENT
        )
        assert "/admin/" in record["disallowed"]
        assert "/private" in record["disallowed"]
        assert len(record["sitemaps"]) == 1
