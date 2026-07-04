"""Tests for the sitemap plugin."""

from __future__ import annotations

import urllib.error
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.sitemap import SitemapPlugin


def _make_httpx_result(urls: list[str]) -> Result:
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


SITEMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/contact</loc></url>
</urlset>"""


class TestSitemapPlugin:
    """Test SitemapPlugin."""

    def test_name(self) -> None:
        plugin = SitemapPlugin()
        assert plugin.name == "sitemap"

    def test_requires(self) -> None:
        assert SitemapPlugin.requires == ["httpx_alive"]

    def test_successful_fetch(self) -> None:
        plugin = SitemapPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = SITEMAP_XML

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["status"] == 200
        assert len(result.data[0]["urls"]) == 3
        assert "https://example.com/about" in result.data[0]["urls"]

    def test_http_error_returns_empty(self) -> None:
        plugin = SitemapPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        err = urllib.error.HTTPError(
            "https://example.com/sitemap.xml", 404, "Not Found", MagicMock(), None
        )
        with patch("urllib.request.urlopen", side_effect=err):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["status"] == 404
        assert result.data[0]["urls"] == []

    def test_url_error_skipped(self) -> None:
        plugin = SitemapPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://bad.invalid"])}

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("fail")):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_empty_input(self) -> None:
        plugin = SitemapPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_parse_xml_with_namespace(self) -> None:
        plugin = SitemapPlugin()
        urls = plugin._parse_sitemap_xml(SITEMAP_XML)
        assert len(urls) == 3
