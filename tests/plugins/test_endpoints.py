"""Tests for js_discovery and endpoints plugins."""

from __future__ import annotations

from datetime import timedelta

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.endpoints import EndpointsPlugin
from reconforge.plugins.js_discovery import JsDiscoveryPlugin


def _make_katana_result(endpoints: list[str]) -> Result:
    return create_success_result(
        module="katana",
        data=endpoints,
        duration=timedelta(seconds=0),
        metadata={"count": len(endpoints)},
    )


class TestJsDiscoveryPlugin:
    """Test JsDiscoveryPlugin."""

    def test_name(self) -> None:
        plugin = JsDiscoveryPlugin()
        assert plugin.name == "js_discovery"

    def test_requires(self) -> None:
        assert JsDiscoveryPlugin.requires == ["katana"]

    def test_discovers_js_urls(self) -> None:
        plugin = JsDiscoveryPlugin()
        upstream = {
            "katana": _make_katana_result(
                [
                    "https://example.com/",
                    "https://example.com/app.js",
                    "https://cdn.example.com/lib.js?v=1",
                ]
            )
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        urls = [item["url"] for item in result.data]
        assert "https://example.com/app.js" in urls
        assert "https://cdn.example.com/lib.js?v=1" in urls

    def test_empty_input(self) -> None:
        plugin = JsDiscoveryPlugin()
        upstream = {"katana": _make_katana_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []


class TestEndpointsPlugin:
    """Test EndpointsPlugin."""

    def test_name(self) -> None:
        plugin = EndpointsPlugin()
        assert plugin.name == "endpoints"

    def test_requires(self) -> None:
        assert EndpointsPlugin.requires == ["katana"]

    def test_classifies_endpoints(self) -> None:
        plugin = EndpointsPlugin()
        upstream = {
            "katana": _make_katana_result(
                [
                    "https://example.com/admin",
                    "https://example.com/api/users",
                    "https://example.com/about",
                ]
            )
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        categories = {item["url"]: item["category"] for item in result.data}
        assert categories["https://example.com/admin"] == "sensitive"
        assert categories["https://example.com/api/users"] == "api"
        assert categories["https://example.com/about"] == "page"

    def test_empty_input(self) -> None:
        plugin = EndpointsPlugin()
        upstream = {"katana": _make_katana_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []
