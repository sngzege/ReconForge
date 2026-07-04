"""Tests for the merge_engine plugin."""

from __future__ import annotations

from datetime import timedelta

from reconforge.core.result import Result, ResultStatus, create_success_result
from reconforge.plugins.merge_engine import MergeEnginePlugin


def _make_subdomain_result(module: str, subdomains: list[str]) -> Result:
    """Helper to create a mock subdomain discovery result."""
    return create_success_result(
        module=module,
        data=subdomains,
        duration=timedelta(seconds=0),
        metadata={"domain": "example.com", "count": len(subdomains)},
    )


class TestMergeEnginePlugin:
    """Test MergeEnginePlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = MergeEnginePlugin()
        assert plugin.name == "merge_engine"

    def test_requires(self) -> None:
        """Plugin should require all subdomain sources."""
        assert set(MergeEnginePlugin.requires) == {"subfinder", "assetfinder", "crtsh"}

    def test_merge_all_sources(self) -> None:
        """Should merge subdomains from all sources."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result(
                "subfinder", ["sub1.example.com", "sub2.example.com"]
            ),
            "assetfinder": _make_subdomain_result(
                "assetfinder", ["sub2.example.com", "sub3.example.com"]
            ),
            "crtsh": _make_subdomain_result(
                "crtsh", ["sub3.example.com", "sub4.example.com"]
            ),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 4
        subdomains = [item["subdomain"] for item in result.data]
        assert "sub1.example.com" in subdomains
        assert "sub4.example.com" in subdomains

    def test_deduplication(self) -> None:
        """Should deduplicate subdomains across sources."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com"]),
            "assetfinder": _make_subdomain_result("assetfinder", ["sub1.example.com"]),
            "crtsh": _make_subdomain_result("crtsh", ["sub1.example.com"]),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 1

    def test_source_attribution(self) -> None:
        """Should track which sources found each subdomain."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com"]),
            "assetfinder": _make_subdomain_result("assetfinder", ["sub1.example.com"]),
            "crtsh": _make_subdomain_result("crtsh", []),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        item = result.data[0]
        assert "subfinder" in item["sources"]
        assert "assetfinder" in item["sources"]
        assert "crtsh" not in item["sources"]

    def test_partial_sources(self) -> None:
        """Should handle missing or failed sources gracefully."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com"]),
            "assetfinder": Result(
                module="assetfinder",
                status=ResultStatus.FAILURE,
                duration=timedelta(0),
                errors=["tool not found"],
            ),
            "crtsh": _make_subdomain_result("crtsh", ["sub2.example.com"]),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2

    def test_empty_sources(self) -> None:
        """Should return empty list if all sources are empty."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", []),
            "assetfinder": _make_subdomain_result("assetfinder", []),
            "crtsh": _make_subdomain_result("crtsh", []),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []
