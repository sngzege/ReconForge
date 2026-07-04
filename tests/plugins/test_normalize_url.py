"""Tests for the normalize_url plugin."""

from datetime import timedelta

import pytest

from reconforge.core.result import Result
from reconforge.plugins.normalize_url import NormalizeUrlPlugin


class TestNormalizeUrlPlugin:
    """Test NormalizeUrlPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = NormalizeUrlPlugin()
        assert plugin.name == "normalize_url"

    def test_requires_empty(self) -> None:
        """Plugin should have no upstream requirements."""
        assert NormalizeUrlPlugin.requires == []

    def test_simple_domain(self) -> None:
        """Simple domain should pass through unchanged."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("example.com", {})
        assert result.is_success
        assert result.data == "example.com"
        assert result.metadata["is_ip"] is False

    def test_uppercase_domain(self) -> None:
        """Uppercase domain should be lowercased."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("EXAMPLE.COM", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_url_with_protocol(self) -> None:
        """URL with protocol should extract hostname."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("https://example.com/path", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_url_with_port(self) -> None:
        """URL with port should extract hostname."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("http://example.com:8080", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_ipv4_address(self) -> None:
        """IPv4 address should pass through unchanged."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("192.168.1.1", {})
        assert result.is_success
        assert result.data == "192.168.1.1"
        assert result.metadata["is_ip"] is True

    def test_ipv6_address(self) -> None:
        """IPv6 address should pass through unchanged."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("::1", {})
        assert result.is_success
        assert result.data == "::1"
        assert result.metadata["is_ip"] is True

    def test_whitespace_stripped(self) -> None:
        """Leading/trailing whitespace should be stripped."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("  example.com  ", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_empty_input_fails(self) -> None:
        """Empty input should return failure result."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("", {})
        assert result.is_failure

    def test_metadata_preserves_original(self) -> None:
        """Metadata should preserve original input."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("HTTPS://EXAMPLE.COM/path", {})
        assert result.is_success
        assert result.metadata["original"] == "HTTPS://EXAMPLE.COM/path"