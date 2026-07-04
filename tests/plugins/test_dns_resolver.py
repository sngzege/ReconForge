"""Tests for the dns_resolver plugin."""

import socket
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import Result, ResultStatus, create_success_result
from reconforge.plugins.dns_resolver import DnsResolverPlugin


def _make_normalize_result(data: str, is_ip: bool = False) -> Result:
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=data,
        duration=timedelta(seconds=0),
        metadata={"original": data, "is_ip": is_ip},
    )


class TestDnsResolverPlugin:
    """Test DnsResolverPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = DnsResolverPlugin()
        assert plugin.name == "dns_resolver"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert DnsResolverPlugin.requires == ["normalize_url"]

    def test_successful_resolution(self) -> None:
        """Should resolve domain to IP addresses."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_getaddrinfo = MagicMock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]
        )

        with patch("socket.getaddrinfo", mock_getaddrinfo):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "93.184.216.34" in result.data

    def test_ip_passthrough(self) -> None:
        """IP address input should return as-is without DNS lookup."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("192.168.1.1", is_ip=True)}

        result = plugin.run("192.168.1.1", upstream)

        assert result.is_success
        assert result.data == ["192.168.1.1"]

    def test_missing_upstream_fails(self) -> None:
        """Missing normalize_url result should return failure."""
        plugin = DnsResolverPlugin()
        result = plugin.run("example.com", {})
        assert result.is_failure
        assert "normalize_url" in result.errors[0]

    def test_upstream_failure_propagates(self) -> None:
        """Failed normalize_url should cause dns_resolver to fail."""
        plugin = DnsResolverPlugin()
        failed_result = Result(
            module="normalize_url",
            status=ResultStatus.FAILURE,
            duration=timedelta(0),
            errors=["normalization failed"],
        )
        upstream = {"normalize_url": failed_result}

        result = plugin.run("example.com", upstream)
        assert result.is_failure

    def test_dns_failure_returns_failure(self) -> None:
        """DNS resolution failure should return failure result."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("nonexistent.invalid")}

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS failed")):
            result = plugin.run("nonexistent.invalid", upstream)

        assert result.is_failure

    def test_multiple_ip_addresses(self) -> None:
        """Should return all resolved IP addresses."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_getaddrinfo = MagicMock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1::1", 0)),
            ]
        )

        with patch("socket.getaddrinfo", mock_getaddrinfo):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) >= 1
