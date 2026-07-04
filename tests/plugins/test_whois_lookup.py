"""Tests for the whois_lookup plugin."""

from __future__ import annotations

import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.whois_lookup import WhoisLookupPlugin


def _make_normalize_result(domain: str) -> Result:
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestWhoisLookupPlugin:
    """Test WhoisLookupPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = WhoisLookupPlugin()
        assert plugin.name == "whois_lookup"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert WhoisLookupPlugin.requires == ["normalize_url"]

    def test_successful_lookup(self) -> None:
        """Should parse whois output into structured data."""
        plugin = WhoisLookupPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        whois_output = """Domain Name: EXAMPLE.COM
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation Date: 1995-08-14
Registry Expiry Date: 2025-08-13
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET"""

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = whois_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data["domain"] == "EXAMPLE.COM"
        assert "registrar" in result.data

    def test_tool_not_found(self) -> None:
        """Should return failure if whois is not installed."""
        plugin = WhoisLookupPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_ip_address_skips_whois(self) -> None:
        """IP address input should skip whois lookup."""
        plugin = WhoisLookupPlugin()
        upstream = {
            "normalize_url": create_success_result(
                module="normalize_url",
                data="192.168.1.1",
                duration=timedelta(0),
                metadata={"original": "192.168.1.1", "is_ip": True},
            )
        }

        result = plugin.run("192.168.1.1", upstream)

        assert result.is_success
        assert result.data["is_ip"] is True

    def test_timeout(self) -> None:
        """Should return failure if whois times out."""
        plugin = WhoisLookupPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        timeout = subprocess.TimeoutExpired("whois", 30)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
