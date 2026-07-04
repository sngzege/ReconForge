"""Tests for the crtsh plugin."""

import json
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.crtsh import CrtshPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestCrtshPlugin:
    """Test CrtshPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = CrtshPlugin()
        assert plugin.name == "crtsh"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert CrtshPlugin.requires == ["normalize_url"]

    def test_successful_run(self) -> None:
        """Should parse crt.sh JSON response into subdomain list."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            [
                {"name_value": "sub1.example.com"},
                {"name_value": "sub2.example.com"},
                {"name_value": "*.example.com"},
            ]
        ).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "sub1.example.com" in result.data
        assert "sub2.example.com" in result.data

    def test_wildcard_expanded(self) -> None:
        """Wildcard entries should be included as-is."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            [
                {"name_value": "*.example.com"},
            ]
        ).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "*.example.com" in result.data

    def test_http_error(self) -> None:
        """Should return failure on HTTP error."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        from urllib.error import HTTPError

        with patch(
            "urllib.request.urlopen",
            side_effect=HTTPError("", 500, "Server Error", {}, None),
        ):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_timeout(self) -> None:
        """Should return failure on timeout."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        import urllib.error

        with patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")
        ):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_response(self) -> None:
        """Should return success with empty list if no results."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps([]).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_deduplication(self) -> None:
        """Should deduplicate subdomains from crt.sh."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            [
                {"name_value": "sub1.example.com"},
                {"name_value": "sub1.example.com"},
                {"name_value": "sub2.example.com"},
            ]
        ).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2
