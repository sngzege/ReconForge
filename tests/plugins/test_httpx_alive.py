"""Tests for the httpx_alive plugin."""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from reconforge.core.result import Result, create_success_result
from reconforge.core.tool_resolver import ToolResolver, ToolUnavailableError
from reconforge.plugins.httpx_alive import HttpxAlivePlugin


def _make_dns_result(ips: list[str]) -> Result:
    """Helper to create a mock dns_resolver result."""
    return create_success_result(
        module="dns_resolver",
        data=ips,
        duration=timedelta(seconds=0),
        metadata={"domain": "example.com", "count": len(ips)},
    )


class TestHttpxAlivePlugin:
    """Test HttpxAlivePlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = HttpxAlivePlugin()
        assert plugin.name == "httpx_alive"

    def test_requires(self) -> None:
        """Plugin should require dns_resolver."""
        assert HttpxAlivePlugin.requires == ["dns_resolver"]

    def test_successful_run(self) -> None:
        """Should parse httpx output into alive URL list."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "https://example.com\nhttp://example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "https://example.com" in result.data
        assert "http://example.com" in result.data

    def test_json_output(self) -> None:
        """Should parse httpx JSON output into alive URL list."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        json_lines = "\n".join(
            [
                json.dumps({"url": "https://example.com", "status_code": 200}),
                json.dumps({"url": "http://example.com", "status_code": 301}),
            ]
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_lines + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "https://example.com" in result.data
        assert "http://example.com" in result.data

    def test_tool_not_found(self) -> None:
        """Should return failure if httpx is not installed."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_output(self) -> None:
        """Should return success with empty list if no alive hosts."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        """Should return failure if httpx times out."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        timeout = subprocess.TimeoutExpired("httpx", 300)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure


class TestHttpxAliveSetup:
    """Test setup() ToolResolver wiring."""

    def setup_method(self) -> None:
        """Clear the shared resolver cache before each test."""
        ToolResolver.clear_cache()

    def test_setup_raises_for_wrong_binary(self) -> None:
        """setup() should raise ToolUnavailableError for a non-PD httpx binary."""
        plugin = HttpxAlivePlugin()
        with patch("shutil.which", return_value="/fake/venv/httpx.exe"):
            probe = MagicMock()
            probe.stdout = ""
            probe.stderr = "Usage: httpx [OPTIONS] URL"
            probe.returncode = 1
            with patch("subprocess.run", return_value=probe):
                with pytest.raises(ToolUnavailableError, match="does not appear to be"):
                    plugin.setup()

    def test_setup_raises_when_missing_no_fallback(self) -> None:
        """setup() should raise when httpx is absent and fallback is off."""
        plugin = HttpxAlivePlugin()
        with patch("shutil.which", return_value=None):
            with pytest.raises(ToolUnavailableError, match="not installed"):
                plugin.setup()

    def test_setup_allows_degraded_when_fallback_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup() should not raise when fallback flag is set."""
        monkeypatch.setenv("RECONFORGE_HTTPX_FALLBACK", "1")
        plugin = HttpxAlivePlugin()
        with patch("shutil.which", return_value=None):
            # Should not raise — degraded mode is acceptable
            plugin.setup()


class TestHttpxAliveFallback:
    """Test the optional urllib fallback for degraded mode."""

    def setup_method(self) -> None:
        """Clear the shared resolver cache before each test."""
        ToolResolver.clear_cache()

    def test_fallback_triggers_on_httpx_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When flag is set and httpx subprocess fails, should use urllib fallback."""
        monkeypatch.setenv("RECONFORGE_HTTPX_FALLBACK", "1")
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        # httpx subprocess fails (wrong binary: non-zero exit, no stdout)
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Invalid value for '--json'"

        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.headers = {"Content-Type": "text/html"}

        with patch("subprocess.run", return_value=mock_proc):
            with patch("urllib.request.urlopen", return_value=fake_response):
                result = plugin.run("example.com", upstream)

        assert result.is_partial
        assert result.is_success is False  # PARTIAL, not SUCCESS
        assert len(result.data) > 0
        assert "degraded" in result.errors[0].lower()

    def test_no_fallback_when_flag_not_set(self) -> None:
        """When flag is NOT set and httpx fails, should return failure (no fallback)."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Invalid value for '--json'"

        with patch("subprocess.run", return_value=mock_proc):
            with patch("urllib.request.urlopen") as mock_urllib:
                result = plugin.run("example.com", upstream)

        assert result.is_failure
        mock_urllib.assert_not_called()

    def test_fallback_skips_unreachable_hosts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fallback should skip IPs that don't respond, include those that do."""
        monkeypatch.setenv("RECONFORGE_HTTPX_FALLBACK", "1")
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["1.2.3.4", "5.6.7.8"])}

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "error"

        import urllib.error

        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.headers = {}

        def urlopen_side_effect(req, timeout=None):  # type: ignore[no-untyped-def]
            url = str(req.full_url) if hasattr(req, "full_url") else str(req)
            if "1.2.3.4" in url:
                return fake_response
            raise urllib.error.URLError("connection refused")

        with patch("subprocess.run", return_value=mock_proc):
            with patch("urllib.request.urlopen", side_effect=urlopen_side_effect):
                result = plugin.run("example.com", upstream)

        assert result.is_partial
        # Only the reachable IP should be in the results
        alive_urls = result.data
        assert len(alive_urls) == 1
        assert "1.2.3.4" in alive_urls[0]

