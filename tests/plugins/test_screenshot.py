"""Tests for screenshot provider and screenshot plugin."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.screenshot import ScreenshotPlugin
from reconforge.reporting.gowitness import GowitnessProvider


def _make_httpx_result(urls: list[str]) -> Result:
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


class TestGowitnessProvider:
    """Test GowitnessProvider."""

    def test_available_when_installed(self) -> None:
        provider = GowitnessProvider()
        with patch("shutil.which", return_value="/usr/bin/gowitness"):
            assert provider.available() is True

    def test_unavailable_when_missing(self) -> None:
        provider = GowitnessProvider()
        with patch("shutil.which", return_value=None):
            assert provider.available() is False

    def test_capture_returns_path(self) -> None:
        provider = GowitnessProvider()
        with patch("shutil.which", return_value="/usr/bin/gowitness"):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            with patch("subprocess.run", return_value=mock_proc):
                with patch.object(Path, "exists", return_value=True):
                    result = provider.capture("https://example.com")
        assert result is not None

    def test_capture_missing_tool_returns_none(self) -> None:
        provider = GowitnessProvider()
        with patch("shutil.which", return_value=None):
            assert provider.capture("https://example.com") is None


class TestScreenshotPlugin:
    """Test ScreenshotPlugin."""

    def test_name(self) -> None:
        plugin = ScreenshotPlugin()
        assert plugin.name == "screenshot"

    def test_requires(self) -> None:
        assert ScreenshotPlugin.requires == ["httpx_alive"]

    def test_no_provider_returns_failure(self) -> None:
        plugin = ScreenshotPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        with patch.object(GowitnessProvider, "available", return_value=False):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_input_returns_success(self) -> None:
        plugin = ScreenshotPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        with patch.object(GowitnessProvider, "available", return_value=True):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []
