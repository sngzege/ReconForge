"""Integration tests for plugins with real tools.

These tests run only on Kali Linux with tools installed.
Run with: pytest tests/integration/
Skip with: pytest -m "not integration"
"""

import shutil

import pytest


@pytest.mark.integration
@pytest.mark.skipif(
    shutil.which("subfinder") is None,
    reason="subfinder not installed",
)
class TestSubfinderIntegration:
    """Integration tests for subfinder plugin."""

    def test_real_subfinder(self) -> None:
        """Test subfinder with real tool on example.com."""
        from reconforge.plugins.subfinder import SubfinderPlugin

        plugin = SubfinderPlugin()
        result = plugin.run("example.com", {})
        assert result.is_success
        assert len(result.data) > 0


@pytest.mark.integration
@pytest.mark.skipif(
    shutil.which("httpx") is None,
    reason="httpx not installed",
)
class TestHttpxIntegration:
    """Integration tests for httpx_alive plugin."""

    def test_real_httpx(self) -> None:
        """Test httpx with real tool."""
        from reconforge.plugins.httpx_alive import HttpxAlivePlugin

        plugin = HttpxAlivePlugin()
        result = plugin.run("example.com", {})
        assert result.is_success