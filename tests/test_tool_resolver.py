"""Tests for the ToolResolver.

The resolver verifies that an external security tool is both present on PATH
and the *correct* binary (e.g. projectdiscovery httpx rather than the
unrelated Python httpx CLI that can shadow it). It raises ToolUnavailableError
with a clear message when the tool is missing or is the wrong program.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from reconforge.core.tool_resolver import ToolResolver, ToolUnavailableError


class TestToolResolver:
    """Test ToolResolver binary verification logic."""

    def setup_method(self) -> None:
        """Clear the shared cache before each test."""
        ToolResolver.clear_cache()

    def test_missing_tool_raises(self) -> None:
        """A tool not on PATH should raise ToolUnavailableError."""
        with patch("shutil.which", return_value=None):
            with pytest.raises(ToolUnavailableError, match="not installed"):
                ToolResolver().resolve("httpx")

    def test_correct_projectdiscovery_binary_returns_path(self) -> None:
        """A genuine projectdiscovery binary should resolve to its path."""
        with patch("shutil.which", return_value="/usr/bin/httpx"):
            probe = MagicMock()
            probe.stdout = "projectdiscovery httpx v1.3.0\n"
            probe.stderr = ""
            probe.returncode = 0
            with patch("subprocess.run", return_value=probe):
                path = ToolResolver().resolve("httpx")
        assert path == "/usr/bin/httpx"

    def test_wrong_binary_raises_clear_error(self) -> None:
        """A name-shadowing binary (e.g. Python httpx CLI) should be rejected.

        The Python httpx CLI prints a Click usage message with no
        'projectdiscovery' marker; the resolver must flag this clearly.
        """
        with patch("shutil.which", return_value="/some/venv/httpx.exe"):
            probe = MagicMock()
            probe.stdout = ""
            probe.stderr = "Usage: httpx [OPTIONS] URL"
            probe.returncode = 1
            with patch("subprocess.run", return_value=probe):
                with pytest.raises(
                    ToolUnavailableError, match="does not appear to be the expected"
                ):
                    ToolResolver().resolve("httpx")

    def test_resolution_is_cached(self) -> None:
        """Repeated resolve() calls should probe the tool only once."""
        with patch("shutil.which", return_value="/usr/bin/naabu"):
            probe = MagicMock()
            probe.stdout = "projectdiscovery naabu v1.0.0\n"
            probe.stderr = ""
            with patch("subprocess.run", return_value=probe) as mock_run:
                ToolResolver().resolve("naabu")
                ToolResolver().resolve("naabu")
        assert mock_run.call_count == 1

    def test_unknown_tool_falls_back_to_presence_check(self) -> None:
        """Tools without a registered signature should only be presence-checked."""
        with patch("shutil.which", return_value="/usr/bin/assetfinder"):
            with patch("subprocess.run") as mock_run:
                path = ToolResolver().resolve("assetfinder")
        assert path == "/usr/bin/assetfinder"
        mock_run.assert_not_called()

    def test_probe_timeout_treated_as_wrong_binary(self) -> None:
        """A probing timeout should surface as ToolUnavailableError."""
        with patch("shutil.which", return_value="/usr/bin/katana"):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("katana", 10),
            ):
                with pytest.raises(ToolUnavailableError):
                    ToolResolver().resolve("katana")
