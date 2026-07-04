"""Tests for the tech_detect plugin."""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from unittest.mock import MagicMock, patch

from reconforge.core.result import Result, create_success_result
from reconforge.plugins.tech_detect import TechDetectPlugin


def _make_fingerprint_result(fingerprints: list[dict]) -> Result:
    """Helper to create a mock http_fingerprint result."""
    return create_success_result(
        module="http_fingerprint",
        data=fingerprints,
        duration=timedelta(seconds=0),
        metadata={"count": len(fingerprints)},
    )


class TestTechDetectPlugin:
    """Test TechDetectPlugin."""

    def test_name(self) -> None:
        plugin = TechDetectPlugin()
        assert plugin.name == "tech_detect"

    def test_requires(self) -> None:
        assert TechDetectPlugin.requires == ["http_fingerprint"]

    def test_successful_run(self) -> None:
        plugin = TechDetectPlugin()
        upstream = {
            "http_fingerprint": _make_fingerprint_result(
                [{"url": "https://example.com", "status_code": 200}]
            )
        }

        json_line = json.dumps(
            {
                "url": "https://example.com",
                "technologies": ["Nginx", "WordPress"],
            }
        )

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_line + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data[0]["technologies"] == ["Nginx", "WordPress"]

    def test_tool_not_found(self) -> None:
        plugin = TechDetectPlugin()
        upstream = {
            "http_fingerprint": _make_fingerprint_result(
                [{"url": "https://example.com"}]
            )
        }

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_input(self) -> None:
        plugin = TechDetectPlugin()
        upstream = {"http_fingerprint": _make_fingerprint_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        plugin = TechDetectPlugin()
        upstream = {
            "http_fingerprint": _make_fingerprint_result(
                [{"url": "https://example.com"}]
            )
        }

        timeout = subprocess.TimeoutExpired("httpx", 300)
        with patch("subprocess.run", side_effect=timeout):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
