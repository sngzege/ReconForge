"""Tests for reporting package."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from reconforge.core.pipeline import PipelineResult
from reconforge.core.result import create_success_result
from reconforge.reporting.json_reporter import to_json
from reconforge.reporting.markdown_reporter import to_markdown
from reconforge.reporting.reporter import Reporter


def _pipeline_result() -> PipelineResult:
    result = PipelineResult()
    result.add_result(
        create_success_result(
            module="test_plugin",
            data={"key": "value"},
            duration=timedelta(seconds=1),
            metadata={"count": 1},
        )
    )
    return result


class TestJsonReporter:
    """Test JSON reporter - tool-based output."""

    def test_json_output(self) -> None:
        report = to_json(_pipeline_result())
        assert "summary" in report
        assert "tools" in report
        assert "test_plugin" in report


class TestMarkdownReporter:
    """Test Markdown reporter - merged findings."""

    def test_markdown_output(self) -> None:
        report = to_markdown(_pipeline_result())
        assert "# ReconForge Discovery Report" in report
        assert "## Target" in report


class TestReporter:
    """Test Reporter orchestrator."""

    def test_render_returns_all_formats(self) -> None:
        reporter = Reporter()
        rendered = reporter.render(_pipeline_result())
        assert "json" in rendered
        assert "markdown" in rendered
        assert len(rendered) == 2

    def test_write_creates_files(self, tmp_path: Any) -> None:
        reporter = Reporter(output_dir=tmp_path)
        paths = reporter.write(_pipeline_result())
        assert len(paths) == 2
        for path in paths.values():
            assert __import__("pathlib").Path(path).exists()
