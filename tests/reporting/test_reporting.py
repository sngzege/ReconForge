"""Tests for reporting package."""

from __future__ import annotations

from reconforge.core.pipeline import PipelineResult
from reconforge.core.result import create_success_result
from reconforge.reporting.html_reporter import to_html
from reconforge.reporting.json_reporter import to_json
from reconforge.reporting.markdown_reporter import to_markdown
from reconforge.reporting.reporter import Reporter
from reconforge.reporting.statistics import compute_statistics
from reconforge.reporting.timeline import compute_timeline


def _pipeline_result() -> PipelineResult:
    result = PipelineResult()
    result.add_result(
        create_success_result(
            module="test_plugin",
            data={"key": "value"},
            duration=__import__("datetime").timedelta(seconds=1),
            metadata={"count": 1},
        )
    )
    return result


class TestStatistics:
    """Test compute_statistics."""

    def test_basic_counts(self) -> None:
        result = _pipeline_result()
        stats = compute_statistics(result)
        assert stats["total_plugins"] == 1
        assert stats["success"] == 1
        assert stats["success_rate"] == 100.0


class TestTimeline:
    """Test compute_timeline."""

    def test_timeline_events(self) -> None:
        result = _pipeline_result()
        timeline = compute_timeline(result)
        assert len(timeline) == 1
        assert timeline[0]["module"] == "test_plugin"


class TestJsonReporter:
    """Test JSON reporter formatter."""

    def test_json_output(self) -> None:
        report = to_json(_pipeline_result())
        assert "test_plugin" in report
        assert "statistics" in report
        assert "timeline" in report


class TestMarkdownReporter:
    """Test Markdown reporter formatter."""

    def test_markdown_output(self) -> None:
        report = to_markdown(_pipeline_result())
        assert "# ReconForge Scan Report" in report
        assert "test_plugin" in report
        assert "Timeline" in report


class TestHtmlReporter:
    """Test HTML reporter formatter."""

    def test_html_output(self) -> None:
        report = to_html(_pipeline_result())
        assert "<!doctype html>" in report
        assert "test_plugin" in report


class TestReporter:
    """Test Reporter orchestrator."""

    def test_render_returns_all_formats(self) -> None:
        reporter = Reporter()
        rendered = reporter.render(_pipeline_result())
        assert "json" in rendered
        assert "markdown" in rendered
        assert "html" in rendered

    def test_write_creates_files(self, tmp_path: Any) -> None:
        reporter = Reporter(output_dir=tmp_path)
        paths = reporter.write(_pipeline_result())
        assert len(paths) == 3
        for path in paths.values():
            assert __import__("pathlib").Path(path).exists()
