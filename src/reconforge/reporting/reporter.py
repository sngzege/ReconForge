"""ReconForge reporting orchestrator.

Responsibilities:
- Import reporters for JSON, Markdown, and HTML
- Handle optional file writes and output directory management

Design:
- Reporter writes artifacts under output_dir/reports/
- Consumed by CLI or pipeline completion hooks
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from reconforge.core.pipeline import PipelineResult
from reconforge.reporting.html_reporter import to_html
from reconforge.reporting.json_reporter import to_json
from reconforge.reporting.markdown_reporter import to_markdown


class Reporter:
    """Orchestrate report generation for pipeline results."""

    def __init__(self, output_dir: str | Path | None = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else Path("artifacts/reports")

    def render(self, result: PipelineResult) -> dict[str, str]:
        """Render reports in all supported formats.

        Args:
            result: Completed PipelineResult.

        Returns:
            Dict mapping format -> rendered content.
        """
        return {
            "json": to_json(result),
            "markdown": to_markdown(result),
            "html": to_html(result),
        }

    def write(self, result: PipelineResult) -> dict[str, str]:
        """Render and write reports to the output directory.

        Args:
            result: Completed PipelineResult.

        Returns:
            Dict mapping format -> written file path.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        rendered = self.render(result)

        paths: dict[str, str] = {}
        for fmt, content in rendered.items():
            name = fmt if fmt != "markdown" else "md"
            path = self.output_dir / f"report_{timestamp}.{name}"
            path.write_text(content, encoding="utf-8")
            paths[fmt] = str(path)
        return paths
