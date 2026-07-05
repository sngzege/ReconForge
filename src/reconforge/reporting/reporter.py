"""ReconForge reporting orchestrator.

Responsibilities:
- Import reporters for JSON and Markdown
- Handle optional file writes and output directory management

Design:
- Reporter writes artifacts under output_dir/
- Filenames use sanitized target name: {target}_report.{ext}
- Consumed by CLI or pipeline completion hooks
"""

from __future__ import annotations

import re
from pathlib import Path

from reconforge.core.pipeline import PipelineResult
from reconforge.reporting.json_reporter import to_json
from reconforge.reporting.markdown_reporter import to_markdown


def _sanitize_target(target: str) -> str:
    """Sanitize target string for use as a filename.

    Replaces characters that are invalid in filenames with underscores.

    Args:
        target: Raw target string (domain, URL, IP).

    Returns:
        Sanitized string safe for use as filename.
    """
    sanitized = target.strip().lower()
    sanitized = re.sub(r"[^\w\-.]", "_", sanitized)
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("_")
    return sanitized or "target"


class Reporter:
    """Orchestrate report generation for pipeline results."""

    def __init__(self, output_dir: str | Path | None = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else Path("output")

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
        }

    def write(
        self, result: PipelineResult, target: str | None = None
    ) -> dict[str, str]:
        """Render and write reports to the output directory.

        Reports are named: {sanitized_target}_report.{ext}
        Falls back to timestamped name if target is not provided.

        Args:
            result: Completed PipelineResult.
            target: Optional target string for report naming.

        Returns:
            Dict mapping format -> written file path.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        rendered = self.render(result)

        if target:
            base_name = f"{_sanitize_target(target)}_report"
        else:
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            base_name = f"report_{ts}"

        paths: dict[str, str] = {}
        for fmt, content in rendered.items():
            ext = "md" if fmt == "markdown" else fmt
            path = self.output_dir / f"{base_name}.{ext}"
            path.write_text(content, encoding="utf-8")
            paths[fmt] = str(path)
        return paths
