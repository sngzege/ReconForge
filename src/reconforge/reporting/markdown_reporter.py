"""Markdown reporter for ReconForge.

Responsibilities:
- Render PipelineResult into Markdown
- Include summary, statistics, timeline, and result tables

Design:
- Pure function returns markdown string
- Reporter wrapper handles file I/O
"""

from __future__ import annotations

from reconforge.core.pipeline import PipelineResult
from reconforge.reporting.statistics import compute_statistics
from reconforge.reporting.timeline import compute_timeline


def to_markdown(result: PipelineResult) -> str:
    """Render PipelineResult as a Markdown report.

    Args:
        result: Completed PipelineResult.

    Returns:
        Markdown report string.
    """
    stats = compute_statistics(result)

    lines: list[str] = [
        "# ReconForge Scan Report",
        "",
        "## Summary",
        "",
        f"- Target plugins executed: {stats['total_plugins']}",
        f"- Success: {stats['success']}",
        f"- Partial: {stats['partial']}",
        f"- Failed: {stats['failure']}",
        f"- Success rate: {stats['success_rate']:.1f}%",
        f"- Duration: {stats['duration_seconds']:.2f}s",
        "",
        "## Timeline",
        "",
        "| # | Module | Status | Duration (s) |",
        "|---|--------|--------|--------------|",
    ]
    for idx, event in enumerate(compute_timeline(result), start=1):
        lines.append(
            f"| {idx} | {event['module']} | {event['status']} "
            f"| {event['duration_seconds']:.2f} |"
        )

    lines.append("")
    lines.append("## Results")
    lines.append("")
    for r in result.results:
        lines.append(f"### {r.module}")
        lines.append("")
        lines.append(f"- Status: `{r.status.value}`")
        lines.append(f"- Duration: `{r.duration.total_seconds():.2f}s`")
        if r.data is not None:
            if isinstance(r.data, list):
                lines.append(f"- Items: `{len(r.data)}`")
                for idx, item in enumerate(r.data[:10], start=1):
                    lines.append(f"  - {idx}. `{item}`")
                if len(r.data) > 10:
                    lines.append(f"  - ... and {len(r.data) - 10} more items")
            else:
                lines.append(f"- Data: `{r.data}`")
        if r.metadata:
            lines.append(f"- Metadata: `{r.metadata}`")
        if r.errors:
            lines.append("- Errors:")
            for err in r.errors[:5]:
                lines.append(f"  - {err}")
        lines.append("")

    return "\n".join(lines)
