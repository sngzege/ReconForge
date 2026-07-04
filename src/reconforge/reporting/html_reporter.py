"""HTML reporter for ReconForge."""

from __future__ import annotations

from reconforge.core.pipeline import PipelineResult
from reconforge.reporting.statistics import compute_statistics
from reconforge.reporting.timeline import compute_timeline


def to_html(result: PipelineResult) -> str:
    """Render PipelineResult as an HTML report.

    Args:
        result: Completed PipelineResult.

    Returns:
        HTML report string.
    """
    stats = compute_statistics(result)

    rows: list[str] = []
    for idx, event in enumerate(compute_timeline(result), start=1):
        rows.append(
            "<tr><td>"
            + str(idx)
            + "</td><td>"
            + event["module"]
            + "</td><td>"
            + event["status"]
            + "</td><td>"
            + str(round(event["duration_seconds"], 2))
            + "</td></tr>"
        )

    result_blocks: list[str] = []
    for r in result.results:
        if isinstance(r.data, list):
            preview = ", ".join(str(item) for item in r.data[:5])
            if len(r.data) > 5:
                preview += ", ... (+" + str(len(r.data) - 5) + " more)"
        else:
            preview = str(r.data)
        result_blocks.append(
            '<div class="result">'
            + "<h3>"
            + r.module
            + "</h3>"
            + "<p>Status: "
            + r.status.value
            + " | Duration: "
            + str(round(r.duration.total_seconds(), 2))
            + "s</p><pre>"
            + _escape(preview)
            + "</pre></div>"
        )

    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>ReconForge Report</title>"
        "<style>"
        "body { font-family: Arial, sans-serif; margin: 2rem; }"
        "table { border-collapse: collapse; width: 100%; }"
        "th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; }"
        ".result { margin: 1rem 0; padding: 1rem; border: 1px solid #ddd; }"
        "</style></head><body>"
        "<h1>ReconForge Scan Report</h1>"
        "<p>Target plugins executed: "
        + str(stats["total_plugins"])
        + " | Success: "
        + str(stats["success"])
        + " | Partial: "
        + str(stats["partial"])
        + " | Failed: "
        + str(stats["failure"])
        + " | Success rate: "
        + str(round(stats["success_rate"], 1))
        + "% | Duration: "
        + str(round(stats["duration_seconds"], 2))
        + "s</p>"
        "<h2>Timeline</h2><table>"
        "<tr><th>#</th><th>Module</th><th>Status</th><th>Duration (s)</th></tr>"
        + "".join(rows)
        + "</table><h2>Results</h2>"
        + "".join(result_blocks)
        + "</body></html>"
    )


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
