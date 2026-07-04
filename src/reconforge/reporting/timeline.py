"""Execution timeline computation for ReconForge.

Responsibilities:
- Build ordered timeline from PipelineResult
- Group events by plugin with timing

Design:
- Pure function on PipelineResult
- Consumed by reporters and audit logs
"""

from __future__ import annotations

from typing import Any

from reconforge.core.pipeline import PipelineResult


def compute_timeline(result: PipelineResult) -> list[dict[str, Any]]:
    """Build a timeline of plugin executions.

    Args:
        result: Completed PipelineResult.

    Returns:
        Ordered list of timeline event dicts.
    """
    timeline: list[dict[str, Any]] = []
    for r in result.results:
        event: dict[str, Any] = {
            "module": r.module,
            "status": r.status.value,
            "duration_seconds": r.duration.total_seconds(),
        }
        if r.data is not None:
            event["data_count"] = len(r.data) if isinstance(r.data, list) else None
        if r.metadata:
            event["metadata"] = r.metadata
        timeline.append(event)
    return timeline
