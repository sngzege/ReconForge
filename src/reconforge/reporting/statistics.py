"""Pipeline statistics computation for ReconForge.

Responsibilities:
- Aggregate counts and timing from PipelineResult
- Identify failures, successes, and partial results

Design:
- Pure functions on PipelineResult
- Consumed by reporters and CLI output
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from reconforge.core.pipeline import PipelineResult


def compute_statistics(result: PipelineResult) -> dict[str, Any]:
    """Compute statistics from a PipelineResult.

    Args:
        result: Completed PipelineResult.

    Returns:
        Statistics dict with success rates, timing, and error counts.
    """
    status_counts = Counter(r.status.value for r in result.results)
    total = len(result.results)
    success = status_counts.get("success", 0)
    failure = status_counts.get("failure", 0)
    partial = status_counts.get("partial", 0)

    return {
        "total_plugins": total,
        "success": success,
        "failure": failure,
        "partial": partial,
        "success_rate": (success / total * 100) if total else 0,
        "duration_seconds": result.duration.total_seconds(),
        "errors": list(result.errors),
    }
