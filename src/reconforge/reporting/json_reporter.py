"""JSON reporter for ReconForge.

Responsibilities:
- Serialize PipelineResult to JSON
- Include statistics, timeline, and raw results

Design:
- Pure function, no file I/O dependency
- Output is wrapped by Reporter if needed
"""

from __future__ import annotations

import json
from typing import Any

from reconforge.core.pipeline import PipelineResult
from reconforge.reporting.statistics import compute_statistics
from reconforge.reporting.timeline import compute_timeline


def to_json(result: PipelineResult) -> str:
    """Convert PipelineResult into a JSON report string.

    Args:
        result: Completed PipelineResult.

    Returns:
        JSON string with metadata, statistics, timeline, and results.
    """
    payload: dict[str, Any] = {
        "results": [
            {
                "module": r.module,
                "status": r.status.value,
                "duration_seconds": r.duration.total_seconds(),
                "data": r.data,
                "metadata": r.metadata,
                "errors": r.errors,
            }
            for r in result.results
        ],
        "statistics": compute_statistics(result),
        "timeline": compute_timeline(result),
    }
    return json.dumps(payload, indent=2)
