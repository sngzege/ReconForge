"""JSON reporter for ReconForge.

Produces tool-based detailed output - each plugin's results preserved separately.
"""

from __future__ import annotations

import json
from typing import Any

from reconforge.core.pipeline import PipelineResult


def to_json(result: PipelineResult) -> str:
    """Convert PipelineResult into tool-based JSON report."""
    payload: dict[str, Any] = {
        "summary": {
            "duration_seconds": result.duration.total_seconds(),
            "total_plugins": len(result.results),
            "successful": result.success_count,
            "failed": result.failure_count,
        },
        "tools": {},
    }

    for r in result.results:
        payload["tools"][r.module] = {
            "status": r.status.value,
            "duration_seconds": r.duration.total_seconds(),
            "data": r.data,
            "metadata": r.metadata,
            "errors": r.errors,
        }

    return json.dumps(payload, indent=2)
