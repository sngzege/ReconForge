"""Result data model for ReconForge.

Responsibilities:
- Define standard Result structure returned by all plugins
- Include module name, status, duration, data, and errors
- Provide helper methods for creating common result types

Design:
- Uses @dataclass for clean, readable data container
- Status enum for type-safe status values
- All plugins return Result objects, never plugin-specific formats
- Merge Engine and Reporter only read Result objects
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Any


class ResultStatus(Enum):
    """Status of a plugin execution.

    Attributes:
        SUCCESS: Plugin completed successfully with full results.
        FAILURE: Plugin failed completely, no results.
        PARTIAL: Plugin partially succeeded, some results available.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


@dataclass
class Result:
    """Standard result structure returned by all plugins.

    Attributes:
        module: Name of the plugin that produced this result.
        status: Execution status (success, failure, partial).
        duration: How long the plugin took to execute.
        data: The actual payload (plugin-specific content).
        errors: List of error messages, if any.
        metadata: Optional additional metadata about the execution.

    Example:
        >>> result = Result(
        ...     module="subfinder",
        ...     status=ResultStatus.SUCCESS,
        ...     duration=timedelta(seconds=5.2),
        ...     data=["sub1.example.com", "sub2.example.com"],
        ... )
    """

    module: str
    status: ResultStatus
    duration: timedelta
    data: Any = None
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        """Check if the result indicates success."""
        return self.status == ResultStatus.SUCCESS

    @property
    def is_failure(self) -> bool:
        """Check if the result indicates failure."""
        return self.status == ResultStatus.FAILURE

    @property
    def is_partial(self) -> bool:
        """Check if the result indicates partial success."""
        return self.status == ResultStatus.PARTIAL

    @property
    def has_errors(self) -> bool:
        """Check if the result has any errors."""
        return len(self.errors) > 0

    @property
    def data_count(self) -> int:
        """Get the count of data items.

        Returns 0 if data is None or not a collection.
        """
        if self.data is None:
            return 0
        if isinstance(self.data, (list, tuple, set)):
            return len(self.data)
        return 1

    def add_error(self, error: str) -> None:
        """Add an error message to the result.

        Args:
            error: Error message to add.
        """
        self.errors.append(error)

    def merge_data(self, other: Result) -> None:
        """Merge data from another result into this one.

        Only merges if both results have list data.

        Args:
            other: Another Result to merge from.

        Raises:
            TypeError: If either result's data is not a list.
        """
        if not isinstance(self.data, list) or not isinstance(other.data, list):
            raise TypeError(
                f"Cannot merge data: expected lists, got "
                f"{type(self.data).__name__} and {type(other.data).__name__}"
            )
        self.data.extend(other.data)
        self.errors.extend(other.errors)


def create_success_result(
    module: str,
    data: Any,
    duration: timedelta,
    metadata: dict[str, Any] | None = None,
) -> Result:
    """Create a success result.

    Args:
        module: Plugin name.
        data: Result data.
        duration: Execution duration.
        metadata: Optional metadata.

    Returns:
        Result with SUCCESS status.
    """
    return Result(
        module=module,
        status=ResultStatus.SUCCESS,
        duration=duration,
        data=data,
        metadata=metadata or {},
    )


def create_failure_result(
    module: str,
    error: str,
    duration: timedelta,
) -> Result:
    """Create a failure result.

    Args:
        module: Plugin name.
        error: Error message.
        duration: Execution duration.

    Returns:
        Result with FAILURE status.
    """
    return Result(
        module=module,
        status=ResultStatus.FAILURE,
        duration=duration,
        errors=[error],
    )


def create_partial_result(
    module: str,
    data: Any,
    error: str,
    duration: timedelta,
) -> Result:
    """Create a partial success result.

    Args:
        module: Plugin name.
        data: Partial result data.
        error: Error message for the partial failure.
        duration: Execution duration.

    Returns:
        Result with PARTIAL status.
    """
    return Result(
        module=module,
        status=ResultStatus.PARTIAL,
        duration=duration,
        data=data,
        errors=[error],
    )