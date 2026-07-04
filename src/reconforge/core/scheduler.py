"""Scheduler for ReconForge.

Responsibilities:
- Determine which plugins can start now
- Track which plugins are waiting for dependencies
- Handle retries for failed plugins
- Manage plugin lifecycle states

Design:
- Uses state machine pattern for plugin lifecycle
- Each plugin transitions through states: PENDING → RUNNING → COMPLETED/FAILED
- Failed plugins can be retried up to max_retries times
- Plugins with failed dependencies are SKIPPED
- Thread-safe state management
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from reconforge.core.logging_setup import get_core_logger
from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, ResultStatus

logger = get_core_logger("scheduler")


class PluginState(Enum):
    """State of a plugin in the scheduler.

    State transitions:
    - PENDING → RUNNING (when dependencies satisfied)
    - RUNNING → COMPLETED (on success)
    - RUNNING → FAILED (on failure)
    - FAILED → RETRYING (if retries remaining)
    - RETRYING → RUNNING (when retry starts)
    - FAILED → SKIPPED (if no retries remaining)
    - PENDING → SKIPPED (if dependency failed)
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    SKIPPED = "skipped"


@dataclass
class PluginTask:
    """Tracks a plugin's state and execution metadata.

    Attributes:
        plugin: The plugin instance.
        state: Current state of the plugin.
        attempts: Number of execution attempts so far.
        max_retries: Maximum number of retries allowed.
        result: Result from the last execution (if any).
        started_at: When the current/last execution started.
        completed_at: When the current/last execution completed.
        error: Last error message (if any).
    """

    plugin: BasePlugin
    state: PluginState = PluginState.PENDING
    attempts: int = 0
    max_retries: int = 3
    result: Result | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None

    @property
    def name(self) -> str:
        """Get the plugin name."""
        return self.plugin.name

    @property
    def duration(self) -> timedelta | None:
        """Get the duration of the last execution."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def can_retry(self) -> bool:
        """Check if the plugin can be retried."""
        return self.attempts < self.max_retries

    def to_dict(self) -> dict[str, Any]:
        """Convert task to dictionary for serialization.

        Returns:
            Dictionary representation of the task.
        """
        return {
            "name": self.name,
            "state": self.state.value,
            "attempts": self.attempts,
            "max_retries": self.max_retries,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class SchedulerError(Exception):
    """Raised when scheduler encounters an error."""


class Scheduler:
    """Manages plugin execution scheduling and state transitions.

    The Scheduler:
    1. Accepts plugins with their dependencies
    2. Tracks each plugin's state
    3. Determines which plugins are ready to run
    4. Handles retries for failed plugins
    5. Skips plugins whose dependencies failed

    Example:
        scheduler = Scheduler(max_retries=3)
        scheduler.add_plugin(dns_plugin)
        scheduler.add_plugin(subfinder_plugin, depends_on=["dns"])

        ready = scheduler.get_ready_plugins()
        # Returns [dns_plugin] (subfinder waiting for dns)

        scheduler.mark_running("dns")
        scheduler.mark_completed("dns", result)

        ready = scheduler.get_ready_plugins()
        # Now returns [subfinder_plugin]
    """

    def __init__(self, max_retries: int = 3) -> None:
        """Initialize the scheduler.

        Args:
            max_retries: Default maximum retries for failed plugins.
        """
        self._tasks: dict[str, PluginTask] = {}
        self._dependencies: dict[str, list[str]] = {}
        self._max_retries = max_retries

    def add_plugin(
        self,
        plugin: BasePlugin,
        depends_on: list[str] | None = None,
        max_retries: int | None = None,
    ) -> None:
        """Add a plugin to the scheduler.

        Args:
            plugin: Plugin instance to schedule.
            depends_on: List of plugin names this plugin depends on.
            max_retries: Maximum retries for this plugin (overrides default).

        Raises:
            ValueError: If plugin already exists or dependency not found.
        """
        if plugin.name in self._tasks:
            raise ValueError(f"Plugin '{plugin.name}' already in scheduler")

        # Validate dependencies
        if depends_on:
            for dep in depends_on:
                if dep not in self._tasks:
                    raise ValueError(
                        f"Dependency '{dep}' not found for plugin '{plugin.name}'. "
                        "Dependencies must be added before dependents."
                    )

        retries = max_retries if max_retries is not None else self._max_retries
        task = PluginTask(plugin=plugin, max_retries=retries)
        self._tasks[plugin.name] = task
        self._dependencies[plugin.name] = depends_on or []

        logger.debug(
            f"Added plugin: {plugin.name} "
            f"(depends_on={depends_on or []}, max_retries={retries})"
        )

    def get_ready_plugins(self) -> list[BasePlugin]:
        """Get plugins that are ready to run.

        A plugin is ready when:
        - It is in PENDING state
        - All its dependencies are in COMPLETED state

        Returns:
            List of plugins ready to execute.
        """
        ready = []

        for name, task in self._tasks.items():
            if task.state != PluginState.PENDING:
                continue

            # Check if all dependencies are completed
            deps = self._dependencies.get(name, [])
            all_deps_completed = all(
                self._tasks[dep].state == PluginState.COMPLETED
                for dep in deps
            )

            if all_deps_completed:
                ready.append(task.plugin)

        return ready

    def get_waiting_plugins(self) -> list[PluginTask]:
        """Get plugins that are waiting for dependencies.

        Returns:
            List of tasks that are pending but have unmet dependencies.
        """
        waiting = []

        for name, task in self._tasks.items():
            if task.state != PluginState.PENDING:
                continue

            deps = self._dependencies.get(name, [])
            all_deps_completed = all(
                self._tasks[dep].state == PluginState.COMPLETED
                for dep in deps
            )

            if not all_deps_completed:
                waiting.append(task)

        return waiting

    def mark_running(self, plugin_name: str) -> None:
        """Mark a plugin as currently running.

        Args:
            plugin_name: Name of the plugin.

        Raises:
            KeyError: If plugin not found.
            SchedulerError: If plugin is not in PENDING or RETRYING state.
        """
        task = self._get_task(plugin_name)

        if task.state not in (PluginState.PENDING, PluginState.RETRYING):
            raise SchedulerError(
                f"Cannot mark '{plugin_name}' as running: "
                f"current state is {task.state.value}"
            )

        task.state = PluginState.RUNNING
        task.started_at = datetime.now()
        task.attempts += 1
        task.error = None

        logger.info(f"Plugin {plugin_name} started (attempt {task.attempts})")

    def mark_completed(self, plugin_name: str, result: Result) -> None:
        """Mark a plugin as successfully completed.

        Args:
            plugin_name: Name of the plugin.
            result: Result from the plugin execution.

        Raises:
            KeyError: If plugin not found.
            SchedulerError: If plugin is not in RUNNING state.
        """
        task = self._get_task(plugin_name)

        if task.state != PluginState.RUNNING:
            raise SchedulerError(
                f"Cannot mark '{plugin_name}' as completed: "
                f"current state is {task.state.value}"
            )

        task.state = PluginState.COMPLETED
        task.completed_at = datetime.now()
        task.result = result

        logger.info(f"Plugin {plugin_name} completed successfully")

    def mark_failed(self, plugin_name: str, error: str) -> None:
        """Mark a plugin as failed.

        If retries are remaining, the plugin moves to RETRYING state.
        Otherwise, it moves to SKIPPED state and dependents are also skipped.

        Args:
            plugin_name: Name of the plugin.
            error: Error message.

        Raises:
            KeyError: If plugin not found.
            SchedulerError: If plugin is not in RUNNING state.
        """
        task = self._get_task(plugin_name)

        if task.state != PluginState.RUNNING:
            raise SchedulerError(
                f"Cannot mark '{plugin_name}' as failed: "
                f"current state is {task.state.value}"
            )

        task.completed_at = datetime.now()
        task.error = error

        if task.can_retry:
            task.state = PluginState.RETRYING
            logger.warning(
                f"Plugin {plugin_name} failed (attempt {task.attempts}/"
                f"{task.max_retries}): {error}. Will retry."
            )
        else:
            task.state = PluginState.SKIPPED
            logger.error(
                f"Plugin {plugin_name} failed permanently: {error}. "
                "Skipping plugin and dependents."
            )
            # Skip all dependents
            self._skip_dependents(plugin_name)

    def _skip_dependents(self, failed_plugin: str) -> None:
        """Skip all plugins that depend on the failed plugin.

        Args:
            failed_plugin: Name of the failed plugin.
        """
        for name, deps in self._dependencies.items():
            if failed_plugin in deps:
                task = self._tasks[name]
                if task.state == PluginState.PENDING:
                    task.state = PluginState.SKIPPED
                    task.error = f"Dependency '{failed_plugin}' failed"
                    logger.warning(f"Plugin {name} skipped due to {failed_plugin} failure")
                    # Recursively skip dependents
                    self._skip_dependents(name)

    def mark_retrying(self, plugin_name: str) -> None:
        """Mark a plugin as being retried.

        This transitions the plugin from RETRYING back to PENDING,
        allowing it to be picked up by get_ready_plugins() again.

        Args:
            plugin_name: Name of the plugin.

        Raises:
            KeyError: If plugin not found.
            SchedulerError: If plugin is not in RETRYING state.
        """
        task = self._get_task(plugin_name)

        if task.state != PluginState.RETRYING:
            raise SchedulerError(
                f"Cannot mark '{plugin_name}' as retrying: "
                f"current state is {task.state.value}"
            )

        task.state = PluginState.PENDING
        task.started_at = None
        task.completed_at = None

        logger.info(f"Plugin {plugin_name} queued for retry")

    def get_task(self, plugin_name: str) -> PluginTask:
        """Get the task for a specific plugin.

        Args:
            plugin_name: Name of the plugin.

        Returns:
            PluginTask for the plugin.

        Raises:
            KeyError: If plugin not found.
        """
        return self._get_task(plugin_name)

    def _get_task(self, plugin_name: str) -> PluginTask:
        """Internal method to get a task with error handling.

        Args:
            plugin_name: Name of the plugin.

        Returns:
            PluginTask for the plugin.

        Raises:
            KeyError: If plugin not found.
        """
        if plugin_name not in self._tasks:
            raise KeyError(f"Plugin '{plugin_name}' not in scheduler")
        return self._tasks[plugin_name]

    def get_all_tasks(self) -> list[PluginTask]:
        """Get all tasks in the scheduler.

        Returns:
            List of all plugin tasks.
        """
        return list(self._tasks.values())

    def get_tasks_by_state(self, state: PluginState) -> list[PluginTask]:
        """Get all tasks in a specific state.

        Args:
            state: State to filter by.

        Returns:
            List of tasks in that state.
        """
        return [task for task in self._tasks.values() if task.state == state]

    def is_complete(self) -> bool:
        """Check if all plugins have finished (completed or skipped).

        Returns:
            True if no plugins are pending, running, or retrying.
        """
        terminal_states = {PluginState.COMPLETED, PluginState.SKIPPED}
        return all(task.state in terminal_states for task in self._tasks.values())

    def get_summary(self) -> dict[str, int]:
        """Get a summary of plugin states.

        Returns:
            Dictionary mapping state names to counts.
        """
        summary: dict[str, int] = {state.value: 0 for state in PluginState}
        for task in self._tasks.values():
            summary[task.state.value] += 1
        return summary

    def __len__(self) -> int:
        """Return the number of plugins in the scheduler."""
        return len(self._tasks)

    def __repr__(self) -> str:
        """Return string representation of the scheduler."""
        summary = self.get_summary()
        return (
            f"<Scheduler: {len(self)} plugins "
            f"(pending={summary['pending']}, running={summary['running']}, "
            f"completed={summary['completed']}, failed={summary['failed']}, "
            f"retrying={summary['retrying']}, skipped={summary['skipped']})>"
        )