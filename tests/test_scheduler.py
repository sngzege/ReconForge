"""Tests for the Scheduler."""

from datetime import timedelta
from typing import Any

import pytest

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, ResultStatus, create_success_result
from reconforge.core.scheduler import (
    PluginState,
    PluginTask,
    Scheduler,
    SchedulerError,
)


# Test plugins
class PluginA(BasePlugin):
    """Test plugin A."""

    @property
    def name(self) -> str:
        return "plugin_a"

    def run(self, target: str, **kwargs: Any) -> Result:
        return create_success_result(
            module=self.name, data=["a"], duration=timedelta(seconds=1)
        )


class PluginB(BasePlugin):
    """Test plugin B."""

    @property
    def name(self) -> str:
        return "plugin_b"

    def run(self, target: str, **kwargs: Any) -> Result:
        return create_success_result(
            module=self.name, data=["b"], duration=timedelta(seconds=1)
        )


class PluginC(BasePlugin):
    """Test plugin C (depends on A)."""

    @property
    def name(self) -> str:
        return "plugin_c"

    def run(self, target: str, **kwargs: Any) -> Result:
        return create_success_result(
            module=self.name, data=["c"], duration=timedelta(seconds=1)
        )


class TestPluginState:
    """Test PluginState enum."""

    def test_state_values(self) -> None:
        """Enum should have all expected states."""
        assert PluginState.PENDING.value == "pending"
        assert PluginState.RUNNING.value == "running"
        assert PluginState.COMPLETED.value == "completed"
        assert PluginState.FAILED.value == "failed"
        assert PluginState.RETRYING.value == "retrying"
        assert PluginState.SKIPPED.value == "skipped"


class TestPluginTask:
    """Test PluginTask dataclass."""

    def test_create_task(self) -> None:
        """Task should be creatable with default values."""
        plugin = PluginA()
        task = PluginTask(plugin=plugin)

        assert task.name == "plugin_a"
        assert task.state == PluginState.PENDING
        assert task.attempts == 0
        assert task.max_retries == 3
        assert task.result is None
        assert task.can_retry is True

    def test_task_duration(self) -> None:
        """Task should calculate duration correctly."""
        from datetime import datetime

        plugin = PluginA()
        task = PluginTask(plugin=plugin)
        task.started_at = datetime(2024, 1, 1, 12, 0, 0)
        task.completed_at = datetime(2024, 1, 1, 12, 0, 5)

        assert task.duration == timedelta(seconds=5)

    def test_task_duration_none(self) -> None:
        """Task duration should be None if not completed."""
        plugin = PluginA()
        task = PluginTask(plugin=plugin)
        assert task.duration is None

    def test_can_retry(self) -> None:
        """can_retry should return True if attempts < max_retries."""
        plugin = PluginA()
        task = PluginTask(plugin=plugin, max_retries=3)

        task.attempts = 0
        assert task.can_retry is True

        task.attempts = 2
        assert task.can_retry is True

        task.attempts = 3
        assert task.can_retry is False

    def test_to_dict(self) -> None:
        """Task should convert to dictionary."""
        plugin = PluginA()
        task = PluginTask(plugin=plugin)
        task_dict = task.to_dict()

        assert task_dict["name"] == "plugin_a"
        assert task_dict["state"] == "pending"
        assert task_dict["attempts"] == 0
        assert task_dict["max_retries"] == 3


class TestScheduler:
    """Test Scheduler class."""

    def test_empty_scheduler(self) -> None:
        """New scheduler should be empty."""
        scheduler = Scheduler()
        assert len(scheduler) == 0
        assert scheduler.get_all_tasks() == []

    def test_add_plugin(self) -> None:
        """Should be able to add plugins."""
        scheduler = Scheduler()
        plugin = PluginA()
        scheduler.add_plugin(plugin)

        assert len(scheduler) == 1
        assert scheduler.get_task("plugin_a").plugin is plugin

    def test_add_duplicate_plugin_raises_error(self) -> None:
        """Adding duplicate plugin should raise ValueError."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())

        with pytest.raises(ValueError, match="already in scheduler"):
            scheduler.add_plugin(PluginA())

    def test_add_plugin_with_dependency(self) -> None:
        """Should be able to add plugin with dependencies."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginC(), depends_on=["plugin_a"])

        task = scheduler.get_task("plugin_c")
        assert task is not None

    def test_add_plugin_with_missing_dependency_raises_error(self) -> None:
        """Adding plugin with missing dependency should raise ValueError."""
        scheduler = Scheduler()

        with pytest.raises(ValueError, match="not found"):
            scheduler.add_plugin(PluginC(), depends_on=["nonexistent"])


class TestSchedulerReadyPlugins:
    """Test get_ready_plugins method."""

    def test_ready_plugins_no_dependencies(self) -> None:
        """Plugins without dependencies should be ready immediately."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginB())

        ready = scheduler.get_ready_plugins()
        assert len(ready) == 2

    def test_ready_plugins_with_dependencies(self) -> None:
        """Plugins with dependencies should wait."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginC(), depends_on=["plugin_a"])

        ready = scheduler.get_ready_plugins()
        assert len(ready) == 1
        assert ready[0].name == "plugin_a"

    def test_ready_plugins_after_dependency_completed(self) -> None:
        """Dependent plugins should become ready after dependency completes."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginC(), depends_on=["plugin_a"])

        # Initially only A is ready
        ready = scheduler.get_ready_plugins()
        assert len(ready) == 1

        # Mark A as running and completed
        scheduler.mark_running("plugin_a")
        result = create_success_result(
            module="plugin_a", data=["a"], duration=timedelta(seconds=1)
        )
        scheduler.mark_completed("plugin_a", result)

        # Now C should be ready
        ready = scheduler.get_ready_plugins()
        assert len(ready) == 1
        assert ready[0].name == "plugin_c"


class TestSchedulerStateTransitions:
    """Test state transition methods."""

    def test_mark_running(self) -> None:
        """mark_running should transition from PENDING to RUNNING."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())

        scheduler.mark_running("plugin_a")
        task = scheduler.get_task("plugin_a")

        assert task.state == PluginState.RUNNING
        assert task.attempts == 1
        assert task.started_at is not None

    def test_mark_running_from_wrong_state_raises_error(self) -> None:
        """mark_running from non-PENDING state should raise error."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.mark_running("plugin_a")

        with pytest.raises(SchedulerError, match="current state"):
            scheduler.mark_running("plugin_a")

    def test_mark_completed(self) -> None:
        """mark_completed should transition from RUNNING to COMPLETED."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.mark_running("plugin_a")

        result = create_success_result(
            module="plugin_a", data=["a"], duration=timedelta(seconds=1)
        )
        scheduler.mark_completed("plugin_a", result)

        task = scheduler.get_task("plugin_a")
        assert task.state == PluginState.COMPLETED
        assert task.result is result
        assert task.completed_at is not None

    def test_mark_completed_from_wrong_state_raises_error(self) -> None:
        """mark_completed from non-RUNNING state should raise error."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())

        with pytest.raises(SchedulerError, match="current state"):
            result = create_success_result(
                module="plugin_a", data=[], duration=timedelta(0)
            )
            scheduler.mark_completed("plugin_a", result)


class TestSchedulerRetryLogic:
    """Test retry mechanism."""

    def test_failed_plugin_retries(self) -> None:
        """Failed plugin with retries should go to RETRYING state."""
        scheduler = Scheduler(max_retries=3)
        scheduler.add_plugin(PluginA())
        scheduler.mark_running("plugin_a")
        scheduler.mark_failed("plugin_a", "Test error")

        task = scheduler.get_task("plugin_a")
        assert task.state == PluginState.RETRYING
        assert task.error == "Test error"
        assert task.can_retry is True

    def test_failed_plugin_skipped_after_max_retries(self) -> None:
        """Failed plugin without retries should be SKIPPED."""
        scheduler = Scheduler(max_retries=2)  # Allow 2 attempts
        scheduler.add_plugin(PluginA())

        # First attempt
        scheduler.mark_running("plugin_a")
        scheduler.mark_failed("plugin_a", "Error 1")

        task = scheduler.get_task("plugin_a")
        assert task.state == PluginState.RETRYING  # Can retry (1 < 2)

        # Second attempt (retry)
        scheduler.mark_retrying("plugin_a")
        scheduler.mark_running("plugin_a")
        scheduler.mark_failed("plugin_a", "Error 2")

        task = scheduler.get_task("plugin_a")
        assert task.state == PluginState.SKIPPED  # No more retries (2 >= 2)

    def test_mark_retrying(self) -> None:
        """mark_retrying should transition from RETRYING to PENDING."""
        scheduler = Scheduler(max_retries=3)
        scheduler.add_plugin(PluginA())
        scheduler.mark_running("plugin_a")
        scheduler.mark_failed("plugin_a", "Error")

        scheduler.mark_retrying("plugin_a")
        task = scheduler.get_task("plugin_a")

        assert task.state == PluginState.PENDING
        assert task.started_at is None
        assert task.completed_at is None

    def test_mark_retrying_from_wrong_state_raises_error(self) -> None:
        """mark_retrying from non-RETRYING state should raise error."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())

        with pytest.raises(SchedulerError, match="current state"):
            scheduler.mark_retrying("plugin_a")


class TestSchedulerDependentSkipping:
    """Test that dependents are skipped when dependency fails."""

    def test_dependents_skipped_on_failure(self) -> None:
        """Dependents should be skipped when dependency fails permanently."""
        scheduler = Scheduler(max_retries=0)  # No retries
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginC(), depends_on=["plugin_a"])

        scheduler.mark_running("plugin_a")
        scheduler.mark_failed("plugin_a", "Fatal error")

        # A should be skipped
        task_a = scheduler.get_task("plugin_a")
        assert task_a.state == PluginState.SKIPPED

        # C should also be skipped
        task_c = scheduler.get_task("plugin_c")
        assert task_c.state == PluginState.SKIPPED
        assert "plugin_a" in task_c.error


class TestSchedulerQueries:
    """Test query methods."""

    def test_get_waiting_plugins(self) -> None:
        """get_waiting_plugins should return plugins with unmet dependencies."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginC(), depends_on=["plugin_a"])

        waiting = scheduler.get_waiting_plugins()
        assert len(waiting) == 1
        assert waiting[0].name == "plugin_c"

    def test_get_tasks_by_state(self) -> None:
        """get_tasks_by_state should filter tasks correctly."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginB())
        scheduler.mark_running("plugin_a")

        running = scheduler.get_tasks_by_state(PluginState.RUNNING)
        assert len(running) == 1
        assert running[0].name == "plugin_a"

        pending = scheduler.get_tasks_by_state(PluginState.PENDING)
        assert len(pending) == 1
        assert pending[0].name == "plugin_b"

    def test_is_complete(self) -> None:
        """is_complete should return True when all plugins are terminal."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginB())

        assert scheduler.is_complete() is False

        scheduler.mark_running("plugin_a")
        result = create_success_result(
            module="plugin_a", data=[], duration=timedelta(0)
        )
        scheduler.mark_completed("plugin_a", result)

        assert scheduler.is_complete() is False

        scheduler.mark_running("plugin_b")
        scheduler.mark_completed("plugin_b", result)

        assert scheduler.is_complete() is True

    def test_get_summary(self) -> None:
        """get_summary should return correct state counts."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())
        scheduler.add_plugin(PluginB())
        scheduler.mark_running("plugin_a")

        summary = scheduler.get_summary()
        assert summary["pending"] == 1
        assert summary["running"] == 1
        assert summary["completed"] == 0

    def test_repr(self) -> None:
        """Scheduler should have useful repr."""
        scheduler = Scheduler()
        scheduler.add_plugin(PluginA())

        assert "1 plugins" in repr(scheduler)
        assert "pending=1" in repr(scheduler)