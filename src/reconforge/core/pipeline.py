"""Pipeline orchestration for ReconForge.

Responsibilities:
- Manage plugin execution order based on dependency graph
- Handle concurrent execution of independent plugins
- Feed results between plugins
- Collect and aggregate all results

Design:
- Uses dependency graph for ordering (not fixed sequence)
- Independent plugins run concurrently via ThreadPoolExecutor
- Results are collected in a thread-safe queue
- Pipeline never stops due to single plugin failure
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from queue import Queue
from typing import Any

from reconforge.core.logging_setup import get_core_logger
from reconforge.core.plugin import BasePlugin, execute_plugin_safely
from reconforge.core.result import Result, ResultStatus, create_failure_result

logger = get_core_logger("pipeline")


class PipelineError(Exception):
    """Raised when pipeline execution fails."""


class PipelineResult:
    """Container for all results from a pipeline execution.

    Attributes:
        results: List of all Result objects from plugins.
        errors: List of errors that occurred during execution.
        duration: Total pipeline execution time.
    """

    def __init__(self) -> None:
        """Initialize an empty pipeline result."""
        self.results: list[Result] = []
        self.errors: list[str] = []
        self.duration: timedelta = timedelta(0)

    def add_result(self, result: Result) -> None:
        """Add a result to the collection.

        Args:
            result: Result object to add.
        """
        self.results.append(result)
        if result.has_errors:
            self.errors.extend(result.errors)

    @property
    def success_count(self) -> int:
        """Count of successful results."""
        return sum(1 for r in self.results if r.is_success)

    @property
    def failure_count(self) -> int:
        """Count of failed results."""
        return sum(1 for r in self.results if r.is_failure)

    @property
    def partial_count(self) -> int:
        """Count of partial results."""
        return sum(1 for r in self.results if r.is_partial)

    def get_results_by_module(self, module_name: str) -> list[Result]:
        """Get all results from a specific module.

        Args:
            module_name: Name of the module to filter by.

        Returns:
            List of results from that module.
        """
        return [r for r in self.results if r.module == module_name]

    def get_all_data(self) -> list[Any]:
        """Get all data from all results, flattened.

        Returns:
            List of all data items from all results.
        """
        all_data = []
        for result in self.results:
            if result.data is not None:
                if isinstance(result.data, list):
                    all_data.extend(result.data)
                else:
                    all_data.append(result.data)
        return all_data

    def __repr__(self) -> str:
        """Return string representation of pipeline result."""
        return (
            f"<PipelineResult: {len(self.results)} results "
            f"({self.success_count} success, {self.failure_count} failed, "
            f"{self.partial_count} partial)>"
        )


class Pipeline:
    """Orchestrates plugin execution based on dependency graph.

    The Pipeline:
    1. Accepts plugins and their dependencies
    2. Builds a dependency graph
    3. Executes plugins in topological order
    4. Runs independent plugins concurrently
    5. Collects all results

    Example:
        pipeline = Pipeline()
        pipeline.add_plugin(dns_plugin)
        pipeline.add_plugin(subfinder_plugin, depends_on=["dns"])
        result = pipeline.run("example.com")
    """

    def __init__(self, max_workers: int = 10) -> None:
        """Initialize the pipeline.

        Args:
            max_workers: Maximum number of concurrent threads.
        """
        self._plugins: dict[str, BasePlugin] = {}
        self._dependencies: dict[str, list[str]] = {}
        self._max_workers = max_workers
        self._results: dict[str, Result] = {}

    def add_plugin(
        self,
        plugin: BasePlugin,
        depends_on: list[str] | None = None,
    ) -> None:
        """Add a plugin to the pipeline.

        Args:
            plugin: Plugin instance to add.
            depends_on: List of plugin names this plugin depends on.
                       Dependencies must be added before this plugin.

        Raises:
            ValueError: If plugin name already exists or dependency not found.
        """
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' already in pipeline")

        # Validate dependencies exist
        if depends_on:
            for dep in depends_on:
                if dep not in self._plugins:
                    raise ValueError(
                        f"Dependency '{dep}' not found for plugin '{plugin.name}'. "
                        "Dependencies must be added before dependents."
                    )

        self._plugins[plugin.name] = plugin
        self._dependencies[plugin.name] = depends_on or []
        logger.debug(
            f"Added plugin: {plugin.name} (depends on: {depends_on or 'none'})"
        )

    def _get_execution_order(self) -> list[list[str]]:
        """Calculate execution order using topological sort.

        Returns:
            List of stages, where each stage is a list of plugin names
            that can run concurrently.

        Raises:
            PipelineError: If circular dependency detected.
        """
        # Build in-degree map
        in_degree: dict[str, int] = {name: 0 for name in self._plugins}
        dependents: dict[str, list[str]] = defaultdict(list)

        for name, deps in self._dependencies.items():
            in_degree[name] = len(deps)
            for dep in deps:
                dependents[dep].append(name)

        # Find all nodes with no dependencies
        stages: list[list[str]] = []
        current_stage = [name for name, degree in in_degree.items() if degree == 0]

        while current_stage:
            stages.append(current_stage)
            next_stage: list[str] = []

            for name in current_stage:
                for dependent in dependents[name]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        next_stage.append(dependent)

            current_stage = next_stage

        # Check for circular dependencies
        processed = sum(len(stage) for stage in stages)
        if processed < len(self._plugins):
            raise PipelineError(
                "Circular dependency detected in pipeline. "
                f"Processed {processed}/{len(self._plugins)} plugins."
            )

        return stages

    def _execute_plugin(
        self,
        plugin: BasePlugin,
        target: str,
    ) -> Result:
        """Execute a single plugin with its upstream results.

        Collects results from plugins declared in `plugin.requires`
        and passes them as `upstream_results`. If a required upstream
        result is missing or failed, returns a failure result.

        Args:
            plugin: Plugin to execute.
            target: Target to process.

        Returns:
            Result from plugin execution.
        """
        # Build upstream_results from declared requires.
        upstream_results: dict[str, Result] = {}
        for dep_name in plugin.requires:
            if dep_name in self._results:
                upstream_results[dep_name] = self._results[dep_name]
            else:
                logger.debug(
                    f"Plugin {plugin.name}: upstream '{dep_name}' not available"
                )

        result = execute_plugin_safely(plugin, target, upstream_results=upstream_results)
        self._results[plugin.name] = result
        return result

    def run(self, target: str, **kwargs: Any) -> PipelineResult:
        """Execute the pipeline with concurrent stage execution.

        Plugins within the same topological stage run concurrently via
        ThreadPoolExecutor. Stages execute in dependency order.

        Skips plugins whose upstream dependencies have failed.

        Args:
            target: Target to process (domain, URL, IP, etc.)
            **kwargs: Additional arguments passed to all plugins.

        Returns:
            PipelineResult containing all results and errors.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from datetime import datetime
        from threading import Lock

        start_time = datetime.now()
        pipeline_result = PipelineResult()
        results_lock = Lock()

        logger.debug(f"Starting pipeline for target: {target}")

        try:
            stages = self._get_execution_order()

            for stage_idx, stage in enumerate(stages, start=1):
                logger.info(
                    f"Stage {stage_idx}/{len(stages)}: "
                    f"{', '.join(stage)} "
                    f"({len(stage)} plugin(s))"
                )

                # Determine which plugins in this stage should be skipped
                skipped = {}
                ready = []
                for plugin_name in stage:
                    plugin = self._plugins[plugin_name]
                    failed_deps = [
                        dep_name
                        for dep_name in plugin.requires
                        if dep_name in self._results
                        and self._results[dep_name].is_failure
                    ]

                    if plugin.requires and failed_deps:
                        if plugin.allow_partial:
                            if len(failed_deps) == len(plugin.requires):
                                skipped[plugin_name] = "all upstream dependencies failed"
                            else:
                                ready.append(plugin_name)
                        else:
                            skipped[plugin_name] = "upstream dependency failed"
                    else:
                        ready.append(plugin_name)

                # Register skipped plugins
                for name, reason in skipped.items():
                    logger.debug(f"Skipping {name}: {reason}")
                    skip_result = create_failure_result(
                        module=name,
                        error=f"Skipped: {reason}",
                        duration=timedelta(0),
                    )
                    self._results[name] = skip_result
                    pipeline_result.add_result(skip_result)

                # Execute ready plugins concurrently
                if not ready:
                    continue

                stage_workers = min(len(ready), self._max_workers)
                with ThreadPoolExecutor(max_workers=stage_workers) as executor:
                    future_map = {
                        executor.submit(
                            self._execute_plugin,
                            self._plugins[name],
                            target,
                        ): name
                        for name in ready
                    }

                    for future in as_completed(future_map):
                        name = future_map[future]
                        try:
                            result = future.result()
                        except Exception as e:
                            logger.error(f"Plugin {name} raised: {e}")
                            result = create_failure_result(
                                module=name,
                                error=str(e),
                                duration=timedelta(0),
                            )
                        with results_lock:
                            pipeline_result.add_result(result)

        except PipelineError as e:
            logger.error(f"Pipeline error: {e}")
            pipeline_result.errors.append(str(e))

        pipeline_result.duration = datetime.now() - start_time

        return pipeline_result

    def get_plugin_names(self) -> list[str]:
        """Get list of all plugin names in the pipeline.

        Returns:
            List of plugin names.
        """
        return list(self._plugins.keys())

    def get_dependencies(self, plugin_name: str) -> list[str]:
        """Get dependencies for a specific plugin.

        Args:
            plugin_name: Name of the plugin.

        Returns:
            List of dependency names.

        Raises:
            KeyError: If plugin not found.
        """
        if plugin_name not in self._dependencies:
            raise KeyError(f"Plugin '{plugin_name}' not in pipeline")
        return self._dependencies[plugin_name]

    def __repr__(self) -> str:
        """Return string representation of the pipeline."""
        return (
            f"<Pipeline: {len(self._plugins)} plugins, "
            f"max_workers={self._max_workers}>"
        )