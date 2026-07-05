"""Enhanced pipeline orchestrator using capability-based scheduling.

Responsibilities:
- Manage pipeline execution based on capability dependencies
- Handle capability-based scheduling instead of plugin names
- Support flexible execution with graceful degradation
- Track capability availability and consumption
- Provide enhanced result aggregation and monitoring

Design:
- Capability-based scheduling using produces/consumes attributes
- Flexible execution with support for partial capability fulfillment
- Enhanced error handling and logging
- Detailed capability tracking and reporting
- Integration with tool provider system
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from queue import Queue
from threading import Event, Thread
from typing import Any

from reconforge.core.logging_setup import get_core_logger
from reconforge.core.result import Result, ResultStatus
from reconforge.core.enhanced_plugin import EnhancedBasePlugin, ResultType
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = get_core_logger("pipeline")


class PipelineError(Exception):
    """Raised when pipeline execution fails."""


class PipelineResult:
    """Enhanced container for all results from a pipeline execution.

    Attributes:
        results: List of all Result objects from plugins.
        errors: List of errors that occurred during execution.
        duration: Total pipeline execution time.
        capability_mapping: Mapping of capabilities to producing plugins.
        execution_summary: Summary of execution by capability.
    """

    def __init__(self) -> None:
        """Initialize an empty pipeline result."""
        self.results: list[Result] = []
        self.errors: list[str] = []
        self.duration: timedelta = timedelta(0)
        self.capability_mapping: dict[str, list[str]] = defaultdict(list)
        self.execution_summary: dict[str, Any] = {}

    def add_result(self, result: Result) -> None:
        """Add a result to the collection and update capability mapping.

        Args:
            result: Result object to add.
        """
        self.results.append(result)
        if result.has_errors:
            self.errors.extend(result.errors)

        # Update capability mapping
        if hasattr(result, 'metadata') and result.metadata:
            result_type = result.metadata.get('result_type')
            if result_type and result.module:
                self.capability_mapping[result_type].append(result.module)

    def update_execution_summary(self) -> None:
        """Update execution summary by analyzing results."""
        self.execution_summary = {
            'total_plugins': len(self.results),
            'successful_plugins': sum(1 for r in self.results if r.is_success),
            'failed_plugins': sum(1 for r in self.results if r.is_failure),
            'partial_plugins': sum(1 for r in self.results if r.is_partial),
            'capabilities_produced': len(self.capability_mapping),
            'plugins_by_type': {
                status.value: sum(1 for r in self.results if getattr(r, f'is_{status.value}', False))
                for status in ResultStatus
            }
        }

    def get_results_by_capability(self, capability: str) -> list[Result]:
        """Get all results that produced a specific capability.

        Args:
            capability: Capability name to filter by.

        Returns:
            List of results that produced the specified capability.
        """
        return [r for r in self.results if self._result_produces_capability(r, capability)]

    def _result_produces_capability(self, result: Result, capability: str) -> bool:
        """Check if a result produces a specific capability.

        Args:
            result: Result object to check.
            capability: Capability name to verify.

        Returns:
            True if the result produces the capability.
        """
        if hasattr(result, 'metadata') and result.metadata:
            result_type = result.metadata.get('result_type')
            return result_type == capability
        return False

    def get_capabilities_summary(self) -> dict[str, Any]:
        """Get a summary of all capabilities produced.

        Returns:
            Dictionary mapping capabilities to producing plugins.
        """
        return {
            'capabilities': dict(self.capability_mapping),
            'total_capabilities': len(self.capability_mapping),
            'plugins_by_capability': {
                cap: modules
                for cap, modules in self.capability_mapping.items()
                if modules
            }
        }

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
        """Return string representation of the pipeline result."""
        return (
            f"<PipelineResult: {len(self.results)} results "
            f"({self.success_count} success, {self.failure_count} failed, "
            f"{self.partial_count} partial)>"
        )

    def __str__(self) -> str:
        """Return human-readable string representation."""
        self.update_execution_summary()
        return (
            f"Pipeline Results: {len(self.results)} total results\n"
            f"  Success: {self.success_count}\n"
            f"  Failed: {self.failure_count}\n"
            f"  Partial: {self.partial_count}\n"
            f"  Capabilities: {self.get_capabilities_summary()}"
        )


class EnhancedPipeline:
    """Enhanced pipeline orchestrator using capability-based scheduling.

    This pipeline implements a capability-based execution model:
    1. Plugins declare what they can produce (produces) and consume (consumes)
    2. The pipeline builds a capability dependency graph
    3. Plugins are scheduled based on capability fulfillment, not plugin names
    4. Execution is flexible with support for partial capability fulfillment
    5. Results are tracked by capability for better downstream processing

    Key features:
    - Capability-based scheduling
    - Graceful degradation with partial capabilities
    - Enhanced result aggregation by capability
    - Flexible dependency resolution
    - Detailed execution monitoring
    """

    def __init__(self, max_workers: int = 10) -> None:
        """Initialize the enhanced pipeline.

        Args:
            max_workers: Maximum number of concurrent threads.
        """
        self._plugins: list[EnhancedBasePlugin] = []
        self._capabilities: dict[str, EnhancedBasePlugin] = {}
        self._max_workers = max_workers
        self._results: dict[str, Result] = {}
        self._execution_log: list[dict[str, Any]] = []
        self._capability_resolver = CapabilityResolver()

    def add_plugin(self, plugin: EnhancedBasePlugin) -> None:
        """Add an enhanced plugin to the pipeline.

        Args:
            plugin: EnhancedBasePlugin instance to add.
        """
        self._plugins.append(plugin)

        # Register plugin capabilities
        for capability in plugin.produces:
            self._capabilities[capability] = plugin

        logger.debug(
            f"Added plugin: {plugin.name} "
            f"(produces: {plugin.produces}, consumes: {plugin.consumes})"
        )

    def get_execution_order(self) -> list[list[str]]:
        """Calculate execution order using capability-based topological sort.

        Returns:
            List of stages, where each stage is a list of plugin names
            that can run concurrently based on capability dependencies.

        Raises:
            PipelineError: If circular capability dependency detected.
        """
        # Build capability dependency graph
        capability_deps = self._build_capability_dependency_graph()

        # Convert to plugin-level execution order
        return self._convert_capability_to_plugin_order(capability_deps)

    def _build_capability_dependency_graph(self) -> dict[str, set[str]]:
        """Build capability dependency graph.

        Returns:
            Dictionary mapping capabilities to their dependencies.
        """
        deps = defaultdict(set)

        for plugin in self._plugins:
            # For each capability this plugin produces,
            # it depends on all capabilities it consumes
            for produced_cap in plugin.produces:
                for consumed_cap in plugin.consumes:
                    deps[produced_cap].add(consumed_cap)

        return deps

    def _convert_capability_to_plugin_order(self, capability_deps: dict[str, set[str]]) -> list[list[str]]:
        """Convert capability dependencies to plugin execution order.

        Args:
            capability_deps: Capability dependency graph.

        Returns:
            List of stages (lists of plugin names).
        """
        # Create a mapping from capabilities to producing plugins
        cap_to_producers = defaultdict(list)
        for plugin in self._plugins:
            for cap in plugin.produces:
                cap_to_producers[cap].append(plugin.name)

        # Initialize stages with capabilities that have no dependencies
        stages: list[list[str]] = []
        all_capabilities = set(cap_to_producers.keys())
        resolved_capabilities = set()

        while resolved_capabilities != all_capabilities:
            # Find capabilities in this stage
            current_stage_caps = [
                cap for cap in all_capabilities
                if cap not in resolved_capabilities
                and not capability_deps.get(cap, set()) & resolved_capabilities
            ]

            if not current_stage_caps:
                raise PipelineError(
                    "Circular capability dependency detected. "
                    f"Resolved: {resolved_capabilities}, "
                    f"All: {all_capabilities}"
                )

            # Get plugins that produce these capabilities
            current_stage_plugins = []
            for cap in current_stage_caps:
                current_stage_plugins.extend(cap_to_producers.get(cap, []))

            # Remove duplicates while preserving order
            current_stage_plugins = list(dict.fromkeys(current_stage_plugins))

            stages.append(current_stage_plugins)
            resolved_capabilities.update(current_stage_caps)

        return stages

    def _execute_plugin(
        self,
        plugin: EnhancedBasePlugin,
        target: str,
    ) -> Result:
        """Execute a single plugin with its upstream results.

        Collects results from plugins whose capabilities are satisfied
        and passes them as upstream_results.

        Args:
            plugin: EnhancedBasePlugin instance to execute.
            target: Target to process.

        Returns:
            Result from plugin execution.
        """
        # Build upstream_results from satisfied capabilities
        upstream_results: dict[str, Result] = {}
        for consumed_cap in plugin.consumes:
            # Find any plugin that produces this capability
            producer = self._capabilities.get(consumed_cap)
            if producer and producer.name in self._results:
                upstream_results[producer.name] = self._results[producer.name]

        result = plugin.execute_with_monitoring(target, upstream_results)
        self._results[plugin.name] = result

        # Log execution
        self._execution_log.append({
            'timestamp': datetime.now(),
            'plugin': plugin.name,
            'status': result.status.value,
            'capabilities_produced': plugin.produces,
            'capabilities_consumed': plugin.consumes,
            'duration_ms': result.duration.total_seconds() * 1000 if result.duration else 0,
        })

        logger.info(
            f"Executed {plugin.name}: {result.status.value} "
            f"in {result.duration.total_seconds():.2f}s"
        )

        return result

    def run(self, target: str, **kwargs: Any) -> PipelineResult:
        """Execute the enhanced pipeline with capability-based scheduling.

        Args:
            target: Target to process (domain, URL, IP, etc.)
            **kwargs: Additional arguments passed to all plugins.

        Returns:
            Enhanced PipelineResult containing results and capability tracking.
        """
        start_time = datetime.now()
        pipeline_result = PipelineResult()

        logger.debug(f"Starting enhanced pipeline for target: {target}")

        try:
            # Calculate execution stages
            stages = self.get_execution_order()

            # Execute plugins in stages
            for stage_num, stage_plugins in enumerate(stages):
                logger.debug(f"Executing stage {stage_num + 1}/{len(stages)}: {stage_plugins}")

                # Execute all plugins in the current stage concurrently
                with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                    future_to_plugin = {
                        executor.submit(self._execute_plugin, plugin, target): plugin
                        for plugin in self._plugins
                        if plugin.name in stage_plugins
                    }

                    for future in as_completed(future_to_plugin):
                        plugin = future_to_plugin[future]
                        try:
                            result = future.result()
                            pipeline_result.add_result(result)
                        except Exception as e:
                            logger.error(f"Plugin {plugin.name} raised: {e}")
                            error_result = self._create_error_result(plugin.name, str(e))
                            pipeline_result.add_result(error_result)

        except PipelineError as e:
            logger.error(f"Pipeline error: {e}")
            pipeline_result.errors.append(str(e))

        pipeline_result.duration = datetime.now() - start_time
        pipeline_result.update_execution_summary()

        return pipeline_result

    def _create_error_result(self, plugin_name: str, error: str) -> Result:
        """Create an error result for a failed plugin.

        Args:
            plugin_name: Name of the failed plugin.
            error: Error message.

        Returns:
            Error Result object.
        """
        return Result(
            module=plugin_name,
            status=ResultStatus.FAILURE,
            duration=timedelta(0),
            data=None,
            errors=[error],
            metadata={"error_type": "pipeline_execution"},
        )

    def get_plugin_names(self) -> list[str]:
        """Get list of all plugin names in the pipeline.

        Returns:
            List of plugin names.
        """
        return [plugin.name for plugin in self._plugins]

    def get_capability_analysis(self) -> dict[str, Any]:
        """Analyze plugin capabilities and dependencies.

        Returns:
            Detailed analysis of plugin capabilities and dependencies.
        """
        analysis = {
            'total_plugins': len(self._plugins),
            'capabilities_summary': {},
            'dependency_graph': {},
            'execution_stages': self.get_execution_order(),
        }

        for plugin in self._plugins:
            analysis['capabilities_summary'][plugin.name] = {
                'produces': plugin.produces,
                'consumes': plugin.consumes,
                'optional': plugin.optional_capabilities,
                'allow_partial': plugin.allow_partial,
            }

            # Build dependency mapping
            deps = set()
            for consumed_cap in plugin.consumes:
                for other_plugin in self._plugins:
                    if other_plugin.name != plugin.name and consumed_cap in other_plugin.produces:
                        deps.add(other_plugin.name)

            analysis['dependency_graph'][plugin.name] = list(deps)

        return analysis

    def get_execution_log(self) -> list[dict[str, Any]]:
        """Get detailed execution log.

        Returns:
            List of execution log entries.
        """
        return self._execution_log

    def clear_results(self) -> None:
        """Clear all plugin results.

        Useful for running the pipeline multiple times with different targets.
        """
        self._results.clear()
        self._execution_log.clear()

    def __repr__(self) -> str:
        """Return string representation of the enhanced pipeline."""
        return (
            f"<EnhancedPipeline: {len(self._plugins)} plugins, "
            f"max_workers={self._max_workers}>"
        )


class CapabilityResolver:
    """Resolve capability dependencies and execution order.

    This class handles the complex logic of resolving capability dependencies
    between plugins, including support for partial capability fulfillment.
    """

    def __init__(self) -> None:
        """Initialize the capability resolver."""
        self._cache: dict[str, list[list[str]]] = {}

    def resolve(
        self,
        plugins: list[EnhancedBasePlugin],
    ) -> list[list[str]]:
        """Resolve execution order for a list of plugins.

        Args:
            plugins: List of EnhancedBasePlugin instances.

        Returns:
            List of stages (each stage is a list of plugin names).
        """
        # Create cache key
        cache_key = tuple(sorted(p.name for p in plugins))

        if cache_key in self._cache:
            return self._cache[cache_key]

        # Build capability dependency graph
        stages = self._calculate_capability_stages(plugins)

        # Cache the result
        self._cache[cache_key] = stages

        return stages

    def _calculate_capability_stages(
        self,
        plugins: list[EnhancedBasePlugin],
    ) -> list[list[str]]:
        """Calculate capability stages using topological sort.

        Args:
            plugins: List of EnhancedBasePlugin instances.

        Returns:
            List of stages (each stage is a list of plugin names).
        """
        # Create capability -> producers mapping
        cap_to_producers: dict[str, list[str]] = defaultdict(list)
        for plugin in plugins:
            for cap in plugin.produces:
                cap_to_producers[cap].append(plugin.name)

        # Create capability dependency graph
        cap_deps: dict[str, set[str]] = defaultdict(set)
        for plugin in plugins:
            for produced_cap in plugin.produces:
                for consumed_cap in plugin.consumes:
                    cap_deps[produced_cap].add(consumed_cap)

        # Topological sort
        stages: list[list[str]] = []
        all_caps = set(cap_to_producers.keys())
        resolved_caps = set()

        while resolved_caps != all_caps:
            # Find capabilities that can be resolved in this stage
            current_stage_caps = [
                cap for cap in all_caps
                if cap not in resolved_caps
                and not cap_deps.get(cap, set()) & resolved_caps
            ]

            if not current_stage_caps:
                raise PipelineError(
                    "Circular capability dependency detected"
                )

            # Convert capabilities to plugins
            stage_plugins = []
            for cap in current_stage_caps:
                stage_plugins.extend(cap_to_producers.get(cap, []))

            # Remove duplicates while preserving order
            stage_plugins = list(dict.fromkeys(stage_plugins))

            stages.append(stage_plugins)
            resolved_caps.update(current_stage_caps)

        return stages

    def clear_cache(self) -> None:
        """Clear the capability resolver cache."""
        self._cache.clear()
