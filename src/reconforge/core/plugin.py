"""Plugin interface for ReconForge.

Responsibilities:
- Define the abstract base class all plugins must implement
- Specify the run() -> Result contract
- Provide plugin metadata interface (name, version, description)

Design:
- Uses ABC (Abstract Base Class) to enforce interface contract
- All plugins inherit from BasePlugin
- Core only knows about BasePlugin interface, not specific implementations
- Plugins are self-contained and never call each other directly
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.result import Result


class BasePlugin(ABC):
    """Abstract base class for all ReconForge plugins.

    Every plugin must implement:
    - name: Plugin identifier (e.g., "subfinder", "httpx")
    - run(): Execute the plugin and return a Result

    Optional overrides:
    - version: Plugin version string
    - description: Human-readable plugin description
    - dependencies: List of plugin names this plugin depends on
    - setup(): One-time initialization before run()
    - teardown(): Cleanup after run()

    Example:
        class SubfinderPlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "subfinder"

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                # Implementation...
                pass
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this plugin.

        This name is used for:
        - Logger naming (reconforge.plugins.<name>)
        - Dependency references
        - Result module attribution

        Returns:
            Unique plugin identifier string.
        """

    @property
    def version(self) -> str:
        """Return the version of this plugin.

        Override in subclass if version tracking is needed.

        Returns:
            Version string (default: "0.1.0").
        """
        return "0.1.0"

    @property
    def description(self) -> str:
        """Return a human-readable description of this plugin.

        Override in subclass to provide meaningful description.

        Returns:
            Plugin description string.
        """
        return f"{self.name} plugin"

    @property
    def dependencies(self) -> list[str]:
        """Return list of plugin names this plugin depends on.

        Override in subclass to declare dependencies.
        The Pipeline will ensure dependencies run before this plugin.

        Returns:
            List of plugin name strings (empty if no dependencies).
        """
        return []

    requires: ClassVar[list[str]] = []
    """List of plugin names whose results this plugin needs.

    Override in subclass to declare upstream dependencies.
    Pipeline will pass results from these plugins as upstream_results.

    Example:
        requires: ClassVar[list[str]] = ["normalize_url", "dns_resolver"]
    """

    allow_partial: ClassVar[bool] = False
    """Whether this plugin may run with partial upstream data.

    When True, the Pipeline only skips this plugin if ALL of its declared
    `requires` failed. When False (default), the plugin is skipped if ANY
    required upstream failed. Set True for plugins that can tolerate
    missing upstream sources (e.g. merge_engine).
    """

    @abstractmethod
    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Execute the plugin's main logic.

        This is the core method that every plugin must implement.
        It should:
        1. Perform the plugin's specific task
        2. Measure execution duration
        3. Return a Result object with the findings

        Args:
            target: The target to scan/process (domain, URL, IP, etc.)
            upstream_results: Results from plugins declared in `requires`.
                             Always a dict (empty if no dependencies).
                             Keys are plugin names, values are Result objects.

        Returns:
            Result object containing the plugin's findings.

        Raises:
            Exception: Any exception should be caught by the caller
                      (Pipeline/Scheduler) and converted to a FAILURE Result.
        """

    def setup(self, **kwargs: Any) -> None:
        """Perform one-time initialization before run().

        Override in subclass if setup is needed (e.g., checking if
        external tool is installed, validating API keys).

        Args:
            **kwargs: Setup parameters from config or pipeline.

        Raises:
            RuntimeError: If setup fails (plugin will be marked as failed).
        """

    def teardown(self) -> None:
        """Perform cleanup after run().

        Override in subclass if cleanup is needed (e.g., closing
        connections, removing temporary files).

        This method is called even if run() raises an exception.
        """

    def __repr__(self) -> str:
        """Return string representation of the plugin."""
        return f"<Plugin: {self.name} v{self.version}>"


class PluginError(Exception):
    """Base exception for plugin-related errors."""


class PluginSetupError(PluginError):
    """Raised when plugin setup fails."""


class PluginExecutionError(PluginError):
    """Raised when plugin execution fails."""


def validate_plugin(plugin: BasePlugin) -> bool:
    """Validate that a plugin instance is properly configured.

    Checks:
    - Plugin has a non-empty name
    - Plugin name contains only valid characters (alphanumeric, underscore, hyphen)
    - Plugin version is non-empty

    Args:
        plugin: Plugin instance to validate.

    Returns:
        True if plugin is valid.

    Raises:
        PluginError: If plugin validation fails.
    """
    import re

    if not plugin.name:
        raise PluginError("Plugin name cannot be empty")

    if not re.match(r"^[a-zA-Z0-9_-]+$", plugin.name):
        raise PluginError(
            f"Plugin name '{plugin.name}' contains invalid characters. "
            "Only alphanumeric, underscore, and hyphen are allowed."
        )

    if not plugin.version:
        raise PluginError("Plugin version cannot be empty")

    return True


def execute_plugin_safely(
    plugin: BasePlugin,
    target: str,
    upstream_results: dict[str, Result] | None = None,
) -> Result:
    """Execute a plugin with error handling and timing.

    This is a helper function that:
    1. Validates the plugin
    2. Calls setup()
    3. Calls run() with timing
    4. Calls teardown() (even if run() fails)
    5. Returns a Result (never raises)

    Args:
        plugin: Plugin instance to execute.
        target: Target to process.
        upstream_results: Results from upstream plugins (default: empty dict).

    Returns:
        Result object with plugin findings or error information.
    """
    from datetime import datetime

    from reconforge.core.logging_setup import get_plugin_logger
    from reconforge.core.result import ResultStatus, create_failure_result

    logger = get_plugin_logger(plugin.name)
    start_time = datetime.now()

    if upstream_results is None:
        upstream_results = {}

    try:
        # Validate plugin
        validate_plugin(plugin)

        # Setup phase
        logger.debug(f"Setting up {plugin.name}")
        plugin.setup()

        # Execution phase
        logger.info(f"Running {plugin.name} on {target}")
        result = plugin.run(target, upstream_results)

        # Ensure result has correct module name
        if result.module != plugin.name:
            result = Result(
                module=plugin.name,
                status=result.status,
                duration=result.duration,
                data=result.data,
                errors=result.errors,
                metadata=result.metadata,
            )

        return result

    except Exception as e:
        # Catch all exceptions and convert to failure result
        duration = datetime.now() - start_time
        logger.error(f"Plugin {plugin.name} failed: {e}")

        return create_failure_result(
            module=plugin.name,
            error=str(e),
            duration=duration if isinstance(duration, timedelta) else timedelta(0),
        )

    finally:
        # Teardown phase (always runs)
        try:
            plugin.teardown()
        except Exception as e:
            logger.warning(f"Plugin {plugin.name} teardown failed: {e}")