"""Enhanced plugin interface with result type tracking.

Responsibilities:
- Define the enhanced abstract base class with result type tracking
- Provide helper methods for creating different result types
- Manage result type compatibility validation
- Support capability-based plugin relationships

Design:
- Extends BasePlugin with result type information
- Introduces capability-based dependency system
- Provides enhanced result tracking and validation
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import timedelta
from enum import Enum
from typing import Any

from reconforge.core.result import Result
from reconforge.core.logging_setup import get_plugin_logger
from reconforge.core.tool_registry import get_global_registry
from reconforge.core.tool_provider import ToolUnavailableError


class ResultType(Enum):
    """Types of results that plugins can produce.

    Attributes:
        HOST_LIST: List of hostnames or IP addresses.
        ALIVE_HOSTS: Hosts that responded to probes.
        OPEN_PORTS: Ports that were found open.
        HTTP_FINGERS: HTTP fingerprinting results.
        HTML_CONTENT: HTML page content.
        ENDPOINTS: Discovered endpoints.
        SSL_INFO: SSL certificate information.
        TECHNOLOGIES: Detected technologies.
        DNS_RECORDS: DNS record information.
        WAYBACK_URLS: Wayback Machine URLs.
        JS_FILES: JavaScript files found.
        HEADERS: HTTP headers.
        ROBOTSTXT: robots.txt content.
        SITEMAP: sitemap.xml content.
        METADATA: General metadata.
        TEXT: Generic text output.
        JSON: JSON data output.
        MERGED: Merged data from multiple sources.
    """

    HOST_LIST = "host_list"
    ALIVE_HOSTS = "alive_hosts"
    OPEN_PORTS = "open_ports"
    HTTP_FINGERS = "http_fingers"
    HTML_CONTENT = "html_content"
    ENDPOINTS = "endpoints"
    SSL_INFO = "ssl_info"
    TECHNOLOGIES = "technologies"
    DNS_RECORDS = "dns_records"
    WAYBACK_URLS = "wayback_urls"
    JS_FILES = "js_files"
    HEADERS = "headers"
    ROBOTSTXT = "robots_txt"
    SITEMAP = "sitemap"
    METADATA = "metadata"
    TEXT = "text"
    JSON = "json"
    MERGED = "merged"


class Capability(Enum):
    """Capabilities that define what a plugin can produce and consume.

    A plugin's capability is declared via its produces and consumes
    attributes. This enables the scheduler to build a dependency graph
    based on capabilities rather than just plugin names.

    Plugin Capability Types:
        Input-only: Can only consume (e.g., merge_engine)
        Output-only: Can only produce (e.g., subfinder)
        Bidirectional: Can both produce and consume (e.g., httpx_alive)
    """

    PRODUCES_HOSTS = "produces_host_list"
    PRODUCES_ALIVE = "produces_alive_hosts"
    PRODUCES_PORTS = "produces_open_ports"
    PRODUCES_HTTP_FING = "produces_http_fingers"
    PRODUCES_HTML = "produces_html_content"
    PRODUCES_ENDPOINTS = "produces_endpoints"
    PRODUCES_TECH = "produces_technologies"
    PRODUCES_DNS = "produces_dns_records"
    PRODUCES_WAYBACK = "produces_wayback_urls"
    PRODUCES_JS = "produces_js_files"
    PRODUCES_HEADERS = "produces_headers"
    PRODUCES_ROBOTS = "produces_robots_txt"
    PRODUCES_SITEMAP = "produces_sitemap"
    PRODUCES_META = "produces_metadata"


class PluginError(Exception):
    """Base exception for plugin-related errors."""


class PluginSetupError(PluginError):
    """Raised when plugin setup fails."""


class PluginExecutionError(PluginError):
    """Raised when plugin execution fails."""


class PluginCapabilityError(PluginError):
    """Raised when there's a capability mismatch."""


class EnhancedBasePlugin(ABC):
    """Enhanced abstract base class for all ReconForge plugins.

    Extended version of BasePlugin with enhanced capabilities:
    - Result type tracking
    - Capability-based dependency system
    - Enhanced error handling
    - Tool provider integration
    - Performance monitoring

    Each plugin declares:
    - What it can produce (produces attribute)
    - What it can consume (consumes attribute)
    - Required capabilities for execution
    - Fallback mechanisms for degraded operation
    """

    produces: list[str] = []
    """List of capability names this plugin can produce.

    Examples:
        produces: ["produces_host_list"]  # Produces host list
        produces: ["produces_alive_hosts", "produces_open_ports"]  # Produces both
    """

    consumes: list[str] = []
    """List of capability names this plugin can consume.

    Examples:
        consumes: ["produces_host_list"]  # Consumes host list
        consumes: ["produces_host_list", "produces_wayback_urls"]  # Consumes both
    """

    optional_capabilities: list[str] = []
    """List of optional capabilities this plugin can work with.

    Plugins with optional capabilities can still execute with partial
    capability fulfillment, producing a PARTIAL result.
    """

    allow_partial: bool = False
    """Whether this plugin may run with partial capability fulfillment.

    When True, the Scheduler only skips this plugin if ALL of its declared
    capabilities are missing. When False (default), the plugin is skipped
    if ANY required capability is missing.
    """

    name: str
    """Plugin identifier (e.g., "subfinder", "httpx")."""

    version: str = "1.0.0"
    """Plugin version string."""

    description: str = ""
    """Human-readable plugin description."""

    def __init__(self) -> None:
        """Initialize the plugin with enhanced logging and monitoring."""
        self.logger = get_plugin_logger(self.name)
        self._tool_registry = get_global_registry()
        self._setup_hooks()

    def _setup_hooks(self) -> None:
        """Setup plugin-specific hooks and pre-flight validation."""
        pass

    def can_produce(self, capability: str) -> bool:
        """Check if this plugin can produce a specific capability.

        Args:
            capability: Capability name to check.

        Returns:
            True if the plugin can produce this capability.
        """
        return capability in self.produces

    def can_consume(self, capability: str) -> bool:
        """Check if this plugin can consume a specific capability.

        Args:
            capability: Capability name to check.

        Returns:
            True if the plugin can consume this capability.
        """
        return capability in self.consumes

    def is_capability_compatible(self, capability: str) -> bool:
        """Check if plugin is compatible with a capability.

        Args:
            capability: Capability name to check.

        Returns:
            True if the plugin produces or consumes this capability.
        """
        return capability in self.produces or capability in self.consumes

    def get_capabilities_summary(self) -> dict[str, Any]:
        """Get a summary of this plugin's capabilities.

        Returns:
            Dictionary with produces, consumes, and optional lists.
        """
        return {
            "produces": self.produces,
            "consumes": self.consumes,
            "optional": self.optional_capabilities,
            "allow_partial": self.allow_partial,
        }

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """Return the unique name of this plugin.

        Returns:
            Unique plugin identifier string.
        """
        pass

    @property
    def name(self) -> str:
        """Get the plugin name for compatibility."""
        return self.plugin_name

    @property
    def version(self) -> str:
        """Return the version of this plugin.

        Override in subclass if version tracking is needed.

        Returns:
            Version string (default: "1.0.0").
        """
        return "1.0.0"

    @property
    def description(self) -> str:
        """Return a human-readable description of this plugin.

        Override in subclass to provide meaningful description.

        Returns:
            Plugin description string.
        """
        return f"{self.name} plugin"

    @property
    def requires(self) -> list[str]:
        """Return list of plugin names this plugin depends on.

        Legacy dependency system for backward compatibility.

        Returns:
            List of plugin name strings (empty if no dependencies).
        """
        return []

    @abstractmethod
    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Execute the plugin's main logic.

        This is the core method that every plugin must implement.
        It should:
        1. Perform the plugin's specific task
        2. Measure execution duration
        3. Return a Result object with the findings
        4. Handle capability fulfillment

        Args:
            target: The target to scan/process (domain, URL, IP, etc.)
            upstream_results: Results from plugins declared in `requires`.

        Returns:
            Result object containing the plugin's findings.

        Raises:
            Exception: Any exception should be caught by the caller
                       and converted to a FAILURE Result.
        """
        pass

    def setup(self, **kwargs: Any) -> None:
        """Perform one-time initialization before run().

        Override in subclass if setup is needed (e.g., checking if
        external tool is available, validating API keys).

        Args:
            **kwargs: Setup parameters from config or pipeline.

        Raises:
            PluginSetupError: If setup fails.
        """
        pass

    def teardown(self) -> None:
        """Perform cleanup after run().

        This method is called even if run() raises an exception.
        """
        pass

    def validate_capabilities(self, available_capabilities: dict[str, bool]) -> bool:
        """Validate if the plugin has the capabilities it needs.

        Args:
            available_capabilities: Dict of available capabilities.

        Returns:
            True if the plugin has all required capabilities.

        Raises:
            PluginCapabilityError: If capability validation fails.
        """
        missing_capabilities = []
        for required in self.consumes:
            if not available_capabilities.get(required, False):
                missing_capabilities.append(required)

        if missing_capabilities and not self.allow_partial:
            raise PluginCapabilityError(
                f"Plugin {self.name} missing required capabilities: {missing_capabilities}"
            )

        return len(missing_capabilities) == 0

    def get_result_type(self, result: Result) -> ResultType | None:
        """Get the result type of a Result object.

        Args:
            result: Result object to analyze.

        Returns:
            ResultType if determined, None otherwise.
        """
        # Check result metadata
        if result.metadata and "result_type" in result.metadata:
            try:
                return ResultType(result.metadata["result_type"])
            except ValueError:
                pass

        # Infer from data content
        if result.data is None:
            return None

        # Common mappings
        if isinstance(result.data, list):
            # Heuristics based on item structure
            if result.data and isinstance(result.data[0], str):
                if any("." in item and len(item.split(".")) > 1 for item in result.data):
                    return ResultType.DNS_RECORDS
                if any("/" in item and len(item.split("/")) > 2 for item in result.data):
                    return ResultType.HEADERS
                return ResultType.HOST_LIST
            elif result.data and isinstance(result.data[0], dict):
                return ResultType.JSON

        return None

    def create_success_result(
        self,
        data: Any,
        result_type: ResultType | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Result:
        """Create a success result with result type tracking.

        Args:
            data: Result data.
            result_type: Type of result being created.
            metadata: Optional metadata.

        Returns:
            Success Result.
        """
        if metadata is None:
            metadata = {}

        if result_type:
            metadata["result_type"] = result_type.value

        return Result(
            module=self.name,
            status="success",
            duration=0,  # To be set by caller
            data=data,
            metadata=metadata,
        )

    def create_failure_result(
        self,
        error: str,
        result_type: ResultType | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Result:
        """Create a failure result with result type tracking.

        Args:
            error: Error message.
            result_type: Type of result being created.
            metadata: Optional metadata.

        Returns:
            Failure Result.
        """
        if metadata is None:
            metadata = {}

        if result_type:
            metadata["result_type"] = result_type.value

        return Result(
            module=self.name,
            status="failure",
            duration=0,  # To be set by caller
            data=None,
            errors=[error],
            metadata=metadata,
        )

    def create_partial_result(
        self,
        data: Any,
        error: str,
        result_type: ResultType | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Result:
        """Create a partial result with result type tracking.

        Args:
            data: Partial result data.
            error: Error message for the partial failure.
            result_type: Type of result being created.
            metadata: Optional metadata.

        Returns:
            Partial Result.
        """
        if metadata is None:
            metadata = {}

        if result_type:
            metadata["result_type"] = result_type.value

        return Result(
            module=self.name,
            status="partial",
            duration=0,  # To be set by caller
            data=data,
            errors=[error],
            metadata=metadata,
        )

    def execute_with_monitoring(
        self,
        target: str,
        upstream_results: dict[str, Result],
    ) -> Result:
        """Execute plugin with enhanced monitoring and capability validation.

        Args:
            target: Target to process.
            upstream_results: Results from upstream plugins.

        Returns:
            Result object with monitoring information.
        """
        from datetime import datetime

        start_time = datetime.now()

        # Analyze upstream results for capability mapping
        available_capabilities = {}
        for result in upstream_results.values():
            result_type = self.get_result_type(result)
            if result_type:
                available_capabilities[result_type.value] = True

        # Validate capabilities
        try:
            self.validate_capabilities(available_capabilities)
        except PluginCapabilityError as e:
            self.logger.warning(f"Capability validation failed: {e}")
            if self.allow_partial:
                self.logger.info(f"Continuing with partial capabilities for {self.name}")
            else:
                return self.create_failure_result(
                    f"Capability validation failed: {e}",
                    metadata={"validation_failed": True},
                )

        # Execute with enhanced error handling
        try:
            result = self.run(target, upstream_results)

            # Ensure duration is set
            if hasattr(result, "duration") and result.duration is None:
                from datetime import datetime
                result.duration = datetime.now() - start_time

            return result

        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
            return self.create_failure_result(
                f"Plugin execution failed: {e}",
                metadata={"execution_error": True},
            )

    def setup_tool_access(self, **kwargs: Any) -> None:
        """Setup tool provider access for this plugin.

        Args:
            **kwargs: Setup parameters including fallback configuration.
        """
        # Enable fallback for tools if requested
        enable_fallback = kwargs.get("enable_fallback", False)

        # Configure specific tool fallbacks
        tool_configs = kwargs.get("tool_configs", {})

        for tool_name, should_fallback in tool_configs.items():
            try:
                self._tool_registry.enable_fallback(tool_name, should_fallback)
            except ValueError:
                self.logger.debug(f"Tool {tool_name} not in registry")

    def __repr__(self) -> str:
        """Return string representation of the plugin."""
        return f"<Plugin: {self.name} v{self.version}>"
