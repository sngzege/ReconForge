"""Tool provider registry for managing all tool providers.

Responsibilities:
- Maintain registry of all tool providers
- Provide unified interface for tool access
- Track global tool availability and status
- Support dependency tracking between tools
- Enable provider lifecycle management

Design:
- Singleton-like registry to avoid creating duplicate providers
- Hierarchical organization (global → specific)
- Track provider health and status
- Provide convenience methods for common operations
"""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from reconforge.core.logging_setup import get_core_logger
from reconforge.core.projectdiscovery_provider import ProjectDiscoveryTool
from reconforge.core.tool_provider import ToolProvider

logger = get_core_logger("tool_registry")


class ToolRegistry:
    """Registry for managing all tool providers in ReconForge.

    This registry provides a centralized way to access and manage all
    external tools used by ReconForge. It maintains a hierarchical
    structure:

    - Global providers: Shared across the entire system (ProjectDiscovery)
    - Specific providers: Individual tool instances (httpx, nmap, etc.)

    The registry handles:
    - Provider initialization and caching
    - Tool availability tracking
    - Fallback mode configuration
    - Provider health monitoring
    - Dependency resolution

    Usage:
        registry = ToolRegistry()

        # Get a ProjectDiscovery tool
        httpx_provider = registry.get("httpx")
        result = httpx_provider.run(["-json"], input_data="example.com")

        # Check tool status
        if registry.is_tool_available("httpx"):
            result = registry.run_tool("httpx", ["-json"], input_data="example.com")
    """

    _instance: ClassVar[ToolRegistry | None] = None
    _initialized: ClassVar[bool] = False

    def __new__(cls) -> ToolRegistry:
        """Get singleton instance of the tool registry."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the tool registry."""
        if not self._initialized:
            self._providers: dict[str, ToolProvider] = {}
            self._tool_to_provider: dict[str, str] = {}
            self._provider_to_tools: defaultdict[str, set[str]] = defaultdict(set)

            self._initialize_providers()
            self._initialized = True

    def _initialize_providers(self) -> None:
        """Initialize all default providers."""
        logger.debug("Initializing tool providers")

        # Create global ProjectDiscovery provider
        self._providers["projectdiscovery"] = ProjectDiscoveryTool("global", "ProjectDiscovery Tools")

        # Register specific ProjectDiscovery tools
        pd_provider = self._providers["projectdiscovery"]

        for tool_name in ["httpx", "naabu", "katana", "subfinder"]:
            pd_tool = pd_provider.get(tool_name)
            self._providers[tool_name] = pd_tool
            self._tool_to_provider[tool_name] = "projectdiscovery"
            self._provider_to_tools["projectdiscovery"].add(tool_name)

    def get_provider(self, name: str) -> ToolProvider | None:
        """Get a tool provider by name.

        Args:
            name: Provider name (e.g., "projectdiscovery", "httpx").

        Returns:
            The tool provider, or None if not found.
        """
        return self._providers.get(name)

    def get(self, tool_name: str) -> ToolProvider:
        """Get a tool provider for the specified tool.

        This is the primary interface for accessing tools. It handles
        provider selection and creation as needed.

        Args:
            tool_name: Name of the tool (e.g., "httpx", "nmap").

        Returns:
            Tool provider for the specified tool.

        Raises:
            ValueError: If the tool is not supported.
        """
        if tool_name in self._providers:
            return self._providers[tool_name]

        # Try to get from a global provider
        for provider_name, provider in self._providers.items():
            if hasattr(provider, "get") and tool_name in provider._tools:
                tool_provider = provider.get(tool_name)
                self._providers[tool_name] = tool_provider
                self._tool_to_provider[tool_name] = provider_name
                self._provider_to_tools[provider_name].add(tool_name)
                return tool_provider

        raise ValueError(f"Unknown tool: {tool_name}")

    def register_provider(self, name: str, provider: ToolProvider) -> None:
        """Register a new tool provider.

        Args:
            name: Unique name for the provider.
            provider: Tool provider instance.
        """
        if name in self._providers:
            logger.warning(f"Provider {name} already registered, overwriting")

        self._providers[name] = provider

        # If provider has nested tools, register them
        if hasattr(provider, "_tools"):
            for tool_name in provider._tools:
                self._tool_to_provider[tool_name] = name
                self._provider_to_tools[name].add(tool_name)

    def enable_fallback(self, tool_name: str, enabled: bool = True) -> None:
        """Enable or disable fallback mode for a tool.

        Args:
            tool_name: Name of the tool.
            enabled: Whether fallback mode should be available.
        """
        provider = self.get(tool_name)
        provider.set_fallback_enabled(enabled)
        logger.debug(f"Fallback {'enabled' if enabled else 'disabled'} for {tool_name}")

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available (installed + validated).

        Args:
            tool_name: Name of the tool.

        Returns:
            True if the tool is available, False otherwise.
        """
        provider = self.get(tool_name)
        return provider.is_fully_available()

    def is_tool_validated(self, tool_name: str) -> bool:
        """Check if a tool has been validated as the correct binary.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if the tool is validated, False otherwise.
        """
        provider = self.get(tool_name)
        return provider.is_validated()

    def run_tool(
        self,
        tool_name: str,
        args: list[str],
        input_data: str | None = None,
        timeout: int = 300,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        """Run a tool using the registry's provider.

        Args:
            tool_name: Name of the tool to run.
            args: Command-line arguments for the tool.
            input_data: Optional data to pass via stdin.
            timeout: Maximum execution time in seconds (default 300).
            **kwargs: Additional arguments passed to subprocess.run.

        Returns:
            CompletedProcess object.

        Raises:
            ValueError: If the tool is not supported.
            ToolNotFoundError: If the tool is not installed.
            ToolInvalidError: If the tool exists but is the wrong binary.
            subprocess.CalledProcessError: If the tool exits with non-zero.
            subprocess.TimeoutExpired: If the tool times out.
        """
        from subprocess import CompletedProcess
        
        provider = self.get(tool_name)
        return provider.run(args, input_data, timeout, **kwargs)

    def run_tool_concurrent(
        self,
        tasks: list[tuple[str, list[str], str | None, int]],
        max_workers: int = 10,
    ) -> list[subprocess.CompletedProcess]:
        """Execute multiple tool tasks concurrently.

        Args:
            tasks: List of (tool_name, args, input_data, timeout) tuples.
            max_workers: Maximum number of concurrent workers.

        Returns:
            List of CompletedProcess results in the same order as tasks.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []

        def run_task(task_tuple: tuple[str, list[str], str | None, int]) -> subprocess.CompletedProcess:
            tool_name, args, input_data, timeout = task_tuple
            return self.run_tool(tool_name, args, input_data, timeout)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(run_task, task): i
                for i, task in enumerate(tasks)
            }
            
            for future in as_completed(future_to_task):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Task failed: {e}")
                    results.append(
                        subprocess.CompletedProcess(
                            args=[],
                            returncode=1,
                            stdout="",
                            stderr=str(e),
                        )
                    )

        return results

    def clear_all_caches(self) -> None:
        """Clear all cached tool information.

        Useful for testing or when tools might have been updated.
        """
        for provider in self._providers.values():
            if hasattr(provider, "clear_cache"):
                provider.clear_cache()

    def get_global_provider(self) -> ToolProvider | None:
        """Get the global ProjectDiscovery tool provider.

        Returns:
            The global provider, or None if not initialized.
        """
        return self.get_provider("projectdiscovery")

    def get_all_tools(self) -> list[str]:
        """Get list of all registered tools.

        Returns:
            List of tool names.
        """
        return list(self._providers.keys())

    def get_provider_tools(self, provider_name: str) -> set[str]:
        """Get all tools managed by a specific provider.

        Args:
            provider_name: Name of the provider.

        Returns:
            Set of tool names managed by the provider.
        """
        return self._provider_to_tools.get(provider_name, set())

    def __repr__(self) -> str:
        """Return string representation of the tool registry."""
        available = sum(1 for name in self._providers if self.is_tool_available(name))
        validated = sum(1 for name in self._providers if self.is_tool_validated(name))
        return (
            f"<ToolRegistry: {len(self._providers)} providers, "
            f"{available} available, {validated} validated>"
        )
