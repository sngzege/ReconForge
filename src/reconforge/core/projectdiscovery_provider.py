"""Tool provider for ProjectDiscovery tools (httpx, naabu, katana, subfinder).

Responsibilities:
- Provide unified interface for all ProjectDiscovery tools
- Validate these tools are the genuine ProjectDiscovery binaries
- Support concurrent execution for multiple tools
- Handle ProjectDiscovery-specific error cases

Design:
- Single provider class for all ProjectDiscovery tools
- Shared validation logic for ProjectDiscovery vendor signature
- Consistent execution interface for all tools
"""

from __future__ import annotations
import shutil
import subprocess
from typing import ClassVar

from reconforge.core.tool_provider import ToolProvider, ToolNotFoundError, ToolInvalidError


class ProjectDiscoveryTool(ToolProvider):
    """Tool provider for all ProjectDiscovery security tools.

    This provider handles the complete lifecycle for ProjectDiscovery tools:
    - Resolution of executable from PATH
    - Validation of vendor signature (ProjectDiscovery brand)
    - Execution with error handling
    - Fallback coordination

    Uses a single cache for all ProjectDiscovery tools since they
    share the same vendor signature and install base.
    """

    def __init__(self, name: str, display_name: str | None = None) -> None:
        """Initialize a ProjectDiscovery tool provider.

        Args:
            name: Tool name (must be 'httpx', 'naabu', 'katana', or 'subfinder').
            display_name: Human-readable display name (defaults to name).
        """
        super().__init__(name, display_name)

        # Registry of all ProjectDiscovery tools managed by this provider
        self._tools: dict[str, ProjectDiscoveryTool] = {}

    def register_tool(self, name: str, display_name: str | None = None) -> ProjectDiscoveryTool:
        """Register a new ProjectDiscovery tool with this provider.

        Args:
            name: Tool name.
            display_name: Human-readable display name.

        Returns:
            The registered tool provider.
        """
        if name not in self._tools:
            tool = ProjectDiscoveryTool(name, display_name)
            self._tools[name] = tool
        return self._tools[name]

    def get_tool(self, name: str) -> ProjectDiscoveryTool | None:
        """Get an already registered tool provider.

        Args:
            name: Tool name.

        Returns:
            Tool provider for the specified tool, or None if not registered.
        """
        return self._tools.get(name)

    def resolve_all(self) -> None:
        """Resolve and validate all registered ProjectDiscovery tools.

        This ensures all tools are available and validated before any
        execution begins. Exceptions from validation are propagated.
        """
        for name, tool in self._tools.items():
            try:
                tool.get_executable_path()
            except (ToolNotFoundError, ToolInvalidError):
                logger.error(f"ProjectDiscovery tool {name} failed validation")
                raise

    def get(self, name: str) -> ProjectDiscoveryTool:
        """Get or create a tool provider for the specified ProjectDiscovery tool.

        Args:
            name: Tool name ('httpx', 'naabu', 'katana', or 'subfinder').

        Returns:
            Tool provider for the specified tool.

        Raises:
            ValueError: If the tool name is not recognized.
        """
        valid_tools = ["httpx", "naabu", "katana", "subfinder"]
        if name not in valid_tools:
            raise ValueError(f"Unknown ProjectDiscovery tool: {name}")

        if name not in self._tools:
            self._tools[name] = self.register_tool(name)

        return self._tools[name]

    @property
    def expected_vendor(self) -> str:
        """Return the expected vendor name for ProjectDiscovery tools."""
        return "projectdiscovery"

    @property
    def required_markers(self) -> list[str]:
        """Return list of expected output markers for ProjectDiscovery tools."""
        return ["projectdiscovery"]

    @property
    def install_url(self) -> str:
        """Return the base installation URL for ProjectDiscovery tools."""
        return "https://github.com/projectdiscovery/"

    def _resolve_executable(self) -> str:
        """Resolve the ProjectDiscovery tool executable path.

        Returns:
            Absolute path to the tool executable.

        Raises:
            ToolNotFoundError: If the tool is not installed.
        """
        path = shutil.which(self.name)
        if path is None:
            raise ToolNotFoundError(
                f"{self.name} is not installed or not in PATH. "
                f"Install from: {self.install_url}{self.name}"
            )
        return path

    def _validate_executable(self) -> None:
        """Validate that the tool is the genuine ProjectDiscovery binary.

        Probes the tool's banner output for the ProjectDiscovery signature
        to distinguish it from name-shadowing imposters.

        Raises:
            ToolInvalidError: If the tool exists but is not the correct binary.
        """
        output = self._probe(self.name)
        lowered = output.lower()

        if not all(marker.lower() in lowered for marker in self.required_markers):
            raise ToolInvalidError(
                f"'{self.name}' is installed at {self._executable_path} but does not appear to be "
                f"the expected {self.expected_vendor} binary (probe output did not "
                f"contain {self.required_markers}). A different program may be "
                f"shadowing it on PATH. Install the correct tool from: "
                f"{self.install_url}{self.name}"
            )

    @staticmethod
    def _probe(name: str) -> str:
        """Probe a tool's banner/version output for identity markers.

        Runs the tool with no arguments and a closed stdin so banner-only
        tools exit promptly. Returns combined stdout+stderr.

        Args:
            name: Tool executable name.

        Returns:
            Combined captured output, or empty string on probe failure.
        """
        try:
            proc = subprocess.run(
                [name],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""
