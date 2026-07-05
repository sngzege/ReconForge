"""Tool provider base class for external security tools.

Responsibilities:
- Provide interface for all external tool execution
- Handle tool validation and caching
- Manage fallback behavior when tools are unavailable
- Track tool availability and capabilities
- Provide consistent error handling across all tools

Design:
- Abstract base class with common operations
- Concrete implementations per tool type
- Validation framework ensuring correct binaries
- Fallback mechanisms for degraded operation
"""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from datetime import timedelta
from pathlib import Path
from typing import Any

from reconforge.core.logging_setup import get_core_logger
from reconforge.core.tool_resolver import ToolUnavailableError

logger = get_core_logger("tool_provider")


class ToolUnavailableError(RuntimeError):
    """Raised when a required external tool is missing or is the wrong binary."""


class ToolNotFoundError(ToolUnavailableError):
    """Raised when a required external tool is not installed."""


class ToolInvalidError(ToolUnavailableError):
    """Raised when a required external tool is installed but is the wrong binary."""


class ToolProvider(ABC):
    """Abstract base class for all external tool providers.

    Responsibilities:
    - Provide unified interface for tool execution
    - Handle tool validation and availability checking
    - Manage tool-specific error handling
    - Support fallback/degraded mode operations
    - Track tool execution metrics

    This abstraction allows plugins to request tool execution without
    knowing about the specific tool implementation details.
    """

    def __init__(self, name: str, display_name: str | None = None) -> None:
        """Initialize a tool provider.

        Args:
            name: Internal tool name (e.g., "httpx", "naabu").
            display_name: Human-readable display name (defaults to name).
        """
        self.name = name
        self.display_name = display_name or name
        self._executable_path: str | None = None
        self._is_available = False
        self._is_validated = False
        self._fallback_enabled = False

    @property
    @abstractmethod
    def expected_vendor(self) -> str:
        """Return the expected vendor name for this tool."""
        pass

    @property
    @abstractmethod
    def required_markers(self) -> list[str]:
        """Return list of expected output markers for vendor verification."""
        pass

    @property
    @abstractmethod
    def install_url(self) -> str:
        """Return URL for installation instructions."""
        pass

    def set_fallback_enabled(self, enabled: bool) -> None:
        """Enable or disable fallback mode for this tool.

        Args:
            enabled: Whether fallback mode should be available.
        """
        self._fallback_enabled = enabled

    def is_available(self) -> bool:
        """Check if the tool is available in the system.

        Returns:
            True if the tool exists in PATH, False otherwise.
        """
        return self._is_available

    def is_validated(self) -> bool:
        """Check if the tool has been validated as the correct binary.

        Returns:
            True if the tool has been checked and confirmed, False otherwise.
        """
        return self._is_validated

    def is_fully_available(self) -> bool:
        """Check if the tool is available AND validated.

        Returns:
            True if the tool is available and correct, False otherwise.
        """
        return self.is_available() and self.is_validated()

    def get_executable_path(self) -> str:
        """Get the absolute path to the tool executable.

        Returns:
            Absolute path to the tool.

        Raises:
            ToolNotFoundError: If the tool is not installed.
            ToolInvalidError: If the tool exists but is the wrong binary.
        """
        if self._executable_path is None:
            self._executable_path = self._resolve_executable()
            self._is_available = True

        if not self.is_validated():
            self._validate_executable()

        return self._executable_path

    def clear_cache(self) -> None:
        """Clear cached tool resolution and validation.

        Useful for testing or when tools might have been updated.
        """
        self._executable_path = None
        self._is_available = False
        self._is_validated = False

    def run(
        self,
        args: list[str],
        input_data: str | None = None,
        timeout: int = 300,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        """Execute the tool with arguments.

        Args:
            args: Command-line arguments for the tool.
            input_data: Optional data to pass via stdin.
            timeout: Maximum execution time in seconds (default 300).
            **kwargs: Additional arguments passed to subprocess.run.

        Returns:
            CompletedProcess object with stdout, stderr, and returncode.

        Raises:
            ToolNotFoundError: If the tool is not installed.
            ToolInvalidError: If the tool exists but is the wrong binary.
            subprocess.CalledProcessError: If the tool exits with non-zero.
            subprocess.TimeoutExpired: If the tool times out.
            ToolUnavailableError: If fallback is enabled and urllib fallback occurs.
        """
        try:
            executable = self.get_executable_path()
            
            proc = subprocess.run(
                [executable] + args,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=timeout,
                **kwargs,
            )

            return proc

        except FileNotFoundError:
            if self._fallback_enabled:
                raise ToolUnavailableError(
                    f"{self.name}: Tool available but executable not found. "
                    f"Tool may have been uninstalled or PATH changed."
                )
            raise ToolNotFoundError(
                f"{self.name} is not installed or not in PATH. "
                f"Install from: {self.install_url}"
            ) from None

        except subprocess.CalledProcessError as e:
            logger.debug(f"Tool {self.name} failed with exit code {e.returncode}")
            raise

        except subprocess.TimeoutExpired:
            logger.warning(f"Tool {self.name} timed out after {timeout} seconds")
            raise

    def run_urllib_fallback(
        self,
        target: str,
        timeout: int = 10,
    ) -> str | None:
        """Execute a basic HTTP/HTTPS probe using urllib as a degraded fallback.

        This provides minimal connectivity checking when the primary tool
        is unavailable. Cannot fingerprint servers or detect technologies.

        Args:
            target: Target URL or IP to probe.
            timeout: Maximum probe time in seconds (default 10).

        Returns:
            Alive URL if target responds, None otherwise.

        Raises:
            ToolUnavailableError: If urllib fallback is not enabled.
        """
        if not self._fallback_enabled:
            raise ToolUnavailableError(
                f"{self.name}: Fallback not enabled. "
                f"Set environment variable RECONFORGE_{self.name.upper()}_FALLBACK."
            )

        import urllib.error
        import urllib.request

        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            try:
                request = urllib.request.Request(
                    url, headers={"User-Agent": "ReconForge/1.0"}, method="GET"
                )
                with urllib.request.urlopen(request, timeout=timeout):
                    return url
            except urllib.error.HTTPError:
                return url
            except (urllib.error.URLError, TimeoutError, OSError):
                continue

        return None

    def _resolve_executable(self) -> str:
        """Resolve the tool executable path (to be implemented by subclass)."""
        raise NotImplementedError

    def _validate_executable(self) -> None:
        """Validate that the tool is the correct binary (to be implemented by subclass)."""
        raise NotImplementedError

    def execute_concurrent(
        self,
        tasks: list[tuple[list[str], str | None, int]],
        max_workers: int = 10,
    ) -> list[subprocess.CompletedProcess]:
        """Execute multiple tool tasks concurrently.

        Args:
            tasks: List of (args, input_data, timeout) tuples.
            max_workers: Maximum number of concurrent workers.

        Returns:
            List of CompletedProcess results in the same order as tasks.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []

        def run_task(task_tuple: tuple[list[str], str | None, int]) -> subprocess.CompletedProcess:
            args, input_data, timeout = task_tuple
            return self.run(args, input_data, timeout)

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

    def __repr__(self) -> str:
        """Return string representation of the tool provider."""
        return (
            f"<ToolProvider: {self.name} "
            f"(available={self.is_available()}, validated={self.is_validated()})>"
        )
