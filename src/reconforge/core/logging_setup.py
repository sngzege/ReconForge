"""Logging system for ReconForge.

Responsibilities:
- Configure root logger with appropriate format and level
- Provide per-plugin logger creation
- Handle log output to console and file
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reconforge.core.config import Config


# Log format templates
_CONSOLE_FORMAT = "%(levelname)-8s | %(message)s"
_FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%d-%m-%Y %HH:%MM:%SS"


def _get_log_level(level_name: str) -> int:
    """Convert string log level to logging constant.
    Args:
        level_name: Log level name (DEBUG, INFO, WARNING, ERROR).
    Returns:
        Corresponding logging level constant.
    Raises:
        ValueError: If level name is invalid.
    """

    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    if level_name not in level_map:
        raise ValueError(
            f"Invalid log level: {level_name!r}. "
            f"Must be one of {list(level_map.keys())}"
        )
    return level_map[level_name]


def setup_logging(
    config: Config, log_dir: Path | None = None, *, force: bool = False
) -> logging.Logger:
    """Set up the logging system for ReconForge.
    Creates a root logger for the application with:
    - Console handler (WARNING level, minimal output)
    - File handler (DEBUG level, detailed format)
    Args:
        config: Configuration object containing log_level setting.
        log_dir: Optional directory for log files. If None, logs to
                 console only.
        force: If True, remove existing handlers and reconfigure.
               Useful for testing.
    Returns:
        The root ReconForge logger instance.
    """
    # Get or create the root logger for our application
    root_logger = logging.getLogger("reconforge")
    root_logger.setLevel(logging.DEBUG)  # Capture all levels, filter in handlers

    # Prevent adding handlers multiple times if called repeatedly
    # unless force=True (useful for testing)
    if root_logger.handlers and not force:
        return root_logger

    # Clear existing handlers if forcing reconfiguration
    if force:
        root_logger.handlers.clear()

    # Console handler - minimal output, only WARNING and above
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter(_CONSOLE_FORMAT)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler - detailed output for debugging
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "reconforge.log"

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Always capture everything
        file_formatter = logging.Formatter(_FILE_FORMAT, datefmt=_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return root_logger


def get_plugin_logger(plugin_name: str) -> logging.Logger:
    """Get a logger for a specific plugin.

    Creates a child logger under the reconforge.plugins namespace.
    This allows filtering logs by plugin name.

    Args:
        plugin_name: Name of the plugin (e.g., "subfinder", "httpx").

    Returns:
        Logger instance for the plugin.

    Example:
        >>> logger = get_plugin_logger("subfinder")
        >>> logger.info("Scanning target.com")
        # Output: INFO     | [subfinder] Scanning target.com
    """
    # Create logger under plugins namespace
    logger = logging.getLogger(f"reconforge.plugins.{plugin_name}")

    # Add plugin name to log messages using a filter
    class PluginFilter(logging.Filter):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.plugin_name = name

        def filter(self, record: logging.LogRecord) -> bool:
            record.msg = f"[{self.plugin_name}] {record.msg}"
            return True

    # Only add filter if not already present
    if not any(isinstance(f, PluginFilter) for f in logger.filters):
        logger.addFilter(PluginFilter(plugin_name))

    return logger


def get_core_logger(module_name: str) -> logging.Logger:
    """Get a logger for a core module.

    Creates a child logger under the reconforge.core namespace.

    Args:
        module_name: Name of the core module (e.g., "config", "pipeline").

    Returns:
        Logger instance for the core module.
    """
    return logging.getLogger(f"reconforge.core.{module_name}")