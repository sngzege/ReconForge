"""Tests for the logging system."""

import logging
from pathlib import Path

import pytest

from reconforge.core.config import Config
from reconforge.core.logging_setup import (
    get_core_logger,
    get_plugin_logger,
    setup_logging,
)


class TestSetupLogging:
    """Test logging setup."""

    def test_setup_returns_logger(self) -> None:
        """setup_logging should return a logger instance."""
        config = Config()
        logger = setup_logging(config, force=True)
        assert isinstance(logger, logging.Logger)
        assert logger.name == "reconforge"

    def test_setup_with_file_handler(self, tmp_path: Path) -> None:
        """setup_logging should create file handler when log_dir provided."""
        config = Config()
        logger = setup_logging(config, log_dir=tmp_path, force=True)

        # Should have both console and file handlers
        assert len(logger.handlers) == 2

        # Log file should be created
        log_file = tmp_path / "reconforge.log"
        assert log_file.exists()

    def test_setup_without_file_handler(self) -> None:
        """setup_logging without log_dir should only have console handler."""
        config = Config()
        logger = setup_logging(config, force=True)

        # Should only have console handler
        assert len(logger.handlers) == 1

    def test_setup_idempotent(self) -> None:
        """Calling setup_logging multiple times should not add duplicate handlers."""
        config = Config()
        logger1 = setup_logging(config, force=True)
        handler_count = len(logger1.handlers)

        logger2 = setup_logging(config)  # Second call without force
        assert len(logger2.handlers) == handler_count
        assert logger1 is logger2


class TestGetPluginLogger:
    """Test plugin logger creation."""

    def test_plugin_logger_name(self) -> None:
        """Plugin logger should have correct namespace."""
        logger = get_plugin_logger("subfinder")
        assert logger.name == "reconforge.plugins.subfinder"

    def test_plugin_logger_adds_prefix(self) -> None:
        """Plugin logger should add plugin name prefix to messages."""
        logger = get_plugin_logger("test_plugin")

        # Check that filter is added
        assert len(logger.filters) > 0


class TestGetCoreLogger:
    """Test core module logger creation."""

    def test_core_logger_name(self) -> None:
        """Core logger should have correct namespace."""
        logger = get_core_logger("config")
        assert logger.name == "reconforge.core.config"


class TestLogOutput:
    """Test actual log output."""

    def test_log_to_file(self, tmp_path: Path) -> None:
        """Logs should be written to file."""
        config = Config(log_level="DEBUG")
        logger = setup_logging(config, log_dir=tmp_path, force=True)

        logger.info("Test message")

        # Flush handlers to ensure writing
        for handler in logger.handlers:
            handler.flush()

        log_file = tmp_path / "reconforge.log"
        content = log_file.read_text()
        assert "Test message" in content

    def test_debug_not_in_console_by_default(self, caplog: pytest.LogCaptureFixture) -> None:
        """DEBUG messages should not appear in console with INFO level."""
        config = Config(log_level="INFO")
        logger = setup_logging(config, force=True)

        with caplog.at_level(logging.INFO, logger="reconforge"):
            logger.debug("Debug message")
            logger.info("Info message")

        # Check captured log records
        messages = [record.getMessage() for record in caplog.records]
        assert "Debug message" not in messages
        assert "Info message" in messages