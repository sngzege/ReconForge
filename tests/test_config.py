"""Tests for the configuration system."""

import os
from pathlib import Path

import pytest

from reconforge.core.config import Config, ConfigError, load_config


class TestConfigDefaults:
    """Test default configuration values."""

    def test_default_values(self) -> None:
        """Config should have sensible defaults when no file/env provided."""
        config = Config()
        assert config.thread_count == 10
        assert config.timeout == 30
        assert config.retry_count == 3
        assert config.cache_ttl == 86400
        assert config.log_level == "INFO"
        assert config.output_dir == "output"
        assert config.rate_limit == 100

    def test_validate_passes_with_defaults(self) -> None:
        """Default config should pass validation."""
        config = Config()
        config.validate()  # Should not raise


class TestConfigValidation:
    """Test configuration validation."""

    def test_invalid_thread_count_zero(self) -> None:
        """Thread count must be >= 1."""
        config = Config(thread_count=0)
        with pytest.raises(ConfigError, match="thread_count"):
            config.validate()

    def test_invalid_thread_count_too_high(self) -> None:
        """Thread count must be <= 100."""
        config = Config(thread_count=101)
        with pytest.raises(ConfigError, match="thread_count"):
            config.validate()

    def test_invalid_log_level(self) -> None:
        """Log level must be one of the valid choices."""
        config = Config(log_level="INVALID")
        with pytest.raises(ConfigError, match="log_level"):
            config.validate()

    def test_valid_log_levels(self) -> None:
        """All valid log levels should pass validation."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            config = Config(log_level=level)
            config.validate()


class TestConfigImmutability:
    """Test that Config is immutable."""

    def test_cannot_modify_config(self) -> None:
        """Frozen dataclass should not allow attribute modification."""
        config = Config()
        with pytest.raises(AttributeError):
            config.thread_count = 20


class TestConfigLoading:
    """Test layered config loading."""

    def test_load_from_nonexistent_file(self, tmp_path: Path) -> None:
        """Loading from nonexistent file should use defaults."""
        config_path = tmp_path / "nonexistent.toml"
        config = load_config(config_path)
        assert config.thread_count == 10

    def test_load_from_toml_file(self, tmp_path: Path) -> None:
        """TOML file should override defaults."""
        config_path = tmp_path / "reconforge.toml"
        config_path.write_text('thread_count = 20\ntimeout = 60\n')
        config = load_config(config_path)
        assert config.thread_count == 20
        assert config.timeout == 60

    def test_unknown_toml_key_raises_error(self, tmp_path: Path) -> None:
        """Unknown keys in TOML file should raise ConfigError."""
        config_path = tmp_path / "reconforge.toml"
        config_path.write_text('unknown_key = "value"\n')
        with pytest.raises(ConfigError, match="Unknown keys"):
            load_config(config_path)

    def test_env_var_overrides_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables should override file values."""
        config_path = tmp_path / "reconforge.toml"
        config_path.write_text('thread_count = 20\n')
        monkeypatch.setenv("RECONFORGE_THREAD_COUNT", "50")
        config = load_config(config_path)
        assert config.thread_count == 50

    def test_env_var_type_coercion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env vars (strings) should be coerced to correct types."""
        monkeypatch.setenv("RECONFORGE_THREAD_COUNT", "25")
        config = load_config(Path("nonexistent.toml"))
        assert config.thread_count == 25
        assert isinstance(config.thread_count, int)

    def test_invalid_env_var_raises_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Invalid env var values should raise ConfigError."""
        monkeypatch.setenv("RECONFORGE_THREAD_COUNT", "not_a_number")
        with pytest.raises(ConfigError, match="RECONFORGE_THREAD_COUNT"):
            load_config(Path("nonexistent.toml"))
