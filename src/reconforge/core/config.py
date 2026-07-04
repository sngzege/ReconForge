"""Configuration system for ReconForge.

Responsibilities:
- Load configuration from defaults, file, and environment variables
- Validate configuration values
- Provide immutable Config object to other modules
"""

from __future__ import annotations
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""


# Default configuration values
_DEFAULTS: dict[str, Any] = {
    "thread_count": 10,
    "timeout": 30,
    "retry_count": 3,
    "cache_ttl": 86400,  # 24 hours in seconds
    "log_level": "INFO",
    "output_dir": "output",
    "rate_limit": 100,  # requests per second
}

# Type mapping for env var coercion
_TYPE_MAP: dict[str, type] = {
    "thread_count": int,
    "timeout": int,
    "retry_count": int,
    "cache_ttl": int,
    "log_level": str,
    "output_dir": str,
    "rate_limit": int,
}

# Valid ranges for validation
_VALID_RANGES: dict[str, dict[str, Any]] = {
    "thread_count": {"min": 1, "max": 100},
    "timeout": {"min": 1, "max": 3600},
    "retry_count": {"min": 0, "max": 10},
    "cache_ttl": {"min": 0, "max": 604800},  # max 7 days
    "log_level": {"choices": ["DEBUG", "INFO", "WARNING", "ERROR"]},
    "rate_limit": {"min": 1, "max": 10000},
}


@dataclass(frozen=True, slots=True)
class Config:
    """Immutable configuration object for ReconForge.

    Attributes:
        thread_count: Number of concurrent threads for parallel operations.
        timeout: Default timeout in seconds for network operations.
        retry_count: Number of retries for failed operations.
        cache_ttl: Time-to-live for cached results in seconds.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        output_dir: Directory for output files.
        rate_limit: Maximum requests per second.
    """

    thread_count: int = _DEFAULTS["thread_count"]
    timeout: int = _DEFAULTS["timeout"]
    retry_count: int = _DEFAULTS["retry_count"]
    cache_ttl: int = _DEFAULTS["cache_ttl"]
    log_level: str = _DEFAULTS["log_level"]
    output_dir: str = _DEFAULTS["output_dir"]
    rate_limit: int = _DEFAULTS["rate_limit"]

    def validate(self) -> None:
        """Validate all configuration values.

        Raises:
            ConfigError: If any configuration value is out of valid range.
        """
        for field_name, constraints in _VALID_RANGES.items():
            value = getattr(self, field_name)

            if "choices" in constraints:
                if value not in constraints["choices"]:
                    raise ConfigError(
                        f"Invalid {field_name}: {value!r}. "
                        f"Must be one of {constraints['choices']}"
                    )
            else:
                min_val = constraints.get("min")
                max_val = constraints.get("max")
                if min_val is not None and value < min_val:
                    raise ConfigError(
                        f"Invalid {field_name}: {value}. "
                        f"Must be >= {min_val}"
                    )
                if max_val is not None and value > max_val:
                    raise ConfigError(
                        f"Invalid {field_name}: {value}. "
                        f"Must be <= {max_val}"
                    )


def _load_from_toml(config_path: Path) -> dict[str, Any]:
    """Load configuration from a TOML file.

    Args:
        config_path: Path to the TOML configuration file.

    Returns:
        Dictionary of configuration values from the file.

    Raises:
        ConfigError: If file contains unknown keys or is malformed.
    """
    if not config_path.exists():
        return {}

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Invalid TOML in {config_path}: {e}") from e

    # Check for unknown keys (fail loud — file is hand-written)
    unknown_keys = set(data.keys()) - set(_DEFAULTS.keys())
    if unknown_keys:
        raise ConfigError(
            f"Unknown keys in {config_path}: {unknown_keys}. "
            f"Valid keys are: {set(_DEFAULTS.keys())}"
        )

    return data


def _load_from_env() -> dict[str, Any]:
    """Load configuration from environment variables.

    Environment variables use RECONFORGE_ prefix.
    Example: RECONFORGE_THREAD_COUNT=20

    Unknown env vars are silently ignored (fail safe).

    Returns:
        Dictionary of configuration values from environment.
    """
    result: dict[str, Any] = {}
    prefix = "RECONFORGE_"

    for key, expected_type in _TYPE_MAP.items():
        env_key = prefix + key.upper()
        env_value = os.environ.get(env_key)

        if env_value is not None:
            try:
                # Coerce string to expected type
                result[key] = expected_type(env_value)
            except ValueError as e:
                raise ConfigError(
                    f"Invalid value for {env_key}: {env_value!r}. "
                    f"Expected {expected_type.__name__}"
                ) from e

    return result


def load_config(config_path: Path | None = None) -> Config:
    """Load configuration with layered precedence.

    Order (highest to lowest priority):
    1. Environment variables (RECONFORGE_*)
    2. TOML config file (reconforge.toml or specified path)
    3. Hard-coded defaults

    Args:
        config_path: Optional path to config file. If None, looks for
                     'reconforge.toml' in current directory.

    Returns:
        Validated Config object.

    Raises:
        ConfigError: If configuration is invalid.
    """
    # Start with defaults
    values: dict[str, Any] = dict(_DEFAULTS)

    # Layer 2: TOML file overrides
    if config_path is None:
        config_path = Path("reconforge.toml")
    file_values = _load_from_toml(config_path)
    values.update(file_values)

    # Layer 3: Environment variables override
    env_values = _load_from_env()
    values.update(env_values)

    # Create and validate config
    config = Config(**values)
    config.validate()

    return config