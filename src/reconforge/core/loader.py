"""Plugin loader for ReconForge.

Responsibilities:
- Discover plugins in the plugins/ directory
- Dynamically load and register plugin classes
- Provide access to loaded plugins by name

Design:
- Uses importlib and pkgutil for dynamic module discovery
- Registry pattern for plugin management
- Plugins are loaded once and cached
- Failed plugins are logged but don't stop other plugins from loading
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any

from reconforge.core.logging_setup import get_core_logger
from reconforge.core.plugin import BasePlugin

logger = get_core_logger("loader")


class PluginLoadError(Exception):
    """Raised when a plugin cannot be loaded."""


class PluginRegistry:
    """Registry for managing loaded plugins.

    Stores plugin instances by name and provides lookup methods.
    """

    def __init__(self) -> None:
        """Initialize an empty plugin registry."""
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin instance.

        Args:
            plugin: Plugin instance to register.

        Raises:
            ValueError: If a plugin with the same name is already registered.
        """
        if plugin.name in self._plugins:
            raise ValueError(
                f"Plugin '{plugin.name}' is already registered. "
                "Duplicate plugin names are not allowed."
            )
        self._plugins[plugin.name] = plugin
        logger.debug(f"Registered plugin: {plugin.name}")

    def unregister(self, name: str) -> None:
        """Remove a plugin from the registry.

        Args:
            name: Name of the plugin to remove.

        Raises:
            KeyError: If no plugin with that name exists.
        """
        if name not in self._plugins:
            raise KeyError(f"Plugin '{name}' is not registered")
        del self._plugins[name]
        logger.debug(f"Unregistered plugin: {name}")

    def get(self, name: str) -> BasePlugin:
        """Get a plugin by name.

        Args:
            name: Name of the plugin to retrieve.

        Returns:
            Plugin instance.

        Raises:
            KeyError: If no plugin with that name exists.
        """
        if name not in self._plugins:
            raise KeyError(f"Plugin '{name}' is not registered")
        return self._plugins[name]

    def get_all(self) -> list[BasePlugin]:
        """Get all registered plugins.

        Returns:
            List of all plugin instances.
        """
        return list(self._plugins.values())

    def get_names(self) -> list[str]:
        """Get all registered plugin names.

        Returns:
            List of plugin names.
        """
        return list(self._plugins.keys())

    def has(self, name: str) -> bool:
        """Check if a plugin is registered.

        Args:
            name: Name of the plugin to check.

        Returns:
            True if plugin is registered, False otherwise.
        """
        return name in self._plugins

    def __len__(self) -> int:
        """Return the number of registered plugins."""
        return len(self._plugins)

    def __repr__(self) -> str:
        """Return string representation of the registry."""
        return f"<PluginRegistry: {len(self)} plugins ({', '.join(self.get_names())})>"


def discover_plugins(plugin_dir: Path) -> list[str]:
    """Discover plugin modules in a directory.

    Scans the given directory for Python files that could be plugins.
    Does not import them, just returns module names.

    Args:
        plugin_dir: Directory to scan for plugins.

    Returns:
        List of module names found (without .py extension).
    """
    if not plugin_dir.exists():
        logger.warning(f"Plugin directory does not exist: {plugin_dir}")
        return []

    if not plugin_dir.is_dir():
        logger.warning(f"Plugin path is not a directory: {plugin_dir}")
        return []

    module_names = []
    for importer, modname, ispkg in pkgutil.iter_modules([str(plugin_dir)]):
        if not modname.startswith("_"):  # Skip private modules
            module_names.append(modname)
            logger.debug(f"Discovered plugin module: {modname}")

    return module_names


def load_plugin_from_module(
    module_name: str,
    plugin_dir: Path,
) -> BasePlugin | None:
    """Load a plugin class from a module and instantiate it.

    Args:
        module_name: Name of the module to load.
        plugin_dir: Directory containing the plugin modules.

    Returns:
        Plugin instance if successful, None otherwise.
    """
    try:
        # Build the full module path
        # Assumes plugins are in a package like 'reconforge.plugins'
        full_module_name = f"reconforge.plugins.{module_name}"

        # Import the module
        module = importlib.import_module(full_module_name)

        # Find the plugin class in the module
        plugin_class = None
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BasePlugin)
                and obj is not BasePlugin
                and not inspect.isabstract(obj)
            ):
                plugin_class = obj
                break

        if plugin_class is None:
            logger.warning(
                f"No concrete BasePlugin subclass found in {module_name}"
            )
            return None

        # Instantiate the plugin
        plugin = plugin_class()
        logger.info(f"Loaded plugin: {plugin.name} from {module_name}")
        return plugin

    except ImportError as e:
        logger.error(f"Failed to import plugin module {module_name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to load plugin from {module_name}: {e}")
        return None


def load_plugins(plugin_dir: Path | None = None) -> PluginRegistry:
    """Load all plugins from the plugins directory.

    This is the main entry point for plugin loading. It:
    1. Discovers plugin modules in the directory
    2. Loads each module and finds the plugin class
    3. Instantiates and registers each plugin
    4. Returns a registry of all successfully loaded plugins

    Args:
        plugin_dir: Directory containing plugin modules.
                   If None, uses default 'plugins' directory.

    Returns:
        PluginRegistry containing all loaded plugins.
    """
    registry = PluginRegistry()

    if plugin_dir is None:
        # Default to 'plugins' directory relative to this file
        plugin_dir = Path(__file__).parent.parent / "plugins"

    logger.info(f"Discovering plugins in: {plugin_dir}")
    module_names = discover_plugins(plugin_dir)

    if not module_names:
        logger.warning("No plugin modules found")
        return registry

    loaded_count = 0
    failed_count = 0

    for module_name in module_names:
        plugin = load_plugin_from_module(module_name, plugin_dir)
        if plugin is not None:
            try:
                registry.register(plugin)
                loaded_count += 1
            except ValueError as e:
                logger.error(f"Failed to register plugin {module_name}: {e}")
                failed_count += 1
        else:
            failed_count += 1

    logger.info(
        f"Plugin loading complete: {loaded_count} loaded, {failed_count} failed"
    )
    return registry


def register_plugin_manually(
    registry: PluginRegistry,
    plugin_class: type[BasePlugin],
    **kwargs: Any,
) -> BasePlugin:
    """Manually register a plugin class.

    Useful for testing or when plugins are not in the standard directory.

    Args:
        registry: PluginRegistry to register the plugin in.
        plugin_class: Plugin class to instantiate and register.
        **kwargs: Arguments to pass to the plugin constructor.

    Returns:
        The registered plugin instance.
    """
    plugin = plugin_class(**kwargs)
    registry.register(plugin)
    return plugin