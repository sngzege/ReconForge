"""Tests for the Plugin Loader."""

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from reconforge.core.loader import (
    PluginRegistry,
    discover_plugins,
    register_plugin_manually,
)
from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_success_result


# Test plugin implementation
class TestPlugin(BasePlugin):
    """A test plugin for loader tests."""

    @property
    def name(self) -> str:
        return "test_plugin"

    def run(self, target: str, **kwargs: Any) -> Result:
        return create_success_result(
            module=self.name,
            data=["test_result"],
            duration=timedelta(seconds=1),
        )


class AnotherTestPlugin(BasePlugin):
    """Another test plugin for registry tests."""

    @property
    def name(self) -> str:
        return "another_plugin"

    def run(self, target: str, **kwargs: Any) -> Result:
        return create_success_result(
            module=self.name,
            data=["another_result"],
            duration=timedelta(seconds=1),
        )


class TestPluginRegistry:
    """Test PluginRegistry class."""

    def test_empty_registry(self) -> None:
        """New registry should be empty."""
        registry = PluginRegistry()
        assert len(registry) == 0
        assert registry.get_all() == []
        assert registry.get_names() == []

    def test_register_plugin(self) -> None:
        """Should be able to register a plugin."""
        registry = PluginRegistry()
        plugin = TestPlugin()
        registry.register(plugin)

        assert len(registry) == 1
        assert registry.has("test_plugin")
        assert registry.get("test_plugin") is plugin

    def test_register_duplicate_raises_error(self) -> None:
        """Registering duplicate plugin name should raise ValueError."""
        registry = PluginRegistry()
        plugin1 = TestPlugin()
        registry.register(plugin1)

        plugin2 = TestPlugin()
        with pytest.raises(ValueError, match="already registered"):
            registry.register(plugin2)

    def test_unregister_plugin(self) -> None:
        """Should be able to unregister a plugin."""
        registry = PluginRegistry()
        plugin = TestPlugin()
        registry.register(plugin)

        registry.unregister("test_plugin")
        assert len(registry) == 0
        assert not registry.has("test_plugin")

    def test_unregister_nonexistent_raises_error(self) -> None:
        """Unregistering non-existent plugin should raise KeyError."""
        registry = PluginRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.unregister("nonexistent")

    def test_get_nonexistent_raises_error(self) -> None:
        """Getting non-existent plugin should raise KeyError."""
        registry = PluginRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.get("nonexistent")

    def test_get_all(self) -> None:
        """get_all should return all registered plugins."""
        registry = PluginRegistry()
        plugin1 = TestPlugin()
        plugin2 = AnotherTestPlugin()
        registry.register(plugin1)
        registry.register(plugin2)

        all_plugins = registry.get_all()
        assert len(all_plugins) == 2
        assert plugin1 in all_plugins
        assert plugin2 in all_plugins

    def test_get_names(self) -> None:
        """get_names should return all plugin names."""
        registry = PluginRegistry()
        plugin1 = TestPlugin()
        plugin2 = AnotherTestPlugin()
        registry.register(plugin1)
        registry.register(plugin2)

        names = registry.get_names()
        assert len(names) == 2
        assert "test_plugin" in names
        assert "another_plugin" in names

    def test_has(self) -> None:
        """has should return True for registered plugins, False otherwise."""
        registry = PluginRegistry()
        plugin = TestPlugin()
        registry.register(plugin)

        assert registry.has("test_plugin") is True
        assert registry.has("nonexistent") is False

    def test_repr(self) -> None:
        """Registry should have a useful repr."""
        registry = PluginRegistry()
        plugin = TestPlugin()
        registry.register(plugin)

        assert "1 plugins" in repr(registry)
        assert "test_plugin" in repr(registry)


class TestDiscoverPlugins:
    """Test plugin discovery."""

    def test_discover_nonexistent_directory(self, tmp_path: Path) -> None:
        """Discovering non-existent directory should return empty list."""
        nonexistent = tmp_path / "nonexistent"
        result = discover_plugins(nonexistent)
        assert result == []

    def test_discover_empty_directory(self, tmp_path: Path) -> None:
        """Discovering empty directory should return empty list."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = discover_plugins(empty_dir)
        assert result == []

    def test_discover_with_python_files(self, tmp_path: Path) -> None:
        """Discovering directory with Python files should return module names."""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        # Create some Python files
        (plugin_dir / "plugin_a.py").write_text("# Plugin A")
        (plugin_dir / "plugin_b.py").write_text("# Plugin B")
        (plugin_dir / "_private.py").write_text("# Private")

        result = discover_plugins(plugin_dir)

        assert "plugin_a" in result
        assert "plugin_b" in result
        assert "_private" not in result  # Private modules should be skipped

    def test_discover_not_a_directory(self, tmp_path: Path) -> None:
        """Discovering a file (not directory) should return empty list."""
        file_path = tmp_path / "not_a_dir.py"
        file_path.write_text("# Not a directory")
        result = discover_plugins(file_path)
        assert result == []


class TestRegisterPluginManually:
    """Test manual plugin registration."""

    def test_register_manually(self) -> None:
        """Manual registration should instantiate and register plugin."""
        registry = PluginRegistry()
        plugin = register_plugin_manually(registry, TestPlugin)

        assert registry.has("test_plugin")
        assert registry.get("test_plugin") is plugin

    def test_register_manually_with_kwargs(self) -> None:
        """Manual registration should pass kwargs to constructor."""

        class PluginWithArgs(BasePlugin):
            def __init__(self, custom_value: str) -> None:
                self.custom_value = custom_value

            @property
            def name(self) -> str:
                return "custom_plugin"

            def run(self, target: str, **kwargs: Any) -> Result:
                return create_success_result(
                    module=self.name, data=[], duration=timedelta(0)
                )

        registry = PluginRegistry()
        plugin = register_plugin_manually(
            registry, PluginWithArgs, custom_value="test"
        )

        assert plugin.custom_value == "test"  # type: ignore[attr-defined]
        assert registry.has("custom_plugin")