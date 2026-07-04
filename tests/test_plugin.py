"""Tests for the Plugin interface."""

from datetime import timedelta
from typing import Any

import pytest

from reconforge.core.plugin import (
    BasePlugin,
    PluginError,
    execute_plugin_safely,
    validate_plugin,
)
from reconforge.core.result import Result, ResultStatus, create_success_result


# Concrete plugin implementation for testing
class DummyPlugin(BasePlugin):
    """A dummy plugin for testing purposes."""

    @property
    def name(self) -> str:
        return "dummy"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "A dummy plugin for testing"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name,
            data=[f"result_for_{target}"],
            duration=timedelta(seconds=1),
        )


class FailingPlugin(BasePlugin):
    """A plugin that always fails."""

    @property
    def name(self) -> str:
        return "failing"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        raise RuntimeError("Plugin execution failed")


class PluginWithSetupTeardown(BasePlugin):
    """A plugin that tracks setup and teardown calls."""

    def __init__(self) -> None:
        self.setup_called = False
        self.teardown_called = False

    @property
    def name(self) -> str:
        return "setup_teardown"

    def setup(self, **kwargs: Any) -> None:
        self.setup_called = True

    def teardown(self) -> None:
        self.teardown_called = True

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name,
            data=["done"],
            duration=timedelta(seconds=1),
        )


class PluginWithDependencies(BasePlugin):
    """A plugin that declares dependencies."""

    @property
    def name(self) -> str:
        return "dependent"

    @property
    def dependencies(self) -> list[str]:
        return ["dummy", "another"]

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name,
            data=["dependent_result"],
            duration=timedelta(seconds=1),
        )


class TestBasePlugin:
    """Test BasePlugin abstract class."""

    def test_cannot_instantiate_abstract_class(self) -> None:
        """BasePlugin cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BasePlugin()  # type: ignore[abstract]

    def test_concrete_plugin_instantiation(self) -> None:
        """Concrete plugin can be instantiated."""
        plugin = DummyPlugin()
        assert plugin.name == "dummy"
        assert plugin.version == "1.0.0"
        assert plugin.description == "A dummy plugin for testing"

    def test_plugin_run_returns_result(self) -> None:
        """Plugin run() should return a Result."""
        plugin = DummyPlugin()
        result = plugin.run("example.com", {})
        assert isinstance(result, Result)
        assert result.module == "dummy"
        assert result.data == ["result_for_example.com"]

    def test_plugin_repr(self) -> None:
        """Plugin should have a useful repr."""
        plugin = DummyPlugin()
        assert repr(plugin) == "<Plugin: dummy v1.0.0>"


class TestPluginProperties:
    """Test plugin property defaults and overrides."""

    def test_default_version(self) -> None:
        """Plugin should have default version if not overridden."""

        class MinimalPlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "minimal"

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                return create_success_result(
                    module=self.name, data=[], duration=timedelta(0)
                )

        plugin = MinimalPlugin()
        assert plugin.version == "0.1.0"

    def test_default_description(self) -> None:
        """Plugin should have default description if not overridden."""

        class MinimalPlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "minimal"

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                return create_success_result(
                    module=self.name, data=[], duration=timedelta(0)
                )

        plugin = MinimalPlugin()
        assert plugin.description == "minimal plugin"

    def test_default_dependencies(self) -> None:
        """Plugin should have empty dependencies by default."""
        plugin = DummyPlugin()
        assert plugin.dependencies == []

    def test_custom_dependencies(self) -> None:
        """Plugin can declare custom dependencies."""
        plugin = PluginWithDependencies()
        assert plugin.dependencies == ["dummy", "another"]


class TestPluginSetupTeardown:
    """Test plugin setup and teardown lifecycle."""

    def test_setup_called(self) -> None:
        """setup() should be callable."""
        plugin = PluginWithSetupTeardown()
        assert plugin.setup_called is False
        plugin.setup()
        assert plugin.setup_called is True

    def test_teardown_called(self) -> None:
        """teardown() should be callable."""
        plugin = PluginWithSetupTeardown()
        assert plugin.teardown_called is False
        plugin.teardown()
        assert plugin.teardown_called is True


class TestValidatePlugin:
    """Test plugin validation."""

    def test_valid_plugin(self) -> None:
        """Valid plugin should pass validation."""
        plugin = DummyPlugin()
        assert validate_plugin(plugin) is True

    def test_empty_name_raises_error(self) -> None:
        """Plugin with empty name should fail validation."""

        class EmptyNamePlugin(BasePlugin):
            @property
            def name(self) -> str:
                return ""

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                return create_success_result(
                    module=self.name, data=[], duration=timedelta(0)
                )

        plugin = EmptyNamePlugin()
        with pytest.raises(PluginError, match="name cannot be empty"):
            validate_plugin(plugin)

    def test_invalid_name_characters(self) -> None:
        """Plugin with invalid name characters should fail validation."""

        class InvalidNamePlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "invalid name with spaces"

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                return create_success_result(
                    module=self.name, data=[], duration=timedelta(0)
                )

        plugin = InvalidNamePlugin()
        with pytest.raises(PluginError, match="invalid characters"):
            validate_plugin(plugin)

    def test_valid_name_with_underscore_and_hyphen(self) -> None:
        """Plugin name with underscore and hyphen should be valid."""

        class ValidNamePlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "my_plugin-name"

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                return create_success_result(
                    module=self.name, data=[], duration=timedelta(0)
                )

        plugin = ValidNamePlugin()
        assert validate_plugin(plugin) is True


class TestExecutePluginSafely:
    """Test safe plugin execution wrapper."""

    def test_successful_execution(self) -> None:
        """Successful plugin should return SUCCESS result."""
        plugin = DummyPlugin()
        result = execute_plugin_safely(plugin, "example.com")

        assert result.status == ResultStatus.SUCCESS
        assert result.module == "dummy"
        assert result.data == ["result_for_example.com"]

    def test_failed_execution_returns_failure_result(self) -> None:
        """Failed plugin should return FAILURE result, not raise."""
        plugin = FailingPlugin()
        result = execute_plugin_safely(plugin, "example.com")

        assert result.status == ResultStatus.FAILURE
        assert result.module == "failing"
        assert "Plugin execution failed" in result.errors[0]

    def test_setup_and_teardown_called(self) -> None:
        """setup() and teardown() should be called during execution."""
        plugin = PluginWithSetupTeardown()
        execute_plugin_safely(plugin, "example.com")

        assert plugin.setup_called is True
        assert plugin.teardown_called is True

    def test_teardown_called_even_on_failure(self) -> None:
        """teardown() should be called even if run() fails."""
        plugin = PluginWithSetupTeardown()

        # Override run to fail
        class FailingSetupTeardownPlugin(PluginWithSetupTeardown):
            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                raise RuntimeError("Failed")

        failing_plugin = FailingSetupTeardownPlugin()
        execute_plugin_safely(failing_plugin, "example.com")

        assert failing_plugin.teardown_called is True

    def test_result_module_name_corrected(self) -> None:
        """Result module name should be corrected to plugin name."""

        class WrongModuleNamePlugin(BasePlugin):
            @property
            def name(self) -> str:
                return "correct_name"

            def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
                return Result(
                    module="wrong_name",
                    status=ResultStatus.SUCCESS,
                    duration=timedelta(seconds=1),
                    data=["data"],
                )

        plugin = WrongModuleNamePlugin()
        result = execute_plugin_safely(plugin, "example.com")

        assert result.module == "correct_name"