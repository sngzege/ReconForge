"""Tests for the Pipeline orchestration."""

from datetime import timedelta

import pytest

from reconforge.core.pipeline import Pipeline, PipelineError, PipelineResult
from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, ResultStatus, create_success_result


# Test plugins
class PluginA(BasePlugin):
    """Test plugin A."""

    @property
    def name(self) -> str:
        return "plugin_a"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name,
            data=[f"a_{target}"],
            duration=timedelta(seconds=1),
        )


class PluginB(BasePlugin):
    """Test plugin B."""

    @property
    def name(self) -> str:
        return "plugin_b"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name,
            data=[f"b_{target}"],
            duration=timedelta(seconds=1),
        )


class PluginC(BasePlugin):
    """Test plugin C (depends on A and B)."""

    @property
    def name(self) -> str:
        return "plugin_c"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name,
            data=[f"c_{target}"],
            duration=timedelta(seconds=1),
        )


class FailingPlugin(BasePlugin):
    """A plugin that always fails."""

    @property
    def name(self) -> str:
        return "failing"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        raise RuntimeError("Plugin failed")


class TestPipelineResult:
    """Test PipelineResult class."""

    def test_empty_result(self) -> None:
        """New pipeline result should be empty."""
        result = PipelineResult()
        assert len(result.results) == 0
        assert len(result.errors) == 0
        assert result.success_count == 0
        assert result.failure_count == 0
        assert result.partial_count == 0

    def test_add_result(self) -> None:
        """Should be able to add results."""
        pipeline_result = PipelineResult()
        result = create_success_result(
            module="test", data=["data"], duration=timedelta(seconds=1)
        )
        pipeline_result.add_result(result)

        assert len(pipeline_result.results) == 1
        assert pipeline_result.success_count == 1

    def test_add_result_with_errors(self) -> None:
        """Adding result with errors should add to errors list."""
        pipeline_result = PipelineResult()
        result = Result(
            module="test",
            status=ResultStatus.FAILURE,
            duration=timedelta(seconds=1),
            errors=["Error 1", "Error 2"],
        )
        pipeline_result.add_result(result)

        assert len(pipeline_result.errors) == 2
        assert pipeline_result.failure_count == 1

    def test_get_results_by_module(self) -> None:
        """Should filter results by module name."""
        pipeline_result = PipelineResult()
        result1 = create_success_result(
            module="plugin_a", data=["a"], duration=timedelta(seconds=1)
        )
        result2 = create_success_result(
            module="plugin_b", data=["b"], duration=timedelta(seconds=1)
        )
        pipeline_result.add_result(result1)
        pipeline_result.add_result(result2)

        filtered = pipeline_result.get_results_by_module("plugin_a")
        assert len(filtered) == 1
        assert filtered[0].module == "plugin_a"

    def test_get_all_data(self) -> None:
        """Should flatten all data from results."""
        pipeline_result = PipelineResult()
        result1 = create_success_result(
            module="a", data=["x", "y"], duration=timedelta(seconds=1)
        )
        result2 = create_success_result(
            module="b", data=["z"], duration=timedelta(seconds=1)
        )
        pipeline_result.add_result(result1)
        pipeline_result.add_result(result2)

        all_data = pipeline_result.get_all_data()
        assert all_data == ["x", "y", "z"]

    def test_repr(self) -> None:
        """Should have useful repr."""
        pipeline_result = PipelineResult()
        result = create_success_result(
            module="test", data=[], duration=timedelta(seconds=1)
        )
        pipeline_result.add_result(result)

        assert "1 results" in repr(pipeline_result)
        assert "1 success" in repr(pipeline_result)


class TestPipeline:
    """Test Pipeline class."""

    def test_empty_pipeline(self) -> None:
        """New pipeline should have no plugins."""
        pipeline = Pipeline()
        assert pipeline.get_plugin_names() == []

    def test_add_plugin(self) -> None:
        """Should be able to add plugins."""
        pipeline = Pipeline()
        plugin = PluginA()
        pipeline.add_plugin(plugin)

        assert "plugin_a" in pipeline.get_plugin_names()

    def test_add_duplicate_plugin_raises_error(self) -> None:
        """Adding duplicate plugin should raise ValueError."""
        pipeline = Pipeline()
        plugin = PluginA()
        pipeline.add_plugin(plugin)

        with pytest.raises(ValueError, match="already in pipeline"):
            pipeline.add_plugin(plugin)

    def test_add_plugin_with_dependency(self) -> None:
        """Should be able to add plugin with dependencies."""
        pipeline = Pipeline()
        plugin_a = PluginA()
        plugin_c = PluginC()

        pipeline.add_plugin(plugin_a)
        pipeline.add_plugin(plugin_c, depends_on=["plugin_a"])

        assert pipeline.get_dependencies("plugin_c") == ["plugin_a"]

    def test_add_plugin_with_missing_dependency_raises_error(self) -> None:
        """Adding plugin with missing dependency should raise ValueError."""
        pipeline = Pipeline()
        plugin_c = PluginC()

        with pytest.raises(ValueError, match="not found"):
            pipeline.add_plugin(plugin_c, depends_on=["nonexistent"])

    def test_get_execution_order_no_dependencies(self) -> None:
        """Plugins without dependencies should be in same stage."""
        pipeline = Pipeline()
        pipeline.add_plugin(PluginA())
        pipeline.add_plugin(PluginB())

        stages = pipeline._get_execution_order()
        assert len(stages) == 1
        assert set(stages[0]) == {"plugin_a", "plugin_b"}

    def test_get_execution_order_with_dependencies(self) -> None:
        """Plugins with dependencies should be in later stages."""
        pipeline = Pipeline()
        pipeline.add_plugin(PluginA())
        pipeline.add_plugin(PluginB())
        pipeline.add_plugin(PluginC(), depends_on=["plugin_a", "plugin_b"])

        stages = pipeline._get_execution_order()
        assert len(stages) == 2
        assert set(stages[0]) == {"plugin_a", "plugin_b"}
        assert stages[1] == ["plugin_c"]

    def test_run_empty_pipeline(self) -> None:
        """Running empty pipeline should return empty result."""
        pipeline = Pipeline()
        result = pipeline.run("example.com")

        assert len(result.results) == 0
        assert isinstance(result, PipelineResult)

    def test_run_single_plugin(self) -> None:
        """Running pipeline with single plugin should work."""
        pipeline = Pipeline()
        pipeline.add_plugin(PluginA())

        result = pipeline.run("example.com")

        assert len(result.results) == 1
        assert result.success_count == 1
        assert result.results[0].data == ["a_example.com"]

    def test_run_with_dependencies(self) -> None:
        """Pipeline should respect dependency order."""
        pipeline = Pipeline()
        pipeline.add_plugin(PluginA())
        pipeline.add_plugin(PluginB())
        pipeline.add_plugin(PluginC(), depends_on=["plugin_a"])

        result = pipeline.run("example.com")

        assert len(result.results) == 3
        assert result.success_count == 3

    def test_run_plugin_failure_doesnt_stop_pipeline(self) -> None:
        """One plugin failure should not stop the pipeline."""
        pipeline = Pipeline()
        pipeline.add_plugin(PluginA())
        pipeline.add_plugin(FailingPlugin())

        result = pipeline.run("example.com")

        assert len(result.results) == 2
        assert result.success_count == 1
        assert result.failure_count == 1

    def test_get_dependencies(self) -> None:
        """Should return dependencies for a plugin."""
        pipeline = Pipeline()
        pipeline.add_plugin(PluginA())
        pipeline.add_plugin(PluginC(), depends_on=["plugin_a"])

        deps = pipeline.get_dependencies("plugin_c")
        assert deps == ["plugin_a"]

    def test_get_dependencies_nonexistent_raises_error(self) -> None:
        """Getting dependencies for nonexistent plugin should raise KeyError."""
        pipeline = Pipeline()
        with pytest.raises(KeyError, match="not in pipeline"):
            pipeline.get_dependencies("nonexistent")

    def test_repr(self) -> None:
        """Pipeline should have useful repr."""
        pipeline = Pipeline(max_workers=5)
        pipeline.add_plugin(PluginA())

        assert "1 plugins" in repr(pipeline)
        assert "max_workers=5" in repr(pipeline)



# --- allow_partial test fixtures and tests ---


class PaSourceA(BasePlugin):
    """Upstream source A that succeeds."""

    @property
    def name(self) -> str:
        return "pa_a"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name, data=["a_data"], duration=timedelta(seconds=1)
        )


class PaSourceB(BasePlugin):
    """Upstream source B that succeeds."""

    @property
    def name(self) -> str:
        return "pa_b"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name, data=["b_data"], duration=timedelta(seconds=1)
        )


class PaFailA(BasePlugin):
    """Upstream source A that always fails."""

    @property
    def name(self) -> str:
        return "pa_a"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        raise RuntimeError("pa_a failed")


class PaFailB(BasePlugin):
    """Upstream source B that always fails."""

    @property
    def name(self) -> str:
        return "pa_b"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        raise RuntimeError("pa_b failed")


class PaMerger(BasePlugin):
    """Partial-tolerant merger: runs unless ALL upstreams fail."""

    requires = ["pa_a", "pa_b"]
    allow_partial = True

    @property
    def name(self) -> str:
        return "pa_merger"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        merged: list[str] = []
        for dep in self.requires:
            r = upstream_results.get(dep)
            if r is not None and r.is_success and isinstance(r.data, list):
                merged.extend(r.data)
        return create_success_result(
            module=self.name, data=merged, duration=timedelta(seconds=1)
        )


class PaStrictMerger(BasePlugin):
    """Strict merger: skips if ANY upstream fails (default behavior)."""

    requires = ["pa_a", "pa_b"]
    allow_partial = False

    @property
    def name(self) -> str:
        return "pa_strict_merger"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        return create_success_result(
            module=self.name, data=["strict"], duration=timedelta(seconds=1)
        )


class TestAllowPartial:
    """Test allow_partial pipeline skip behavior."""

    def test_runs_when_some_upstream_failed(self) -> None:
        """allow_partial=True should run when only some upstreams failed."""
        pipeline = Pipeline()
        pipeline.add_plugin(PaSourceA())
        pipeline.add_plugin(PaFailB())
        pipeline.add_plugin(PaMerger(), depends_on=["pa_a", "pa_b"])

        result = pipeline.run("example.com")
        merger = result.get_results_by_module("pa_merger")[0]
        assert merger.is_success
        assert "a_data" in merger.data

    def test_skipped_when_all_upstream_failed(self) -> None:
        """allow_partial=True should still skip when ALL upstreams failed."""
        pipeline = Pipeline()
        pipeline.add_plugin(PaFailA())
        pipeline.add_plugin(PaFailB())
        pipeline.add_plugin(PaMerger(), depends_on=["pa_a", "pa_b"])

        result = pipeline.run("example.com")
        merger = result.get_results_by_module("pa_merger")[0]
        assert merger.is_failure
        assert "Skipped" in merger.errors[0]

    def test_strict_skipped_when_any_upstream_failed(self) -> None:
        """allow_partial=False (default) should skip on any upstream failure."""
        pipeline = Pipeline()
        pipeline.add_plugin(PaSourceA())
        pipeline.add_plugin(PaFailB())
        pipeline.add_plugin(PaStrictMerger(), depends_on=["pa_a", "pa_b"])

        result = pipeline.run("example.com")
        merger = result.get_results_by_module("pa_strict_merger")[0]
        assert merger.is_failure
        assert "Skipped" in merger.errors[0]
