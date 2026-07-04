"""Tests for the Result data model."""

from datetime import timedelta

import pytest

from reconforge.core.result import (
    Result,
    ResultStatus,
    create_failure_result,
    create_partial_result,
    create_success_result,
)


class TestResultStatus:
    """Test ResultStatus enum."""

    def test_status_values(self) -> None:
        """Enum should have three status values."""
        assert ResultStatus.SUCCESS.value == "success"
        assert ResultStatus.FAILURE.value == "failure"
        assert ResultStatus.PARTIAL.value == "partial"


class TestResult:
    """Test Result dataclass."""

    def test_create_result(self) -> None:
        """Result should be creatable with required fields."""
        result = Result(
            module="test_plugin",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=5),
        )
        assert result.module == "test_plugin"
        assert result.status == ResultStatus.SUCCESS
        assert result.duration == timedelta(seconds=5)
        assert result.data is None
        assert result.errors == []
        assert result.metadata == {}

    def test_result_with_data(self) -> None:
        """Result should store data correctly."""
        data = ["sub1.example.com", "sub2.example.com"]
        result = Result(
            module="subfinder",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=3),
            data=data,
        )
        assert result.data == data
        assert result.data_count == 2

    def test_result_with_errors(self) -> None:
        """Result should store errors correctly."""
        result = Result(
            module="test_plugin",
            status=ResultStatus.FAILURE,
            duration=timedelta(seconds=1),
            errors=["Error 1", "Error 2"],
        )
        assert result.errors == ["Error 1", "Error 2"]
        assert result.has_errors is True


class TestResultProperties:
    """Test Result property methods."""

    def test_is_success(self) -> None:
        """is_success should return True for SUCCESS status."""
        result = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
        )
        assert result.is_success is True
        assert result.is_failure is False
        assert result.is_partial is False

    def test_is_failure(self) -> None:
        """is_failure should return True for FAILURE status."""
        result = Result(
            module="test",
            status=ResultStatus.FAILURE,
            duration=timedelta(seconds=1),
        )
        assert result.is_failure is True
        assert result.is_success is False

    def test_is_partial(self) -> None:
        """is_partial should return True for PARTIAL status."""
        result = Result(
            module="test",
            status=ResultStatus.PARTIAL,
            duration=timedelta(seconds=1),
        )
        assert result.is_partial is True

    def test_has_errors(self) -> None:
        """has_errors should return True when errors exist."""
        result = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
        )
        assert result.has_errors is False

        result.add_error("Something went wrong")
        assert result.has_errors is True

    def test_data_count_none(self) -> None:
        """data_count should return 0 when data is None."""
        result = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
        )
        assert result.data_count == 0

    def test_data_count_list(self) -> None:
        """data_count should return list length."""
        result = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
            data=["a", "b", "c"],
        )
        assert result.data_count == 3

    def test_data_count_single_value(self) -> None:
        """data_count should return 1 for non-collection data."""
        result = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
            data="single_value",
        )
        assert result.data_count == 1


class TestResultMethods:
    """Test Result instance methods."""

    def test_add_error(self) -> None:
        """add_error should append to errors list."""
        result = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
        )
        result.add_error("Error 1")
        result.add_error("Error 2")
        assert result.errors == ["Error 1", "Error 2"]

    def test_merge_data(self) -> None:
        """merge_data should combine list data from two results."""
        result1 = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
            data=["a", "b"],
        )
        result2 = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
            data=["c", "d"],
        )
        result1.merge_data(result2)
        assert result1.data == ["a", "b", "c", "d"]

    def test_merge_data_type_error(self) -> None:
        """merge_data should raise TypeError for non-list data."""
        result1 = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
            data="not_a_list",
        )
        result2 = Result(
            module="test",
            status=ResultStatus.SUCCESS,
            duration=timedelta(seconds=1),
            data=["a"],
        )
        with pytest.raises(TypeError, match="Cannot merge data"):
            result1.merge_data(result2)


class TestFactoryFunctions:
    """Test result factory functions."""

    def test_create_success_result(self) -> None:
        """create_success_result should create SUCCESS result."""
        result = create_success_result(
            module="subfinder",
            data=["sub1.com"],
            duration=timedelta(seconds=5),
        )
        assert result.status == ResultStatus.SUCCESS
        assert result.module == "subfinder"
        assert result.data == ["sub1.com"]

    def test_create_failure_result(self) -> None:
        """create_failure_result should create FAILURE result."""
        result = create_failure_result(
            module="subfinder",
            error="Connection timeout",
            duration=timedelta(seconds=30),
        )
        assert result.status == ResultStatus.FAILURE
        assert result.errors == ["Connection timeout"]

    def test_create_partial_result(self) -> None:
        """create_partial_result should create PARTIAL result."""
        result = create_partial_result(
            module="subfinder",
            data=["sub1.com"],
            error="Partial timeout",
            duration=timedelta(seconds=15),
        )
        assert result.status == ResultStatus.PARTIAL
        assert result.data == ["sub1.com"]
        assert result.errors == ["Partial timeout"]