"""Configuration for integration tests.

Integration tests require real security tools installed on the system.
They are marked with @pytest.mark.integration and skipped if tools are missing.
"""

import shutil

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip integration tests if required tools are not installed."""
    for item in items:
        if "integration" in item.keywords:
            # Check for required tools based on test module
            if "test_real_tools" in str(item.fspath):
                required_tools = ["subfinder", "httpx", "assetfinder"]
                missing = [t for t in required_tools if shutil.which(t) is None]
                if missing:
                    skip_reason = f"Missing tools: {', '.join(missing)}"
                    item.add_marker(pytest.mark.skip(reason=skip_reason))