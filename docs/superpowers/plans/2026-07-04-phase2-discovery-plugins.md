# Phase 2 — Discovery Plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 10 discovery plugins that orchestrate external security tools, extending the Core to support plugin-to-plugin data flow via `upstream_results`.

**Architecture:** Plugins declare their upstream dependencies via `requires: ClassVar[list[str]]`. Pipeline collects results from declared dependencies and passes them as `upstream_results: dict[str, Result]` to each plugin's `run()` method. External tools are invoked via `subprocess.run` with mocked unit tests for Windows compatibility.

**Tech Stack:** Python 3.11+, stdlib only (socket, ipaddress, subprocess, urllib), pytest with mock

## Global Constraints

- Python version: `>= 3.11`
- Core dependencies: zero (`dependencies = []` in pyproject.toml)
- Duration measurement: `time.perf_counter()` (monotonic)
- IP detection: `ipaddress.ip_address()` (stdlib, IPv4+IPv6)
- Subprocess calls: `subprocess.run` with explicit `timeout`
- Test markers: `@pytest.mark.integration` for Kali-only tests
- Missing upstream dependency: failure result, never silently skipped
- `run()` signature: `(target: str, upstream_results: dict[str, Result]) -> Result` (no `**kwargs`)

---

## File Structure

### New Files to Create

| File | Responsibility |
|------|----------------|
| `src/reconforge/plugins/__init__.py` | Plugin package marker |
| `src/reconforge/plugins/normalize_url.py` | URL/domain normalization |
| `src/reconforge/plugins/dns_resolver.py` | DNS resolution via stdlib socket |
| `src/reconforge/plugins/subfinder.py` | Subdomain discovery via subfinder |
| `src/reconforge/plugins/assetfinder.py` | Subdomain discovery via assetfinder |
| `src/reconforge/plugins/crtsh.py` | Subdomain discovery via crt.sh HTTP API |
| `src/reconforge/plugins/httpx_alive.py` | HTTP alive check via httpx |
| `src/reconforge/plugins/http_fingerprint.py` | HTTP response fingerprinting |
| `src/reconforge/plugins/merge_engine.py` | Deduplicate and merge subdomain results |
| `src/reconforge/plugins/whois_lookup.py` | WHOIS information retrieval |
| `tests/plugins/__init__.py` | Test package marker |
| `tests/plugins/test_normalize_url.py` | Tests for normalize_url plugin |
| `tests/plugins/test_dns_resolver.py` | Tests for dns_resolver plugin |
| `tests/plugins/test_subfinder.py` | Tests for subfinder plugin |
| `tests/plugins/test_assetfinder.py` | Tests for assetfinder plugin |
| `tests/plugins/test_crtsh.py` | Tests for crtsh plugin |
| `tests/plugins/test_httpx_alive.py` | Tests for httpx_alive plugin |
| `tests/plugins/test_http_fingerprint.py` | Tests for http_fingerprint plugin |
| `tests/plugins/test_merge_engine.py` | Tests for merge_engine plugin |
| `tests/plugins/test_whois_lookup.py` | Tests for whois_lookup plugin |
| `tests/integration/__init__.py` | Integration test package marker |
| `tests/integration/conftest.py` | Integration test fixtures and markers |
| `tests/integration/test_real_tools.py` | Kali-only integration tests |

### Files to Modify

| File | Changes |
|------|---------|
| `src/reconforge/core/plugin.py` | Add `requires: ClassVar[list[str]]`, update `run()` signature |
| `src/reconforge/core/pipeline.py` | Update `_execute_plugin()` to pass `upstream_results` |
| `tests/test_plugin.py` | Update test plugins to new `run()` signature |
| `tests/test_pipeline.py` | Update test plugins to new `run()` signature |
| `pyproject.toml` | Add pytest integration marker |

---

## Task 1: Core Changes — plugin.py

**Files:**
- Modify: `src/reconforge/core/plugin.py`
- Modify: `tests/test_plugin.py`

**Interfaces:**
- Produces: `BasePlugin.requires: ClassVar[list[str]]` (default: `[]`)
- Produces: `BasePlugin.run(target: str, upstream_results: dict[str, Result]) -> Result`

- [ ] **Step 1: Update plugin.py — add ClassVar import and requires class variable**

In `src/reconforge/core/plugin.py`, update the import line:

```python
from typing import Any, ClassVar
```

Add `requires` class variable to `BasePlugin` class (after the `dependencies` property):

```python
    requires: ClassVar[list[str]] = []
    """List of plugin names whose results this plugin needs.

    Override in subclass to declare upstream dependencies.
    Pipeline will pass results from these plugins as upstream_results.

    Example:
        requires: ClassVar[list[str]] = ["normalize_url", "dns_resolver"]
    """
```

- [ ] **Step 2: Update plugin.py — change run() abstract method signature**

Replace the existing `run()` abstract method:

```python
    @abstractmethod
    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Execute the plugin's main logic.

        This is the core method that every plugin must implement.
        It should:
        1. Perform the plugin's specific task
        2. Measure execution duration
        3. Return a Result object with the findings

        Args:
            target: The target to scan/process (domain, URL, IP, etc.)
            upstream_results: Results from plugins declared in `requires`.
                             Always a dict (empty if no dependencies).
                             Keys are plugin names, values are Result objects.

        Returns:
            Result object containing the plugin's findings.

        Raises:
            Exception: Any exception should be caught by the caller
                      (Pipeline/Scheduler) and converted to a FAILURE Result.
        """
```

- [ ] **Step 3: Update plugin.py — update execute_plugin_safely**

Replace the `execute_plugin_safely` function:

```python
def execute_plugin_safely(
    plugin: BasePlugin,
    target: str,
    upstream_results: dict[str, Result] | None = None,
) -> Result:
    """Execute a plugin with error handling and timing.

    This is a helper function that:
    1. Validates the plugin
    2. Calls setup()
    3. Calls run() with timing
    4. Calls teardown() (even if run() fails)
    5. Returns a Result (never raises)

    Args:
        plugin: Plugin instance to execute.
        target: Target to process.
        upstream_results: Results from upstream plugins (default: empty dict).

    Returns:
        Result object with plugin findings or error information.
    """
    from datetime import datetime

    from reconforge.core.logging_setup import get_plugin_logger
    from reconforge.core.result import ResultStatus, create_failure_result

    logger = get_plugin_logger(plugin.name)
    start_time = datetime.now()

    if upstream_results is None:
        upstream_results = {}

    try:
        # Validate plugin
        validate_plugin(plugin)

        # Setup phase
        logger.debug(f"Setting up {plugin.name}")
        plugin.setup()

        # Execution phase
        logger.info(f"Running {plugin.name} on {target}")
        result = plugin.run(target, upstream_results)

        # Ensure result has correct module name
        if result.module != plugin.name:
            result = Result(
                module=plugin.name,
                status=result.status,
                duration=result.duration,
                data=result.data,
                errors=result.errors,
                metadata=result.metadata,
            )

        return result

    except Exception as e:
        # Catch all exceptions and convert to failure result
        duration = datetime.now() - start_time
        logger.error(f"Plugin {plugin.name} failed: {e}")

        return create_failure_result(
            module=plugin.name,
            error=str(e),
            duration=duration if isinstance(duration, timedelta) else timedelta(0),
        )

    finally:
        # Teardown phase (always runs)
        try:
            plugin.teardown()
        except Exception as e:
            logger.warning(f"Plugin {plugin.name} teardown failed: {e}")
```

- [ ] **Step 4: Update tests/test_plugin.py — update all test plugin run() signatures**

Replace the entire `tests/test_plugin.py` file content with updated signatures. All `run(self, target: str, **kwargs: Any)` become `run(self, target: str, upstream_results: dict[str, Result])`. Remove `from typing import Any` import if no longer needed (keep it for `setup(**kwargs)`).

Key changes to each test plugin class:

```python
# DummyPlugin
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    return create_success_result(
        module=self.name,
        data=[f"result_for_{target}"],
        duration=timedelta(seconds=1),
    )

# FailingPlugin
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    raise RuntimeError("Plugin execution failed")

# PluginWithSetupTeardown
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    return create_success_result(
        module=self.name,
        data=["done"],
        duration=timedelta(seconds=1),
    )

# PluginWithDependencies
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    return create_success_result(
        module=self.name,
        data=["dependent_result"],
        duration=timedelta(seconds=1),
    )
```

Also update all inline plugin classes in test methods (MinimalPlugin, EmptyNamePlugin, InvalidNamePlugin, ValidNamePlugin, WrongModuleNamePlugin, FailingSetupTeardownPlugin) to use the new signature.

Update test calls:
- `plugin.run("example.com")` → `plugin.run("example.com", {})`
- `execute_plugin_safely(plugin, "example.com")` stays the same (upstream_results defaults to None → {})

- [ ] **Step 5: Run tests to verify plugin.py changes**

Run: `pytest tests/test_plugin.py -v`
Expected: All 19 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/reconforge/core/plugin.py tests/test_plugin.py
git commit -m "feat(plugin): add requires ClassVar and upstream_results to run() signature"
```

---

## Task 2: Core Changes — pipeline.py

**Files:**
- Modify: `src/reconforge/core/pipeline.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `BasePlugin.requires: ClassVar[list[str]]` (from Task 1)
- Consumes: `BasePlugin.run(target, upstream_results)` (from Task 1)
- Produces: `Pipeline._execute_plugin()` passes `upstream_results` dict

- [ ] **Step 1: Update tests/test_pipeline.py — update all test plugin run() signatures**

Update all test plugin classes in `tests/test_pipeline.py`:

```python
# PluginA
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    return create_success_result(
        module=self.name,
        data=[f"a_{target}"],
        duration=timedelta(seconds=1),
    )

# PluginB
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    return create_success_result(
        module=self.name,
        data=[f"b_{target}"],
        duration=timedelta(seconds=1),
    )

# PluginC
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    return create_success_result(
        module=self.name,
        data=[f"c_{target}"],
        duration=timedelta(seconds=1),
    )

# FailingPlugin
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    raise RuntimeError("Plugin failed")
```

Remove `from typing import Any` import if no longer used.

- [ ] **Step 2: Run tests to verify they still pass (pipeline not yet changed)**

Run: `pytest tests/test_pipeline.py -v`
Expected: All 20 tests PASS (pipeline currently passes `**kwargs` which includes `upstream_results`)

- [ ] **Step 3: Update pipeline.py — modify _execute_plugin to build upstream_results**

Replace the `_execute_plugin` method in `src/reconforge/core/pipeline.py`:

```python
    def _execute_plugin(
        self,
        plugin: BasePlugin,
        target: str,
    ) -> Result:
        """Execute a single plugin with its upstream results.

        Collects results from plugins declared in `plugin.requires`
        and passes them as `upstream_results`. If a required upstream
        result is missing, returns a failure result.

        Args:
            plugin: Plugin to execute.
            target: Target to process.

        Returns:
            Result from plugin execution.
        """
        logger.info(f"Executing plugin: {plugin.name}")

        # Build upstream_results from declared requires
        upstream_results: dict[str, Result] = {}
        for dep_name in plugin.requires:
            if dep_name not in self._results:
                logger.error(
                    f"Plugin {plugin.name} requires '{dep_name}' but it is not available"
                )
                return create_failure_result(
                    module=plugin.name,
                    error=f"Required upstream result '{dep_name}' not available",
                    duration=timedelta(0),
                )
            upstream_results[dep_name] = self._results[dep_name]

        result = execute_plugin_safely(plugin, target, upstream_results=upstream_results)
        self._results[plugin.name] = result
        return result
```

- [ ] **Step 4: Run all tests to verify pipeline changes**

Run: `pytest tests/test_plugin.py tests/test_pipeline.py -v`
Expected: All 39 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/core/pipeline.py tests/test_pipeline.py
git commit -m "feat(pipeline): pass upstream_results to plugins based on requires"
```

---

## Task 3: Test Infrastructure

**Files:**
- Create: `tests/plugins/__init__.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/conftest.py`
- Create: `tests/integration/test_real_tools.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Create test directories and package markers**

Create `tests/plugins/__init__.py`:
```python
"""Plugin unit tests."""
```

Create `tests/integration/__init__.py`:
```python
"""Integration tests (Kali-only, requires real tools)."""
```

- [ ] **Step 2: Create integration test conftest.py**

Create `tests/integration/conftest.py`:
```python
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
```

- [ ] **Step 3: Create placeholder integration test file**

Create `tests/integration/test_real_tools.py`:
```python
"""Integration tests for plugins with real tools.

These tests run only on Kali Linux with tools installed.
Run with: pytest tests/integration/
Skip with: pytest -m "not integration"
"""

import shutil

import pytest


@pytest.mark.integration
@pytest.mark.skipif(
    shutil.which("subfinder") is None,
    reason="subfinder not installed",
)
class TestSubfinderIntegration:
    """Integration tests for subfinder plugin."""

    def test_real_subfinder(self) -> None:
        """Test subfinder with real tool on example.com."""
        from reconforge.plugins.subfinder import SubfinderPlugin

        plugin = SubfinderPlugin()
        result = plugin.run("example.com", {})
        assert result.is_success
        assert len(result.data) > 0


@pytest.mark.integration
@pytest.mark.skipif(
    shutil.which("httpx") is None,
    reason="httpx not installed",
)
class TestHttpxIntegration:
    """Integration tests for httpx_alive plugin."""

    def test_real_httpx(self) -> None:
        """Test httpx with real tool."""
        from reconforge.plugins.httpx_alive import HttpxAlivePlugin

        plugin = HttpxAlivePlugin()
        result = plugin.run("example.com", {})
        assert result.is_success
```

- [ ] **Step 4: Add pytest integration marker to pyproject.toml**

Add to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "integration: marks tests requiring real tools (deselect with '-m \"not integration\"')",
]
```

- [ ] **Step 5: Run all tests to verify infrastructure**

Run: `pytest -m "not integration" -v`
Expected: All existing tests PASS, integration tests deselected

- [ ] **Step 6: Commit**

```bash
git add tests/plugins/ tests/integration/ pyproject.toml
git commit -m "test: add plugin test infrastructure with integration markers"
```

---

## Task 4: Group A — normalize_url Plugin

**Files:**
- Create: `src/reconforge/plugins/__init__.py`
- Create: `src/reconforge/plugins/normalize_url.py`
- Create: `tests/plugins/test_normalize_url.py`

**Interfaces:**
- Consumes: `BasePlugin` (from core)
- Produces: `NormalizeUrlPlugin.run(target, upstream_results) -> Result`
- Output: `data` = normalized domain string, `metadata` = `{"original": str, "is_ip": bool}`

- [ ] **Step 1: Create plugins package marker**

Create `src/reconforge/plugins/__init__.py`:
```python
"""ReconForge plugins for reconnaissance and discovery."""
```

- [ ] **Step 2: Write failing tests for normalize_url**

Create `tests/plugins/test_normalize_url.py`:
```python
"""Tests for the normalize_url plugin."""

from datetime import timedelta

import pytest

from reconforge.core.result import Result
from reconforge.plugins.normalize_url import NormalizeUrlPlugin


class TestNormalizeUrlPlugin:
    """Test NormalizeUrlPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = NormalizeUrlPlugin()
        assert plugin.name == "normalize_url"

    def test_requires_empty(self) -> None:
        """Plugin should have no upstream requirements."""
        assert NormalizeUrlPlugin.requires == []

    def test_simple_domain(self) -> None:
        """Simple domain should pass through unchanged."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("example.com", {})
        assert result.is_success
        assert result.data == "example.com"
        assert result.metadata["is_ip"] is False

    def test_uppercase_domain(self) -> None:
        """Uppercase domain should be lowercased."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("EXAMPLE.COM", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_url_with_protocol(self) -> None:
        """URL with protocol should extract hostname."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("https://example.com/path", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_url_with_port(self) -> None:
        """URL with port should extract hostname."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("http://example.com:8080", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_ipv4_address(self) -> None:
        """IPv4 address should pass through unchanged."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("192.168.1.1", {})
        assert result.is_success
        assert result.data == "192.168.1.1"
        assert result.metadata["is_ip"] is True

    def test_ipv6_address(self) -> None:
        """IPv6 address should pass through unchanged."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("::1", {})
        assert result.is_success
        assert result.data == "::1"
        assert result.metadata["is_ip"] is True

    def test_whitespace_stripped(self) -> None:
        """Leading/trailing whitespace should be stripped."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("  example.com  ", {})
        assert result.is_success
        assert result.data == "example.com"

    def test_empty_input_fails(self) -> None:
        """Empty input should return failure result."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("", {})
        assert result.is_failure

    def test_metadata_preserves_original(self) -> None:
        """Metadata should preserve original input."""
        plugin = NormalizeUrlPlugin()
        result = plugin.run("HTTPS://EXAMPLE.COM/path", {})
        assert result.is_success
        assert result.metadata["original"] == "HTTPS://EXAMPLE.COM/path"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/plugins/test_normalize_url.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'reconforge.plugins.normalize_url'`

- [ ] **Step 4: Implement normalize_url plugin**

Create `src/reconforge/plugins/normalize_url.py`:
```python
"""Normalize URL plugin for ReconForge.

Responsibilities:
- Standardize user input (domain, URL, IP) to canonical form
- Detect whether input is an IP address or domain
- Strip protocol, path, port, and trailing whitespace

Design:
- Pure Python implementation using stdlib (urllib.parse, ipaddress)
- Returns normalized string in Result.data
- Sets metadata["is_ip"] for downstream plugins
"""

from __future__ import annotations

import ipaddress
import time
from datetime import timedelta
from typing import ClassVar
from urllib.parse import urlparse

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class NormalizeUrlPlugin(BasePlugin):
    """Normalize user input to standard domain/IP format.

    Handles various input formats:
    - Plain domain: example.com → example.com
    - URL with protocol: https://example.com/path → example.com
    - URL with port: http://example.com:8080 → example.com
    - IPv4 address: 192.168.1.1 → 192.168.1.1
    - IPv6 address: ::1 → ::1
    - Uppercase: EXAMPLE.COM → example.com
    """

    requires: ClassVar[list[str]] = []

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "normalize_url"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Normalize input to standard domain/IP format"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Normalize the target input.

        Args:
            target: Raw user input (domain, URL, or IP address).
            upstream_results: Empty dict (no upstream dependencies).

        Returns:
            Result with normalized domain/IP in data field.
        """
        start = time.perf_counter()

        try:
            # Strip whitespace
            target = target.strip()

            if not target:
                return create_failure_result(
                    module=self.name,
                    error="Input cannot be empty",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            # Check if it's an IP address
            if self._is_ip(target):
                return create_success_result(
                    module=self.name,
                    data=target,
                    duration=timedelta(seconds=time.perf_counter() - start),
                    metadata={"original": target, "is_ip": True},
                )

            # Extract hostname from URL if protocol present
            normalized = self._extract_hostname(target)

            # Lowercase
            normalized = normalized.lower()

            return create_success_result(
                module=self.name,
                data=normalized,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"original": target, "is_ip": False},
            )

        except Exception as e:
            return create_failure_result(
                module=self.name,
                error=f"Normalization failed: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _is_ip(self, value: str) -> bool:
        """Check if value is a valid IP address (IPv4 or IPv6).

        Args:
            value: String to check.

        Returns:
            True if value is a valid IP address.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _extract_hostname(self, value: str) -> str:
        """Extract hostname from URL or return value as-is.

        Args:
            value: URL string or plain domain.

        Returns:
            Hostname extracted from URL, or original value.
        """
        if "://" in value:
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname
        return value
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/plugins/test_normalize_url.py -v`
Expected: All 11 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/reconforge/plugins/ tests/plugins/test_normalize_url.py
git commit -m "feat(plugin): add normalize_url plugin for input standardization"
```

---

## Task 5: Group A — dns_resolver Plugin

**Files:**
- Create: `src/reconforge/plugins/dns_resolver.py`
- Create: `tests/plugins/test_dns_resolver.py`

**Interfaces:**
- Consumes: `NormalizeUrlPlugin` output (via `upstream_results["normalize_url"]`)
- Produces: `DnsResolverPlugin.run(target, upstream_results) -> Result`
- Output: `data` = list of IP addresses (IPv4 + IPv6)

- [ ] **Step 1: Write failing tests for dns_resolver**

Create `tests/plugins/test_dns_resolver.py`:
```python
"""Tests for the dns_resolver plugin."""

import socket
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import Result, ResultStatus, create_success_result
from reconforge.plugins.dns_resolver import DnsResolverPlugin


def _make_normalize_result(data: str, is_ip: bool = False) -> Result:
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=data,
        duration=timedelta(seconds=0),
        metadata={"original": data, "is_ip": is_ip},
    )


class TestDnsResolverPlugin:
    """Test DnsResolverPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = DnsResolverPlugin()
        assert plugin.name == "dns_resolver"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert DnsResolverPlugin.requires == ["normalize_url"]

    def test_successful_resolution(self) -> None:
        """Should resolve domain to IP addresses."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_getaddrinfo = MagicMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ])

        with patch("socket.getaddrinfo", mock_getaddrinfo):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "93.184.216.34" in result.data

    def test_ip_passthrough(self) -> None:
        """IP address input should return as-is without DNS lookup."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("192.168.1.1", is_ip=True)}

        result = plugin.run("192.168.1.1", upstream)

        assert result.is_success
        assert result.data == ["192.168.1.1"]

    def test_missing_upstream_fails(self) -> None:
        """Missing normalize_url result should return failure."""
        plugin = DnsResolverPlugin()
        result = plugin.run("example.com", {})
        assert result.is_failure
        assert "normalize_url" in result.errors[0]

    def test_upstream_failure_propagates(self) -> None:
        """Failed normalize_url should cause dns_resolver to fail."""
        plugin = DnsResolverPlugin()
        failed_result = Result(
            module="normalize_url",
            status=ResultStatus.FAILURE,
            duration=timedelta(0),
            errors=["normalization failed"],
        )
        upstream = {"normalize_url": failed_result}

        result = plugin.run("example.com", upstream)
        assert result.is_failure

    def test_dns_failure_returns_failure(self) -> None:
        """DNS resolution failure should return failure result."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("nonexistent.invalid")}

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS failed")):
            result = plugin.run("nonexistent.invalid", upstream)

        assert result.is_failure

    def test_multiple_ip_addresses(self) -> None:
        """Should return all resolved IP addresses."""
        plugin = DnsResolverPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_getaddrinfo = MagicMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1::1", 0)),
        ])

        with patch("socket.getaddrinfo", mock_getaddrinfo):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_dns_resolver.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement dns_resolver plugin**

Create `src/reconforge/plugins/dns_resolver.py`:
```python
"""DNS Resolver plugin for ReconForge.

Responsibilities:
- Resolve domain names to IP addresses
- Support both IPv4 and IPv6 resolution
- Pass through IP addresses without DNS lookup

Design:
- Uses stdlib socket.getaddrinfo() for resolution
- Reads is_ip from normalize_url metadata to skip DNS for IPs
- Returns list of IP addresses in Result.data
"""

from __future__ import annotations

import socket
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class DnsResolverPlugin(BasePlugin):
    """Resolve domain to IP addresses using stdlib socket.

    Uses socket.getaddrinfo() for DNS resolution, supporting
    both IPv4 and IPv6 addresses.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "dns_resolver"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Resolve domain to IP addresses"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Resolve domain to IP addresses.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of IP addresses in data field.
        """
        start = time.perf_counter()

        # Get normalized result from upstream
        normalize_result = upstream_results["normalize_url"]

        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        is_ip = normalize_result.metadata.get("is_ip", False)

        # If input was already an IP, return as-is
        if is_ip:
            return create_success_result(
                module=self.name,
                data=[domain],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "source": "input_was_ip"},
            )

        # Resolve domain
        try:
            ips = self._resolve(domain)
            if not ips:
                return create_failure_result(
                    module=self.name,
                    error=f"No DNS records found for {domain}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            return create_success_result(
                module=self.name,
                data=sorted(ips),
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(ips)},
            )

        except socket.gaierror as e:
            return create_failure_result(
                module=self.name,
                error=f"DNS resolution failed for {domain}: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _resolve(self, domain: str) -> list[str]:
        """Resolve domain to list of IP addresses.

        Args:
            domain: Domain name to resolve.

        Returns:
            List of IP addresses (IPv4 and IPv6).
        """
        ips: set[str] = set()

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                results = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                for result in results:
                    ips.add(result[4][0])
            except socket.gaierror:
                continue

        return list(ips)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_dns_resolver.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/dns_resolver.py tests/plugins/test_dns_resolver.py
git commit -m "feat(plugin): add dns_resolver plugin for domain resolution"
```

---

## Task 6: Group B — subfinder Plugin

**Files:**
- Create: `src/reconforge/plugins/subfinder.py`
- Create: `tests/plugins/test_subfinder.py`

**Interfaces:**
- Consumes: `NormalizeUrlPlugin` output (via `upstream_results["normalize_url"]`)
- Produces: `SubfinderPlugin.run(target, upstream_results) -> Result`
- Output: `data` = list of subdomain strings

- [ ] **Step 1: Write failing tests for subfinder**

Create `tests/plugins/test_subfinder.py`:
```python
"""Tests for the subfinder plugin."""

import subprocess
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.subfinder import SubfinderPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestSubfinderPlugin:
    """Test SubfinderPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = SubfinderPlugin()
        assert plugin.name == "subfinder"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert SubfinderPlugin.requires == ["normalize_url"]

    def test_successful_run(self) -> None:
        """Should parse subfinder output into subdomain list."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\nsub2.example.com\napi.example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == ["sub1.example.com", "sub2.example.com", "api.example.com"]
        mock_run.assert_called_once()

    def test_tool_not_found(self) -> None:
        """Should return failure if subfinder is not installed."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=FileNotFoundError("subfinder not found")):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
        assert "not found" in result.errors[0].lower() or "not installed" in result.errors[0].lower()

    def test_tool_error(self) -> None:
        """Should return failure if subfinder returns non-zero exit code."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error: invalid target"

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_timeout(self) -> None:
        """Should return failure if subfinder times out."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("subfinder", 300)):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
        assert "timeout" in result.errors[0].lower()

    def test_empty_output(self) -> None:
        """Should return success with empty list if no subdomains found."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_whitespace_lines_filtered(self) -> None:
        """Should filter out empty and whitespace-only lines."""
        plugin = SubfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\n\n  \nsub2.example.com\n"

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == ["sub1.example.com", "sub2.example.com"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_subfinder.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement subfinder plugin**

Create `src/reconforge/plugins/subfinder.py`:
```python
"""Subfinder plugin for ReconForge.

Responsibilities:
- Discover subdomains using the subfinder tool
- Parse subfinder output into structured data

Design:
- Calls subfinder via subprocess.run
- Uses -silent flag for clean output (one subdomain per line)
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class SubfinderPlugin(BasePlugin):
    """Discover subdomains using the subfinder tool.

    Subfinder is a passive subdomain enumeration tool that queries
    multiple online sources for subdomains.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "subfinder"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Discover subdomains using subfinder"

    def setup(self, **kwargs: object) -> None:
        """Check if subfinder is installed.

        Raises:
            RuntimeError: If subfinder is not found in PATH.
        """
        if shutil.which("subfinder") is None:
            raise RuntimeError(
                "subfinder is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/subfinder"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run subfinder on the target domain.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of subdomains in data field.
        """
        start = time.perf_counter()

        # Get normalized domain from upstream
        normalize_result = upstream_results["normalize_url"]
        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data

        try:
            proc = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0:
                return create_failure_result(
                    module=self.name,
                    error=f"subfinder failed (exit {proc.returncode}): {proc.stderr.strip()}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            # Parse output: one subdomain per line
            subdomains = [
                line.strip()
                for line in proc.stdout.splitlines()
                if line.strip()
            ]

            return create_success_result(
                module=self.name,
                data=subdomains,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(subdomains)},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="subfinder is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="subfinder timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_subfinder.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/subfinder.py tests/plugins/test_subfinder.py
git commit -m "feat(plugin): add subfinder plugin for subdomain discovery"
```

---

## Task 7: Group B — assetfinder Plugin

**Files:**
- Create: `src/reconforge/plugins/assetfinder.py`
- Create: `tests/plugins/test_assetfinder.py`

**Interfaces:**
- Consumes: `NormalizeUrlPlugin` output (via `upstream_results["normalize_url"]`)
- Produces: `AssetfinderPlugin.run(target, upstream_results) -> Result`
- Output: `data` = list of subdomain strings

- [ ] **Step 1: Write failing tests for assetfinder**

Create `tests/plugins/test_assetfinder.py`:
```python
"""Tests for the assetfinder plugin."""

import subprocess
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.assetfinder import AssetfinderPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestAssetfinderPlugin:
    """Test AssetfinderPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = AssetfinderPlugin()
        assert plugin.name == "assetfinder"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert AssetfinderPlugin.requires == ["normalize_url"]

    def test_successful_run(self) -> None:
        """Should parse assetfinder output into subdomain list."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\nsub2.example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == ["sub1.example.com", "sub2.example.com"]

    def test_tool_not_found(self) -> None:
        """Should return failure if assetfinder is not installed."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_tool_error(self) -> None:
        """Should return failure if assetfinder returns non-zero exit code."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error"

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_timeout(self) -> None:
        """Should return failure if assetfinder times out."""
        plugin = AssetfinderPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("assetfinder", 300)):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_assetfinder.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement assetfinder plugin**

Create `src/reconforge/plugins/assetfinder.py`:
```python
"""Assetfinder plugin for ReconForge.

Responsibilities:
- Discover subdomains using the assetfinder tool
- Parse assetfinder output into structured data

Design:
- Calls assetfinder via subprocess.run
- Uses --subs-only flag for subdomain-only output
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class AssetfinderPlugin(BasePlugin):
    """Discover subdomains using the assetfinder tool.

    Assetfinder finds assets associated with a target using
    multiple online sources.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "assetfinder"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Discover subdomains using assetfinder"

    def setup(self, **kwargs: object) -> None:
        """Check if assetfinder is installed.

        Raises:
            RuntimeError: If assetfinder is not found in PATH.
        """
        if shutil.which("assetfinder") is None:
            raise RuntimeError(
                "assetfinder is not installed or not in PATH. "
                "Install from: https://github.com/tomnomnom/assetfinder"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run assetfinder on the target domain.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of subdomains in data field.
        """
        start = time.perf_counter()

        normalize_result = upstream_results["normalize_url"]
        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data

        try:
            proc = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0:
                return create_failure_result(
                    module=self.name,
                    error=f"assetfinder failed (exit {proc.returncode}): {proc.stderr.strip()}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            subdomains = [
                line.strip()
                for line in proc.stdout.splitlines()
                if line.strip()
            ]

            return create_success_result(
                module=self.name,
                data=subdomains,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(subdomains)},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="assetfinder is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="assetfinder timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_assetfinder.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/assetfinder.py tests/plugins/test_assetfinder.py
git commit -m "feat(plugin): add assetfinder plugin for subdomain discovery"
```

---

## Task 8: Group B — crtsh Plugin

**Files:**
- Create: `src/reconforge/plugins/crtsh.py`
- Create: `tests/plugins/test_crtsh.py`

**Interfaces:**
- Consumes: `NormalizeUrlPlugin` output (via `upstream_results["normalize_url"]`)
- Produces: `CrtshPlugin.run(target, upstream_results) -> Result`
- Output: `data` = list of subdomain strings

- [ ] **Step 1: Write failing tests for crtsh**

Create `tests/plugins/test_crtsh.py`:
```python
"""Tests for the crtsh plugin."""

import json
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.crtsh import CrtshPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestCrtshPlugin:
    """Test CrtshPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = CrtshPlugin()
        assert plugin.name == "crtsh"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert CrtshPlugin.requires == ["normalize_url"]

    def test_successful_run(self) -> None:
        """Should parse crt.sh JSON response into subdomain list."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps([
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com"},
            {"name_value": "*.example.com"},
        ]).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "sub1.example.com" in result.data
        assert "sub2.example.com" in result.data

    def test_wildcard_expanded(self) -> None:
        """Wildcard entries should be included as-is."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps([
            {"name_value": "*.example.com"},
        ]).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "*.example.com" in result.data

    def test_http_error(self) -> None:
        """Should return failure on HTTP error."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        from urllib.error import HTTPError
        with patch("urllib.request.urlopen", side_effect=HTTPError("", 500, "Server Error", {}, None)):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_timeout(self) -> None:
        """Should return failure on timeout."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_response(self) -> None:
        """Should return success with empty list if no results."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps([]).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_deduplication(self) -> None:
        """Should deduplicate subdomains from crt.sh."""
        plugin = CrtshPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps([
            {"name_value": "sub1.example.com"},
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com"},
        ]).encode()

        mock_urlopen = MagicMock()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", mock_urlopen):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_crtsh.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement crtsh plugin**

Create `src/reconforge/plugins/crtsh.py`:
```python
"""crt.sh plugin for ReconForge.

Responsibilities:
- Discover subdomains via crt.sh certificate transparency logs
- Parse JSON response from crt.sh API

Design:
- Uses urllib.request for HTTP (no external dependencies)
- Queries https://crt.sh/?q=<domain>&output=json
- Deduplicates results
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class CrtshPlugin(BasePlugin):
    """Discover subdomains via crt.sh certificate transparency.

    Queries the crt.sh API for certificate transparency logs
    associated with the target domain.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "crtsh"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Discover subdomains via crt.sh certificate transparency"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Query crt.sh for subdomains.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with list of subdomains in data field.
        """
        start = time.perf_counter()

        normalize_result = upstream_results["normalize_url"]
        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        url = f"https://crt.sh/?q={domain}&output=json"

        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ReconForge/1.0"},
            )

            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode())

            # Extract and deduplicate subdomains
            subdomains: set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip()
                    if name:
                        subdomains.add(name)

            result_list = sorted(subdomains)

            return create_success_result(
                module=self.name,
                data=result_list,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain, "count": len(result_list)},
            )

        except urllib.error.HTTPError as e:
            return create_failure_result(
                module=self.name,
                error=f"crt.sh HTTP error: {e.code} {e.reason}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except urllib.error.URLError as e:
            return create_failure_result(
                module=self.name,
                error=f"crt.sh connection error: {e.reason}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except (json.JSONDecodeError, KeyError) as e:
            return create_failure_result(
                module=self.name,
                error=f"crt.sh response parsing error: {e}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_crtsh.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/crtsh.py tests/plugins/test_crtsh.py
git commit -m "feat(plugin): add crtsh plugin for certificate transparency subdomain discovery"
```

---

## Task 9: Group C — httpx_alive Plugin

**Files:**
- Create: `src/reconforge/plugins/httpx_alive.py`
- Create: `tests/plugins/test_httpx_alive.py`

**Interfaces:**
- Consumes: `DnsResolverPlugin` output (via `upstream_results["dns_resolver"]`)
- Produces: `HttpxAlivePlugin.run(target, upstream_results) -> Result`
- Output: `data` = list of alive URL strings

- [ ] **Step 1: Write failing tests for httpx_alive**

Create `tests/plugins/test_httpx_alive.py`:
```python
"""Tests for the httpx_alive plugin."""

import subprocess
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.httpx_alive import HttpxAlivePlugin


def _make_dns_result(ips: list[str]) -> "Result":
    """Helper to create a mock dns_resolver result."""
    return create_success_result(
        module="dns_resolver",
        data=ips,
        duration=timedelta(seconds=0),
        metadata={"domain": "example.com", "count": len(ips)},
    )


class TestHttpxAlivePlugin:
    """Test HttpxAlivePlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = HttpxAlivePlugin()
        assert plugin.name == "httpx_alive"

    def test_requires(self) -> None:
        """Plugin should require dns_resolver."""
        assert HttpxAlivePlugin.requires == ["dns_resolver"]

    def test_successful_run(self) -> None:
        """Should parse httpx output into alive URL list."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "https://example.com\nhttp://example.com\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert "https://example.com" in result.data

    def test_tool_not_found(self) -> None:
        """Should return failure if httpx is not installed."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_output(self) -> None:
        """Should return success with empty list if no alive hosts."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_timeout(self) -> None:
        """Should return failure if httpx times out."""
        plugin = HttpxAlivePlugin()
        upstream = {"dns_resolver": _make_dns_result(["93.184.216.34"])}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("httpx", 300)):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_httpx_alive.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement httpx_alive plugin**

Create `src/reconforge/plugins/httpx_alive.py`:
```python
"""httpx alive check plugin for ReconForge.

Responsibilities:
- Check which hosts respond to HTTP/HTTPS
- Parse httpx output for alive URLs

Design:
- Calls httpx via subprocess.run with stdin input
- Uses -silent flag for clean output
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class HttpxAlivePlugin(BasePlugin):
    """Check which hosts are alive using httpx.

    httpx is a fast and multi-purpose HTTP toolkit that
    probes hosts for HTTP/HTTPS responses.
    """

    requires: ClassVar[list[str]] = ["dns_resolver"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "httpx_alive"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Check which hosts are alive via HTTP/HTTPS"

    def setup(self, **kwargs: object) -> None:
        """Check if httpx is installed.

        Raises:
            RuntimeError: If httpx is not found in PATH.
        """
        if shutil.which("httpx") is None:
            raise RuntimeError(
                "httpx is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/httpx"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Run httpx to check which hosts are alive.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "dns_resolver" result.

        Returns:
            Result with list of alive URLs in data field.
        """
        start = time.perf_counter()

        dns_result = upstream_results["dns_resolver"]
        if not dns_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"dns_resolver failed: {dns_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        ips = dns_result.data
        if not ips:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        try:
            # Pass IPs via stdin to httpx
            input_data = "\n".join(ips)
            proc = subprocess.run(
                ["httpx", "-silent"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0 and not proc.stdout:
                return create_failure_result(
                    module=self.name,
                    error=f"httpx failed (exit {proc.returncode}): {proc.stderr.strip()}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            alive_urls = [
                line.strip()
                for line in proc.stdout.splitlines()
                if line.strip()
            ]

            return create_success_result(
                module=self.name,
                data=alive_urls,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(alive_urls)},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="httpx is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="httpx timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_httpx_alive.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/httpx_alive.py tests/plugins/test_httpx_alive.py
git commit -m "feat(plugin): add httpx_alive plugin for HTTP probing"
```

---

## Task 10: Group C — http_fingerprint Plugin

**Files:**
- Create: `src/reconforge/plugins/http_fingerprint.py`
- Create: `tests/plugins/test_http_fingerprint.py`

**Interfaces:**
- Consumes: `HttpxAlivePlugin` output (via `upstream_results["httpx_alive"]`)
- Produces: `HttpFingerprintPlugin.run(target, upstream_results) -> Result`
- Output: `data` = list of dicts with fingerprint info (url, status_code, server, title)

- [ ] **Step 1: Write failing tests for http_fingerprint**

Create `tests/plugins/test_http_fingerprint.py`:
```python
"""Tests for the http_fingerprint plugin."""

import subprocess
import json
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.http_fingerprint import HttpFingerprintPlugin


def _make_httpx_result(urls: list[str]) -> "Result":
    """Helper to create a mock httpx_alive result."""
    return create_success_result(
        module="httpx_alive",
        data=urls,
        duration=timedelta(seconds=0),
        metadata={"count": len(urls)},
    )


class TestHttpFingerprintPlugin:
    """Test HttpFingerprintPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = HttpFingerprintPlugin()
        assert plugin.name == "http_fingerprint"

    def test_requires(self) -> None:
        """Plugin should require httpx_alive."""
        assert HttpFingerprintPlugin.requires == ["httpx_alive"]

    def test_successful_run(self) -> None:
        """Should parse httpx JSON output into fingerprint list."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        json_output = json.dumps({
            "url": "https://example.com",
            "status_code": 200,
            "webserver": "nginx",
            "title": "Example Domain",
        })

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_output + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 1
        assert result.data[0]["url"] == "https://example.com"
        assert result.data[0]["status_code"] == 200

    def test_tool_not_found(self) -> None:
        """Should return failure if httpx is not installed."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result(["https://example.com"])}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_empty_input(self) -> None:
        """Should return success with empty list if no URLs to fingerprint."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result([])}

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []

    def test_multiple_urls(self) -> None:
        """Should fingerprint multiple URLs."""
        plugin = HttpFingerprintPlugin()
        upstream = {"httpx_alive": _make_httpx_result([
            "https://example.com",
            "https://api.example.com",
        ])}

        json_line1 = json.dumps({"url": "https://example.com", "status_code": 200, "webserver": "nginx", "title": "Example"})
        json_line2 = json.dumps({"url": "https://api.example.com", "status_code": 200, "webserver": "Apache", "title": "API"})

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json_line1 + "\n" + json_line2 + "\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_http_fingerprint.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement http_fingerprint plugin**

Create `src/reconforge/plugins/http_fingerprint.py`:
```python
"""HTTP fingerprint plugin for ReconForge.

Responsibilities:
- Fingerprint HTTP responses (server, status, title)
- Parse httpx JSON output for detailed info

Design:
- Calls httpx via subprocess.run with -json flag
- Parses JSON lines output
- Mocked in unit tests, real tool in integration tests
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class HttpFingerprintPlugin(BasePlugin):
    """Fingerprint HTTP responses using httpx.

    Extracts server headers, status codes, page titles,
    and other HTTP response metadata.
    """

    requires: ClassVar[list[str]] = ["httpx_alive"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "http_fingerprint"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Fingerprint HTTP responses (server, status, title)"

    def setup(self, **kwargs: object) -> None:
        """Check if httpx is installed.

        Raises:
            RuntimeError: If httpx is not found in PATH.
        """
        if shutil.which("httpx") is None:
            raise RuntimeError(
                "httpx is not installed or not in PATH. "
                "Install from: https://github.com/projectdiscovery/httpx"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Fingerprint HTTP responses.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "httpx_alive" result.

        Returns:
            Result with list of fingerprint dicts in data field.
        """
        start = time.perf_counter()

        httpx_result = upstream_results["httpx_alive"]
        if not httpx_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"httpx_alive failed: {httpx_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        urls = httpx_result.data
        if not urls:
            return create_success_result(
                module=self.name,
                data=[],
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": 0},
            )

        try:
            input_data = "\n".join(urls)
            proc = subprocess.run(
                ["httpx", "-json", "-silent"],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if proc.returncode != 0 and not proc.stdout:
                return create_failure_result(
                    module=self.name,
                    error=f"httpx failed (exit {proc.returncode}): {proc.stderr.strip()}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            fingerprints: list[dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    fingerprints.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "server": data.get("webserver", ""),
                        "title": data.get("title", ""),
                    })
                except json.JSONDecodeError:
                    continue

            return create_success_result(
                module=self.name,
                data=fingerprints,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"count": len(fingerprints)},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="httpx is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="httpx timed out after 300 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_http_fingerprint.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/http_fingerprint.py tests/plugins/test_http_fingerprint.py
git commit -m "feat(plugin): add http_fingerprint plugin for HTTP response analysis"
```

---

## Task 11: Group D — merge_engine Plugin

**Files:**
- Create: `src/reconforge/plugins/merge_engine.py`
- Create: `tests/plugins/test_merge_engine.py`

**Interfaces:**
- Consumes: `SubfinderPlugin`, `AssetfinderPlugin`, `CrtshPlugin` outputs
- Produces: `MergeEnginePlugin.run(target, upstream_results) -> Result`
- Output: `data` = deduplicated list of subdomains with source attribution

- [ ] **Step 1: Write failing tests for merge_engine**

Create `tests/plugins/test_merge_engine.py`:
```python
"""Tests for the merge_engine plugin."""

from datetime import timedelta

import pytest

from reconforge.core.result import Result, ResultStatus, create_success_result
from reconforge.plugins.merge_engine import MergeEnginePlugin


def _make_subdomain_result(module: str, subdomains: list[str]) -> Result:
    """Helper to create a mock subdomain discovery result."""
    return create_success_result(
        module=module,
        data=subdomains,
        duration=timedelta(seconds=0),
        metadata={"domain": "example.com", "count": len(subdomains)},
    )


class TestMergeEnginePlugin:
    """Test MergeEnginePlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = MergeEnginePlugin()
        assert plugin.name == "merge_engine"

    def test_requires(self) -> None:
        """Plugin should require all subdomain sources."""
        assert set(MergeEnginePlugin.requires) == {"subfinder", "assetfinder", "crtsh"}

    def test_merge_all_sources(self) -> None:
        """Should merge subdomains from all sources."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com", "sub2.example.com"]),
            "assetfinder": _make_subdomain_result("assetfinder", ["sub2.example.com", "sub3.example.com"]),
            "crtsh": _make_subdomain_result("crtsh", ["sub3.example.com", "sub4.example.com"]),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 4
        subdomains = [item["subdomain"] for item in result.data]
        assert "sub1.example.com" in subdomains
        assert "sub4.example.com" in subdomains

    def test_deduplication(self) -> None:
        """Should deduplicate subdomains across sources."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com"]),
            "assetfinder": _make_subdomain_result("assetfinder", ["sub1.example.com"]),
            "crtsh": _make_subdomain_result("crtsh", ["sub1.example.com"]),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 1

    def test_source_attribution(self) -> None:
        """Should track which sources found each subdomain."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com"]),
            "assetfinder": _make_subdomain_result("assetfinder", ["sub1.example.com"]),
            "crtsh": _make_subdomain_result("crtsh", []),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        item = result.data[0]
        assert "subfinder" in item["sources"]
        assert "assetfinder" in item["sources"]
        assert "crtsh" not in item["sources"]

    def test_partial_sources(self) -> None:
        """Should handle missing or failed sources gracefully."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", ["sub1.example.com"]),
            "assetfinder": Result(
                module="assetfinder",
                status=ResultStatus.FAILURE,
                duration=timedelta(0),
                errors=["tool not found"],
            ),
            "crtsh": _make_subdomain_result("crtsh", ["sub2.example.com"]),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert len(result.data) == 2

    def test_empty_sources(self) -> None:
        """Should return empty list if all sources are empty."""
        plugin = MergeEnginePlugin()
        upstream = {
            "subfinder": _make_subdomain_result("subfinder", []),
            "assetfinder": _make_subdomain_result("assetfinder", []),
            "crtsh": _make_subdomain_result("crtsh", []),
        }

        result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_merge_engine.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement merge_engine plugin**

Create `src/reconforge/plugins/merge_engine.py`:
```python
"""Merge Engine plugin for ReconForge.

Responsibilities:
- Deduplicate subdomains from multiple sources
- Track source attribution for each subdomain
- Produce unified subdomain list

Design:
- Pure Python implementation (no external tools)
- Reads results from subfinder, assetfinder, crtsh
- Returns list of dicts with subdomain and sources
"""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_success_result


class MergeEnginePlugin(BasePlugin):
    """Merge and deduplicate subdomain results from multiple sources.

    Combines results from subfinder, assetfinder, and crtsh into
    a unified list with source attribution.
    """

    requires: ClassVar[list[str]] = ["subfinder", "assetfinder", "crtsh"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "merge_engine"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Merge and deduplicate subdomain results"

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Merge subdomain results from all sources.

        Args:
            target: Original target (unused).
            upstream_results: Must contain subfinder, assetfinder, crtsh results.

        Returns:
            Result with deduplicated subdomain list in data field.
            Each item is a dict: {"subdomain": str, "sources": list[str]}
        """
        start = time.perf_counter()

        # Collect subdomains with source attribution
        subdomain_sources: dict[str, list[str]] = {}

        for source_name in self.requires:
            source_result = upstream_results.get(source_name)
            if not source_result or not source_result.is_success:
                continue

            subdomains = source_result.data
            if not isinstance(subdomains, list):
                continue

            for subdomain in subdomains:
                if subdomain not in subdomain_sources:
                    subdomain_sources[subdomain] = []
                subdomain_sources[subdomain].append(source_name)

        # Build result list
        merged_data: list[dict[str, Any]] = [
            {"subdomain": subdomain, "sources": sources}
            for subdomain, sources in sorted(subdomain_sources.items())
        ]

        return create_success_result(
            module=self.name,
            data=merged_data,
            duration=timedelta(seconds=time.perf_counter() - start),
            metadata={
                "total_unique": len(merged_data),
                "sources_processed": len(self.requires),
            },
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_merge_engine.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/merge_engine.py tests/plugins/test_merge_engine.py
git commit -m "feat(plugin): add merge_engine plugin for subdomain deduplication"
```

---

## Task 12: Group E — whois_lookup Plugin

**Files:**
- Create: `src/reconforge/plugins/whois_lookup.py`
- Create: `tests/plugins/test_whois_lookup.py`

**Interfaces:**
- Consumes: `NormalizeUrlPlugin` output (via `upstream_results["normalize_url"]`)
- Produces: `WhoisLookupPlugin.run(target, upstream_results) -> Result`
- Output: `data` = dict with WHOIS fields (registrar, creation_date, expiration_date, etc.)

- [ ] **Step 1: Write failing tests for whois_lookup**

Create `tests/plugins/test_whois_lookup.py`:
```python
"""Tests for the whois_lookup plugin."""

import subprocess
from datetime import timedelta
from unittest.mock import patch, MagicMock

import pytest

from reconforge.core.result import create_success_result
from reconforge.plugins.whois_lookup import WhoisLookupPlugin


def _make_normalize_result(domain: str) -> "Result":
    """Helper to create a mock normalize_url result."""
    return create_success_result(
        module="normalize_url",
        data=domain,
        duration=timedelta(seconds=0),
        metadata={"original": domain, "is_ip": False},
    )


class TestWhoisLookupPlugin:
    """Test WhoisLookupPlugin."""

    def test_name(self) -> None:
        """Plugin should have correct name."""
        plugin = WhoisLookupPlugin()
        assert plugin.name == "whois_lookup"

    def test_requires(self) -> None:
        """Plugin should require normalize_url."""
        assert WhoisLookupPlugin.requires == ["normalize_url"]

    def test_successful_lookup(self) -> None:
        """Should parse whois output into structured data."""
        plugin = WhoisLookupPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        whois_output = """Domain Name: EXAMPLE.COM
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation Date: 1995-08-14
Registry Expiry Date: 2025-08-13
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET"""

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = whois_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream)

        assert result.is_success
        assert result.data["domain"] == "EXAMPLE.COM"
        assert "registrar" in result.data

    def test_tool_not_found(self) -> None:
        """Should return failure if whois is not installed."""
        plugin = WhoisLookupPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = plugin.run("example.com", upstream)

        assert result.is_failure

    def test_ip_address_skips_whois(self) -> None:
        """IP address input should skip whois lookup."""
        plugin = WhoisLookupPlugin()
        upstream = {
            "normalize_url": create_success_result(
                module="normalize_url",
                data="192.168.1.1",
                duration=timedelta(0),
                metadata={"original": "192.168.1.1", "is_ip": True},
            )
        }

        result = plugin.run("192.168.1.1", upstream)

        assert result.is_success
        assert result.data["is_ip"] is True

    def test_timeout(self) -> None:
        """Should return failure if whois times out."""
        plugin = WhoisLookupPlugin()
        upstream = {"normalize_url": _make_normalize_result("example.com")}

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("whois", 30)):
            result = plugin.run("example.com", upstream)

        assert result.is_failure
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/plugins/test_whois_lookup.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement whois_lookup plugin**

Create `src/reconforge/plugins/whois_lookup.py`:
```python
"""WHOIS lookup plugin for ReconForge.

Responsibilities:
- Retrieve WHOIS information for domains
- Parse whois command output into structured data

Design:
- Calls whois via subprocess.run
- Parses key-value pairs from output
- Skips lookup for IP addresses
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import timedelta
from typing import Any, ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_failure_result, create_success_result


class WhoisLookupPlugin(BasePlugin):
    """Retrieve WHOIS information for domains.

    Uses the whois command-line tool to query domain
    registration information.
    """

    requires: ClassVar[list[str]] = ["normalize_url"]

    @property
    def name(self) -> str:
        """Return the plugin name."""
        return "whois_lookup"

    @property
    def description(self) -> str:
        """Return the plugin description."""
        return "Retrieve WHOIS information for domains"

    def setup(self, **kwargs: object) -> None:
        """Check if whois is installed.

        Raises:
            RuntimeError: If whois is not found in PATH.
        """
        if shutil.which("whois") is None:
            raise RuntimeError(
                "whois is not installed or not in PATH. "
                "Install with: apt install whois (Kali/Debian)"
            )

    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Perform WHOIS lookup.

        Args:
            target: Original target (unused, read from upstream).
            upstream_results: Must contain "normalize_url" result.

        Returns:
            Result with WHOIS data dict in data field.
        """
        start = time.perf_counter()

        normalize_result = upstream_results["normalize_url"]
        if not normalize_result.is_success:
            return create_failure_result(
                module=self.name,
                error=f"normalize_url failed: {normalize_result.errors}",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        domain = normalize_result.data
        is_ip = normalize_result.metadata.get("is_ip", False)

        # Skip WHOIS for IP addresses
        if is_ip:
            return create_success_result(
                module=self.name,
                data={"domain": domain, "is_ip": True, "note": "WHOIS skipped for IP address"},
                duration=timedelta(seconds=time.perf_counter() - start),
            )

        try:
            proc = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if proc.returncode != 0:
                return create_failure_result(
                    module=self.name,
                    error=f"whois failed (exit {proc.returncode}): {proc.stderr.strip()}",
                    duration=timedelta(seconds=time.perf_counter() - start),
                )

            # Parse WHOIS output
            whois_data = self._parse_whois(proc.stdout, domain)

            return create_success_result(
                module=self.name,
                data=whois_data,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"domain": domain},
            )

        except FileNotFoundError:
            return create_failure_result(
                module=self.name,
                error="whois is not installed or not in PATH",
                duration=timedelta(seconds=time.perf_counter() - start),
            )
        except subprocess.TimeoutExpired:
            return create_failure_result(
                module=self.name,
                error="whois timed out after 30 seconds",
                duration=timedelta(seconds=time.perf_counter() - start),
            )

    def _parse_whois(self, output: str, domain: str) -> dict[str, Any]:
        """Parse WHOIS output into structured data.

        Args:
            output: Raw WHOIS command output.
            domain: The domain being queried.

        Returns:
            Dict with parsed WHOIS fields.
        """
        data: dict[str, Any] = {"domain": domain, "is_ip": False, "raw": output}

        # Common WHOIS fields to extract
        field_mappings = {
            "Domain Name": "domain_name",
            "Registrar": "registrar",
            "Creation Date": "creation_date",
            "Registry Expiry Date": "expiration_date",
            "Updated Date": "updated_date",
            "Name Server": "name_servers",
        }

        name_servers: list[str] = []

        for line in output.splitlines():
            line = line.strip()
            if ":" not in line:
                continue

            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key in field_mappings:
                field_name = field_mappings[key]
                if field_name == "name_servers":
                    name_servers.append(value)
                else:
                    data[field_name] = value

        if name_servers:
            data["name_servers"] = name_servers

        return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/plugins/test_whois_lookup.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/reconforge/plugins/whois_lookup.py tests/plugins/test_whois_lookup.py
git commit -m "feat(plugin): add whois_lookup plugin for domain registration info"
```

---

## Task 13: Final Verification

**Files:**
- All plugin files and tests

- [ ] **Step 1: Run all unit tests**

Run: `pytest -m "not integration" -v`
Expected: All tests PASS (existing 122 + new plugin tests)

- [ ] **Step 2: Verify plugin loader discovers all plugins**

Run: `python -c "from reconforge.core.loader import load_plugins; r = load_plugins(); print(r.get_names())"`
Expected: List includes all 9 plugins

- [ ] **Step 3: Update PROMPT.md progress log**

Add to PROMPT.md Section 18:

```markdown
- **Lesson 11 — DONE.** Phase 2 — Discovery Plugins:
  - Core changes: `requires: ClassVar[list[str]]` on BasePlugin, `upstream_results` parameter on `run()`.
  - Pipeline updated to collect and pass upstream results based on `requires`.
  - 9 plugins implemented: normalize_url, dns_resolver, subfinder, assetfinder, crtsh, httpx_alive, http_fingerprint, merge_engine, whois_lookup.
  - Test infrastructure: `tests/plugins/` for unit tests, `tests/integration/` for Kali-only tests.
  - All unit tests pass on Windows with mocked subprocess calls.
```

- [ ] **Step 4: Final commit**

```bash
git add PROMPT.md
git commit -m "docs: update PROMPT.md with Phase 2 completion"
```

---

## Summary

| Task | Component | Tests |
|------|-----------|-------|
| 1 | Core: plugin.py | 19 existing tests updated |
| 2 | Core: pipeline.py | 20 existing tests updated |
| 3 | Test infrastructure | pytest markers |
| 4 | normalize_url | 11 tests |
| 5 | dns_resolver | 7 tests |
| 6 | subfinder | 7 tests |
| 7 | assetfinder | 5 tests |
| 8 | crtsh | 7 tests |
| 9 | httpx_alive | 5 tests |
| 10 | http_fingerprint | 5 tests |
| 11 | merge_engine | 6 tests |
| 12 | whois_lookup | 5 tests |
| 13 | Final verification | All tests |

**Total new tests:** 58
**Total tests after Phase 2:** ~180