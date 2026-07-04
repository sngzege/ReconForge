# Phase 2 — Discovery Plugins Design Specification

**Date:** 2026-07-04  
**Status:** Approved  
**Scope:** Phase 2 of ReconForge — Discovery Plugins

---

## 1. Overview

Phase 2 introduces the first real reconnaissance plugins that orchestrate external security tools (subfinder, httpx, etc.) and provide core discovery capabilities (DNS resolution, URL normalization, subdomain enumeration).

### Goals

- Implement 10 discovery plugins/modules
- Extend Core to support plugin-to-plugin data flow via `upstream_results`
- Establish test infrastructure for subprocess-mocked unit tests and Kali-only integration tests
- Maintain strict separation: Core never imports plugin implementations

### Non-Goals (deferred to later phases)

- Cache system (Phase 5)
- Reporting/output layer (Phase 4)
- Enumeration plugins like naabu, nmap (Phase 3)

---

## 2. Core Changes

### 2.1 BasePlugin Extension (`src/reconforge/core/plugin.py`)

Add `requires` as a **class variable** (not property) so dependency graphs can be built without instantiation:

```python
from typing import ClassVar

class BasePlugin(ABC):
    requires: ClassVar[list[str]] = []
    # ... existing code ...
```

Update `run()` signature — `upstream_results` is always a dict (empty or populated), no `**kwargs`:

```python
@abstractmethod
def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
    """Execute the plugin's main logic.
    
    Args:
        target: The target to scan/process.
        upstream_results: Results from plugins declared in `requires`.
                         Always a dict (empty if no dependencies).
    
    Returns:
        Result object containing the plugin's findings.
    """
```

### 2.2 Pipeline Extension (`src/reconforge/core/pipeline.py`)

Pipeline collects only declared upstream results and passes them to plugins:

```python
def _execute_plugin(self, plugin: BasePlugin, target: str) -> Result:
    upstream_results: dict[str, Result] = {}
    for dep_name in plugin.requires:
        if dep_name not in self._results:
            # Missing dependency → failure result, never silently skipped
            return create_failure_result(
                module=plugin.name,
                error=f"Required upstream result '{dep_name}' not available",
                duration=timedelta(0),
            )
        upstream_results[dep_name] = self._results[dep_name]
    
    return execute_plugin_safely(plugin, target, upstream_results=upstream_results)
```

### 2.3 execute_plugin_safely Update

Pass `upstream_results` to `run()`:

```python
result = plugin.run(target, upstream_results=upstream_results)
```

---

## 3. Plugin Structure

### 3.1 Directory Layout

```
src/reconforge/
├── core/                    # Existing (extended)
│   ├── config.py
│   ├── loader.py
│   ├── logging_setup.py
│   ├── pipeline.py          # Extended
│   ├── plugin.py            # Extended
│   ├── result.py
│   └── scheduler.py
├── plugins/                 # NEW
│   ├── __init__.py
│   ├── normalize_url.py     # Group A
│   ├── dns_resolver.py      # Group A
│   ├── subfinder.py         # Group B
│   ├── assetfinder.py       # Group B
│   ├── crtsh.py             # Group B
│   ├── httpx_alive.py       # Group C
│   ├── http_fingerprint.py  # Group C
│   ├── merge_engine.py      # Group D
│   └── whois_lookup.py      # Group E
└── cli.py
```

### 3.2 Plugin Template

```python
from __future__ import annotations

import subprocess
import time
from datetime import timedelta
from typing import ClassVar

from reconforge.core.plugin import BasePlugin
from reconforge.core.result import Result, create_success_result, create_failure_result


class ExamplePlugin(BasePlugin):
    """One-line description of what this plugin does."""
    
    requires: ClassVar[list[str]] = []  # or ["normalize_url", ...]
    
    @property
    def name(self) -> str:
        return "example"
    
    @property
    def description(self) -> str:
        return "Human-readable description"
    
    def run(self, target: str, upstream_results: dict[str, Result]) -> Result:
        """Execute the plugin logic.
        
        Args:
            target: Target domain/IP.
            upstream_results: Results from required plugins.
        
        Returns:
            Result with plugin findings.
        """
        start = time.perf_counter()
        try:
            # ... plugin logic ...
            return create_success_result(
                module=self.name,
                data=result_data,
                duration=timedelta(seconds=time.perf_counter() - start),
                metadata={"key": "value"},
            )
        except Exception as e:
            return create_failure_result(
                module=self.name,
                error=str(e),
                duration=timedelta(seconds=time.perf_counter() - start),
            )
```

---

## 4. Plugin Groups

### 4.1 Group A — URL Normalize + DNS Resolver

**Execution order:** `normalize_url` → `dns_resolver`

#### normalize_url

- **Purpose:** Standardize user input (domain, URL, IP) to canonical form
- **requires:** `[]` (no dependencies)
- **Input:** `target` string
- **Output:** `data` = normalized string, `metadata` = `{"original": str, "is_ip": bool}`
- **Behavior:**
  - Strip protocol (`https://example.com` → `example.com`)
  - Strip path (`example.com/path` → `example.com`)
  - Strip port (`example.com:8080` → `example.com`)
  - Lowercase (`EXAMPLE.COM` → `example.com`)
  - IP detection via `ipaddress.ip_address()` (IPv4 + IPv6)

#### dns_resolver

- **Purpose:** Resolve domain to IP addresses
- **requires:** `["normalize_url"]`
- **Input:** Normalized domain from upstream
- **Output:** `data` = list of IP addresses (IPv4 + IPv6)
- **Implementation:** stdlib `socket.getaddrinfo()` (no external tool)
- **Special:** If upstream `metadata["is_ip"]` is True, return IP as-is

### 4.2 Group B — Subdomain Discovery

**Execution order:** All three run concurrently (no inter-dependencies)

#### subfinder

- **Purpose:** Discover subdomains using `subfinder` tool
- **requires:** `["normalize_url"]`
- **Tool:** `subfinder -d <domain> -silent`
- **Output:** `data` = list of subdomain strings

#### assetfinder

- **Purpose:** Discover subdomains using `assetfinder` tool
- **requires:** `["normalize_url"]`
- **Tool:** `assetfinder --subs-only <domain>`
- **Output:** `data` = list of subdomain strings

#### crtsh

- **Purpose:** Discover subdomains via crt.sh certificate transparency
- **requires:** `["normalize_url"]`
- **Tool:** HTTP request to `https://crt.sh/?q=<domain>&output=json`
- **Output:** `data` = list of subdomain strings
- **Note:** Pure HTTP, no external binary needed (uses `urllib`)

### 4.3 Group C — HTTP Probing

#### httpx_alive

- **Purpose:** Check which hosts are alive (respond to HTTP)
- **requires:** `["dns_resolver"]` (needs resolved IPs or domains)
- **Tool:** `httpx -silent` (stdin input)
- **Output:** `data` = list of alive URLs

#### http_fingerprint

- **Purpose:** Fingerprint HTTP responses (server, technology, status)
- **requires:** `["httpx_alive"]`
- **Tool:** `httpx -json` or custom HTTP probing
- **Output:** `data` = list of dicts with fingerprint info

### 4.4 Group D — Merge Engine

#### merge_engine

- **Purpose:** Deduplicate and merge results from multiple subdomain sources
- **requires:** `["subfinder", "assetfinder", "crtsh"]`
- **Output:** `data` = deduplicated list of subdomains with source attribution
- **Note:** This is a pure-Python plugin, no external tool

### 4.5 Group E — WHOIS

#### whois_lookup

- **Purpose:** Retrieve WHOIS information for domain
- **requires:** `["normalize_url"]`
- **Tool:** `whois <domain>` or stdlib socket for basic info
- **Output:** `data` = dict with WHOIS fields

---

## 5. Test Strategy

### 5.1 Test Directory Structure

```
tests/
├── __init__.py
├── conftest.py              # NEW: shared fixtures
├── test_config.py           # Existing
├── test_loader.py           # Existing
├── test_logging.py          # Existing
├── test_pipeline.py         # Existing (extended)
├── test_plugin.py           # Existing (extended)
├── test_result.py           # Existing
├── test_scheduler.py        # Existing
├── plugins/                 # NEW
│   ├── __init__.py
│   ├── test_normalize_url.py
│   ├── test_dns_resolver.py
│   ├── test_subfinder.py
│   └── ...
└── integration/             # NEW (Kali-only)
    ├── __init__.py
    ├── conftest.py
    └── test_real_tools.py
```

### 5.2 Unit Tests (Mock-based, Windows-compatible)

- `subprocess.run` is mocked for all external tool plugins
- Mock responses defined as fixtures
- Tests pass on Windows without any external tools installed

```python
# Example: tests/plugins/test_subfinder.py
from unittest.mock import patch, MagicMock

class TestSubfinderPlugin:
    def test_successful_run(self):
        plugin = SubfinderPlugin()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "sub1.example.com\nsub2.example.com\n"
        
        with patch("subprocess.run", return_value=mock_result):
            result = plugin.run("example.com", upstream_results={})
        
        assert result.is_success
        assert result.data == ["sub1.example.com", "sub2.example.com"]
```

### 5.3 Integration Tests (Kali-only)

- Marked with `@pytest.mark.integration`
- Skipped if tool not installed (`shutil.which()`)
- Run only on Kali Linux

```python
@pytest.mark.integration
@pytest.mark.skipif(shutil.which("subfinder") is None, reason="subfinder not installed")
class TestSubfinderIntegration:
    def test_real_subfinder(self):
        plugin = SubfinderPlugin()
        result = plugin.run("example.com", upstream_results={})
        assert result.is_success
```

### 5.4 pytest Configuration

```toml
# pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: marks tests requiring real tools (deselect with '-m \"not integration\"')",
]
```

### 5.5 Running Tests

```bash
# Windows (fast feedback, no external tools needed)
pytest -m "not integration"

# Kali (full test suite)
pytest
```

---

## 6. Implementation Order

1. **Core changes first:** Update `plugin.py` and `pipeline.py`
2. **Group A:** `normalize_url` → `dns_resolver` (foundation for all others)
3. **Group B:** `subfinder`, `assetfinder`, `crtsh` (concurrent subdomain discovery)
4. **Group C:** `httpx_alive`, `http_fingerprint` (HTTP probing)
5. **Group D:** `merge_engine` (result deduplication)
6. **Group E:** `whois_lookup` (supplementary)

Each group: implement → test → commit → next group.

---

## 7. Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| `requires` type | `ClassVar[list[str]]` | Build dependency graph without instantiation |
| Missing upstream | Failure result | Never silently skip — explicit failure is better |
| `run()` signature | `(target, upstream_results)` | No `**kwargs`, explicit contract |
| Duration measurement | `time.perf_counter()` | Monotonic, not affected by system clock changes |
| IP detection | `ipaddress.ip_address()` | stdlib, supports IPv4+IPv6 |
| Subprocess calls | `subprocess.run` | Simple, synchronous, easy to mock |
| Test markers | `@pytest.mark.integration` | Standard pytest, clear separation |

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| External tool not installed | `setup()` checks with `shutil.which()`, returns clear error |
| Tool output format changes | Parse defensively, log warnings on unexpected format |
| Network timeout | All subprocess calls have explicit `timeout` parameter |
| Plugin crashes pipeline | `execute_plugin_safely` catches all exceptions |

---

## 9. Success Criteria

- [ ] All 10 plugins implemented and passing unit tests
- [ ] Core changes (requires, upstream_results) working correctly
- [ ] Unit tests pass on Windows (`pytest -m "not integration"`)
- [ ] Integration tests pass on Kali (with tools installed)
- [ ] No core file imports any plugin implementation
- [ ] Each plugin has docstrings and type hints